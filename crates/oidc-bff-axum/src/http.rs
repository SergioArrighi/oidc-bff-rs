use axum::{
    Json, Router,
    extract::{Query, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use std::sync::Arc;
use tower_sessions::{Session, SessionStore};

use crate::{IdentityApplication, IdentityError};

const ANTI_FORGERY_HEADER: &str = "x-anti-forgery-token";
const FETCH_SITE_HEADER: &str = "sec-fetch-site";

#[derive(Clone, Debug, Default, Deserialize)]
struct LoginQuery {
    return_to: Option<String>,
    #[serde(default)]
    reauthenticate: bool,
}

#[derive(Clone, Debug, Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(Clone)]
/// Fixed same-origin login, callback, session, and logout HTTP service.
pub struct IdentityHttpApplication {
    application: IdentityApplication,
    sessions: Option<Arc<dyn SessionStore>>,
}

impl IdentityHttpApplication {
    /// Binds the route service to a discovered identity application.
    pub fn new(application: IdentityApplication) -> Self {
        Self {
            application,
            sessions: None,
        }
    }

    /// Enables authoritative inactivity deadlines and explicit browser activity.
    /// Supply the same (decrypting) store used by IdentitySessionLayer.
    pub fn with_session_store(mut self, sessions: Arc<dyn SessionStore>) -> Self {
        self.sessions = Some(sessions);
        self
    }

    /// Builds the `/auth/*` router backed by the discovered identity application.
    pub fn router(self) -> Router {
        Router::new()
            .route("/auth/login", get(Self::login))
            .route("/auth/callback", get(Self::callback))
            .route("/auth/session", get(Self::session))
            .route("/auth/session/activity", post(Self::activity))
            .route("/auth/logout", post(Self::logout))
            .layer(middleware::map_response(Self::apply_response_policy))
            .with_state(self)
    }

    async fn login(
        State(http): State<Self>,
        session: Session,
        Query(query): Query<LoginQuery>,
    ) -> Result<Response, IdentityError> {
        let mut destination = http
            .application
            .begin_login(&session, query.return_to.as_deref())
            .await?;
        if query.reauthenticate {
            destination
                .query_pairs_mut()
                .append_pair("prompt", "login")
                .append_pair("max_age", "0");
        }
        Ok(Self::redirect(destination.as_str()))
    }

    async fn callback(
        State(http): State<Self>,
        session: Session,
        Query(query): Query<CallbackQuery>,
    ) -> Result<Response, IdentityError> {
        if query.error.is_some() {
            return Err(IdentityError::LoginRejected);
        }
        let code = query.code.ok_or(IdentityError::LoginRejected)?;
        let state = query.state.ok_or(IdentityError::LoginStateInvalid)?;
        if code.is_empty() || code.len() > 8 * 1024 || state.is_empty() || state.len() > 512 {
            return Err(IdentityError::LoginRejected);
        }
        let return_to = http
            .application
            .complete_login(&session, &code, &state)
            .await?;
        Ok(Self::redirect(&return_to))
    }

    async fn session(
        State(http): State<Self>,
        session: Session,
    ) -> Result<impl IntoResponse, IdentityError> {
        let projection = match &http.sessions {
            Some(store) => tokio::time::timeout(
                std::time::Duration::from_secs(5),
                http.application
                    .browser_session_activity(&session, store.as_ref(), None),
            )
            .await
            .map_err(|_| IdentityError::Session)??,
            None => http.application.session(&session).await?,
        };
        http.session_response(&session, projection)
    }

    async fn activity(
        State(http): State<Self>,
        session: Session,
        headers: HeaderMap,
    ) -> Result<Response, IdentityError> {
        let protection = BrowserRequestProtection::new(&Method::POST, &headers);
        let token = protection
            .validate(&http.application)?
            .ok_or(IdentityError::CsrfRejected)?;
        let store = http.sessions.as_ref().ok_or(IdentityError::Session)?;
        let projection = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            http.application
                .browser_session_activity(&session, store.as_ref(), Some(token)),
        )
        .await
        .map_err(|_| IdentityError::Session)??;
        if projection.inactivity_expires_at_epoch_seconds.is_none() {
            return Err(IdentityError::AuthenticationRequired);
        }
        http.session_response(&session, projection)
    }

    fn session_response(
        &self,
        session: &Session,
        projection: oidc_bff_core::IdentitySession,
    ) -> Result<Response, IdentityError> {
        let cookie = projection
            .inactivity_expires_at_epoch_seconds
            .map(|deadline| {
                session
                    .id()
                    .map(|id| self.application.renewed_browser_cookie(id, deadline))
                    .ok_or(IdentityError::AuthenticationRequired)
            })
            .transpose()?;
        let mut response = Json(projection).into_response();
        if let Some(cookie) = cookie {
            // Reconcile a missed renewal response without extending the stored
            // deadline. Status polling still cannot keep an idle login alive.
            response.headers_mut().append(
                header::SET_COOKIE,
                HeaderValue::from_str(&cookie).map_err(|_| IdentityError::Session)?,
            );
        }
        Ok(response)
    }

    async fn logout(
        State(http): State<Self>,
        session: Session,
        headers: HeaderMap,
    ) -> Result<impl IntoResponse, IdentityError> {
        let method = Method::POST;
        let request_protection = BrowserRequestProtection::new(&method, &headers);
        let anti_forgery_token = request_protection
            .validate(&http.application)?
            .ok_or(IdentityError::CsrfRejected)?;
        Ok(Json(
            http.application
                .logout(&session, anti_forgery_token)
                .await?,
        ))
    }

    fn redirect(destination: &str) -> Response {
        (StatusCode::SEE_OTHER, [(header::LOCATION, destination)]).into_response()
    }

    async fn apply_response_policy(mut response: Response) -> Response {
        let headers = response.headers_mut();
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
        headers.insert(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        );
        headers.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
        response
    }
}

#[derive(Clone)]
/// Axum authentication middleware bound to a discovered identity application.
pub struct IdentityAuthentication {
    application: IdentityApplication,
}

impl IdentityAuthentication {
    /// Creates authentication middleware state for one identity application.
    pub fn new(application: IdentityApplication) -> Self {
        Self { application }
    }

    /// Accepts a human Authorization bearer token or a human browser session.
    /// Workload tokens are rejected even when otherwise valid.
    pub async fn authorize_user_or_access_token(
        State(authentication): State<Self>,
        session: Session,
        mut request: Request,
        next: Next,
    ) -> Result<Response, IdentityError> {
        let authenticated = if let Some(authorization) = BearerCredential::from_request(&request)? {
            authentication
                .application
                .authenticated_access_token(authorization.as_str())
                .await?
        } else {
            let request_protection = BrowserRequestProtection::from_request(&request);
            let anti_forgery_token = request_protection.validate(&authentication.application)?;
            authentication
                .application
                .authenticated_browser_request(&session, anti_forgery_token)
                .await?
        };
        if authenticated.kind != crate::AuthenticationPrincipalKind::Human {
            return Err(IdentityError::AccessTokenInvalid);
        }
        request.extensions_mut().insert(authenticated);
        Ok(next.run(request).await)
    }

    /// Requires a valid human browser session.
    pub async fn authorize(
        State(authentication): State<Self>,
        session: Session,
        mut request: Request,
        next: Next,
    ) -> Result<Response, IdentityError> {
        let request_protection = BrowserRequestProtection::from_request(&request);
        let anti_forgery_token = request_protection.validate(&authentication.application)?;
        let authenticated = authentication
            .application
            .authenticated_browser_request(&session, anti_forgery_token)
            .await?;
        request.extensions_mut().insert(authenticated);
        Ok(next.run(request).await)
    }

    /// Requires a valid human or workload bearer token.
    pub async fn authorize_access_token(
        State(authentication): State<Self>,
        mut request: Request,
        next: Next,
    ) -> Result<Response, IdentityError> {
        let authorization =
            BearerCredential::from_request(&request)?.ok_or(IdentityError::BearerTokenRequired)?;
        let authenticated = authentication
            .application
            .authenticated_access_token(authorization.as_str())
            .await?;
        request.extensions_mut().insert(authenticated);
        Ok(next.run(request).await)
    }

    /// Requires a valid bearer token classified as a workload.
    pub async fn authorize_workload_access_token(
        State(authentication): State<Self>,
        mut request: Request,
        next: Next,
    ) -> Result<Response, IdentityError> {
        let authorization =
            BearerCredential::from_request(&request)?.ok_or(IdentityError::BearerTokenRequired)?;
        let authenticated = authentication
            .application
            .authenticated_access_token(authorization.as_str())
            .await?;
        if authenticated.kind != crate::AuthenticationPrincipalKind::Workload {
            return Err(IdentityError::AccessTokenInvalid);
        }
        request.extensions_mut().insert(authenticated);
        Ok(next.run(request).await)
    }
}

struct BearerCredential<'request>(&'request str);

impl<'request> BearerCredential<'request> {
    fn from_request(request: &'request Request) -> Result<Option<Self>, IdentityError> {
        let mut values = request
            .headers()
            .get_all(axum::http::header::AUTHORIZATION)
            .iter();
        let Some(value) = values.next() else {
            return Ok(None);
        };
        if values.next().is_some() {
            return Err(IdentityError::AccessTokenInvalid);
        }
        let value = value
            .to_str()
            .map_err(|_| IdentityError::AccessTokenInvalid)?;
        let token = value
            .strip_prefix("Bearer ")
            .filter(|token| !token.is_empty() && token.len() <= 16 * 1024)
            .ok_or(IdentityError::AccessTokenInvalid)?;
        Ok(Some(Self(token)))
    }

    fn as_str(&self) -> &str {
        self.0
    }
}

struct BrowserRequestProtection<'request> {
    method: &'request Method,
    headers: &'request HeaderMap,
}

impl<'request> BrowserRequestProtection<'request> {
    fn new(method: &'request Method, headers: &'request HeaderMap) -> Self {
        Self { method, headers }
    }

    fn from_request(request: &'request Request) -> Self {
        Self::new(request.method(), request.headers())
    }

    fn validate(&self, application: &IdentityApplication) -> Result<Option<&str>, IdentityError> {
        if matches!(*self.method, Method::GET | Method::HEAD | Method::OPTIONS) {
            return Ok(None);
        }
        let origin = self.unique_header(header::ORIGIN)?;
        if origin != application.expected_browser_origin() {
            return Err(IdentityError::CsrfRejected);
        }
        if self
            .optional_unique_header(axum::http::HeaderName::from_static(FETCH_SITE_HEADER))?
            .is_some_and(|value| value != "same-origin")
        {
            return Err(IdentityError::CsrfRejected);
        }
        let anti_forgery_token =
            self.unique_header(axum::http::HeaderName::from_static(ANTI_FORGERY_HEADER))?;
        if !(16..=512).contains(&anti_forgery_token.len()) {
            return Err(IdentityError::CsrfRejected);
        }
        Ok(Some(anti_forgery_token))
    }

    fn unique_header(&self, name: axum::http::HeaderName) -> Result<&str, IdentityError> {
        self.optional_unique_header(name)?
            .ok_or(IdentityError::CsrfRejected)
    }

    fn optional_unique_header(
        &self,
        name: axum::http::HeaderName,
    ) -> Result<Option<&str>, IdentityError> {
        let mut values = self.headers.get_all(name).iter();
        let Some(value) = values.next() else {
            return Ok(None);
        };
        if values.next().is_some() {
            return Err(IdentityError::CsrfRejected);
        }
        value
            .to_str()
            .map(Some)
            .map_err(|_| IdentityError::CsrfRejected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    #[test]
    fn bearer_header_must_be_unique_and_bounded() {
        let mut duplicate = Request::new(Body::empty());
        duplicate.headers_mut().append(
            axum::http::header::AUTHORIZATION,
            "Bearer first".parse().unwrap(),
        );
        duplicate.headers_mut().append(
            axum::http::header::AUTHORIZATION,
            "Bearer second".parse().unwrap(),
        );
        assert!(matches!(
            BearerCredential::from_request(&duplicate),
            Err(IdentityError::AccessTokenInvalid)
        ));

        let oversized = Request::builder()
            .header(
                axum::http::header::AUTHORIZATION,
                format!("Bearer {}", "x".repeat(16 * 1024 + 1)),
            )
            .body(Body::empty())
            .unwrap();
        assert!(matches!(
            BearerCredential::from_request(&oversized),
            Err(IdentityError::AccessTokenInvalid)
        ));
    }
}
