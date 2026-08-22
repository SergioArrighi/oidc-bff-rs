use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use axum::{
    Form, Json, Router,
    body::Body,
    extract::State,
    http::{Request, StatusCode, header},
    middleware,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use oidc_bff_axum::{
    BrowserApplicationConfiguration, ClientSecretCredential, IdentityApplication,
    IdentityAuthentication, IdentityConfiguration, IdentityHttpApplication, IdentitySessionLayer,
    ProviderConfiguration, ResourceServerConfiguration, SessionCookieConfiguration,
};
use oidc_bff_core::{AuthenticationStatus, IdentityLogout, IdentitySession};
use rand::rngs::OsRng;
use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt;

#[derive(Clone)]
struct ProviderState {
    issuer: String,
    jwks: Value,
    private_key: Arc<Vec<u8>>,
    nonce: Arc<Mutex<Option<String>>>,
}

struct TestProvider {
    issuer: String,
    backchannel_base_url: Option<String>,
    nonce: Arc<Mutex<Option<String>>>,
    task: tokio::task::JoinHandle<()>,
}

#[derive(Serialize)]
struct IdentityTokenClaims {
    iss: String,
    aud: String,
    sub: String,
    exp: u64,
    iat: u64,
    nonce: String,
    email: String,
    email_verified: bool,
    preferred_username: String,
}

impl TestProvider {
    async fn start_with_distinct_backchannel() -> Self {
        Self::start_with_issuer(Some("http://localhost:65534".to_owned())).await
    }

    async fn start_with_issuer(public_issuer: Option<String>) -> Self {
        let private_key = RsaPrivateKey::new(&mut OsRng, 2_048).unwrap();
        let public_key = private_key.to_public_key();
        let private_key = private_key.to_pkcs1_der().unwrap().as_bytes().to_vec();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backchannel_base_url = format!("http://{}", listener.local_addr().unwrap());
        let issuer = public_issuer.unwrap_or_else(|| backchannel_base_url.clone());
        let distinct_backchannel = (issuer != backchannel_base_url).then_some(backchannel_base_url);
        let nonce = Arc::new(Mutex::new(None));
        let state = ProviderState {
            issuer: issuer.clone(),
            jwks: json!({
                "keys": [{
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "browser-flow-key",
                    "alg": "RS256",
                    "n": URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
                    "e": URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be())
                }]
            }),
            private_key: Arc::new(private_key),
            nonce: Arc::clone(&nonce),
        };
        let router = Router::new()
            .route("/.well-known/openid-configuration", get(Self::discovery))
            .route("/jwks", get(Self::jwks))
            .route("/token", post(Self::token))
            .with_state(state);
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self {
            issuer,
            backchannel_base_url: distinct_backchannel,
            nonce,
            task,
        }
    }

    fn configuration(&self) -> IdentityConfiguration {
        let provider = ProviderConfiguration::new(
            self.issuer.parse().unwrap(),
            "browser-client",
            ClientSecretCredential::new("test-client-secret-with-32-bytes-minimum").unwrap(),
            format!("{}/account", self.issuer).parse().unwrap(),
        )
        .unwrap();
        let provider = if let Some(backchannel_base_url) = &self.backchannel_base_url {
            provider
                .with_backchannel_base_url(backchannel_base_url.parse().unwrap())
                .unwrap()
        } else {
            provider
        };
        IdentityConfiguration::new(
            provider,
            BrowserApplicationConfiguration::new(
                "http://127.0.0.1:3000/".parse().unwrap(),
                "http://127.0.0.1:3000/auth/callback".parse().unwrap(),
                "http://127.0.0.1:3000/".parse().unwrap(),
            )
            .unwrap(),
            ResourceServerConfiguration::new(
                "application-api",
                "browser-client",
                "automation-client",
                "application_mcp",
                "at+jwt",
            )
            .unwrap(),
            SessionCookieConfiguration::loopback_development("browser-flow", 3_600, 7_200).unwrap(),
        )
        .unwrap()
    }

    async fn discovery(State(state): State<ProviderState>) -> Json<Value> {
        Json(json!({
            "issuer": format!("{}/", state.issuer),
            "authorization_endpoint": format!("{}/authorize", state.issuer),
            "token_endpoint": format!("{}/token", state.issuer),
            "jwks_uri": format!("{}/jwks", state.issuer),
            "end_session_endpoint": format!("{}/logout", state.issuer),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
            "code_challenge_methods_supported": ["S256"]
        }))
    }

    async fn jwks(State(state): State<ProviderState>) -> Json<Value> {
        Json(state.jwks)
    }

    async fn token(
        State(state): State<ProviderState>,
        headers: axum::http::HeaderMap,
        Form(form): Form<BTreeMap<String, String>>,
    ) -> Result<Json<Value>, StatusCode> {
        let expected_authorization = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode("browser-client:test-client-secret-with-32-bytes-minimum")
        );
        if form.get("grant_type").map(String::as_str) != Some("authorization_code")
            || form.get("code").map(String::as_str) != Some("test-code")
            || form.get("code_verifier").is_none_or(String::is_empty)
            || headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                != Some(expected_authorization.as_str())
        {
            return Err(StatusCode::BAD_REQUEST);
        }
        let nonce = state
            .nonce
            .lock()
            .await
            .clone()
            .ok_or(StatusCode::CONFLICT)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = IdentityTokenClaims {
            iss: format!("{}/", state.issuer),
            aud: "browser-client".to_owned(),
            sub: "user-42".to_owned(),
            exp: now + 3_600,
            iat: now,
            nonce,
            email: "user@example.com".to_owned(),
            email_verified: true,
            preferred_username: "user".to_owned(),
        };
        let mut token_header = Header::new(Algorithm::RS256);
        token_header.kid = Some("browser-flow-key".to_owned());
        let id_token = encode(
            &token_header,
            &claims,
            &EncodingKey::from_rsa_der(&state.private_key),
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        Ok(Json(json!({
            "access_token": "unused-browser-access-token",
            "token_type": "Bearer",
            "expires_in": 3_600,
            "scope": "openid profile email",
            "id_token": id_token
        })))
    }
}

impl Drop for TestProvider {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn discovery_rejects_a_cross_origin_jwks_before_fetching_it() {
    let jwks_requests = Arc::new(AtomicUsize::new(0));
    let observed_requests = Arc::clone(&jwks_requests);
    let trap = Router::new().route(
        "/jwks",
        get(move || {
            let observed_requests = Arc::clone(&observed_requests);
            async move {
                observed_requests.fetch_add(1, Ordering::SeqCst);
                Json(json!({ "keys": [] }))
            }
        }),
    );
    let trap_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let trap_origin = format!("http://{}", trap_listener.local_addr().unwrap());
    let trap_task = tokio::spawn(async move { axum::serve(trap_listener, trap).await.unwrap() });

    let provider_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let provider_origin = format!("http://{}", provider_listener.local_addr().unwrap());
    let document = json!({
        "issuer": format!("{provider_origin}/"),
        "authorization_endpoint": format!("{provider_origin}/authorize"),
        "token_endpoint": format!("{provider_origin}/token"),
        "jwks_uri": format!("{trap_origin}/jwks"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"]
    });
    let provider = Router::new().route(
        "/.well-known/openid-configuration",
        get(move || {
            let document = document.clone();
            async move { Json(document) }
        }),
    );
    let provider_task =
        tokio::spawn(async move { axum::serve(provider_listener, provider).await.unwrap() });

    let configuration = IdentityConfiguration::new(
        ProviderConfiguration::new(
            provider_origin.parse().unwrap(),
            "browser-client",
            ClientSecretCredential::new("test-client-secret-with-32-bytes-minimum").unwrap(),
            format!("{provider_origin}/account").parse().unwrap(),
        )
        .unwrap(),
        BrowserApplicationConfiguration::new(
            "http://127.0.0.1:3000/".parse().unwrap(),
            "http://127.0.0.1:3000/auth/callback".parse().unwrap(),
            "http://127.0.0.1:3000/".parse().unwrap(),
        )
        .unwrap(),
        ResourceServerConfiguration::new(
            "application-api",
            "browser-client",
            "automation-client",
            "application_mcp",
            "at+jwt",
        )
        .unwrap(),
        SessionCookieConfiguration::loopback_development("ssrf-test", 600, 1_200).unwrap(),
    )
    .unwrap();
    assert!(IdentityApplication::discover(configuration).await.is_err());
    assert_eq!(jwks_requests.load(Ordering::SeqCst), 0);
    provider_task.abort();
    trap_task.abort();
}

fn session_cookie(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| value.split(';').next())
        .find(|value| value.starts_with("browser-flow="))
        .map(str::to_owned)
}

#[tokio::test]
async fn authorization_code_session_and_logout_round_trip() {
    let provider = TestProvider::start_with_distinct_backchannel().await;
    let configuration = provider.configuration();
    let identity = IdentityApplication::discover(configuration.clone())
        .await
        .unwrap();
    let protected = Router::new()
        .route("/protected", post(|| async { StatusCode::NO_CONTENT }))
        .route_layer(middleware::from_fn_with_state(
            IdentityAuthentication::new(identity.clone()),
            IdentityAuthentication::authorize,
        ));
    let application = IdentityHttpApplication::new(identity)
        .router()
        .merge(protected)
        .layer(IdentitySessionLayer::new(configuration.cookie()).memory());

    let rejected_return = application
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/login?return_to=//attacker.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected_return.status(), StatusCode::BAD_REQUEST);

    let disposable_login = application
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/login?return_to=/discarded")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let disposable_cookie = session_cookie(disposable_login.headers()).unwrap();
    let disposable_url = url::Url::parse(
        disposable_login
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let disposable_state = disposable_url
        .query_pairs()
        .find(|(name, _)| name == "state")
        .unwrap()
        .1
        .into_owned();
    let failed_query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("code", "invalid-code")
        .append_pair("state", &disposable_state)
        .finish();
    let failed_callback = application
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/auth/callback?{failed_query}"))
                .header(header::COOKIE, &disposable_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(failed_callback.status(), StatusCode::UNAUTHORIZED);
    let retried_query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("code", "test-code")
        .append_pair("state", &disposable_state)
        .finish();
    let replayed_callback = application
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/auth/callback?{retried_query}"))
                .header(header::COOKIE, disposable_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replayed_callback.status(), StatusCode::CONFLICT);

    let login = application
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/login?return_to=/dashboard?view=risk")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::SEE_OTHER);
    let login_cookie = session_cookie(login.headers()).expect("pending-login cookie");
    let authorization_url = url::Url::parse(
        login
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        authorization_url.origin().ascii_serialization(),
        provider.issuer
    );
    let query = authorization_url
        .query_pairs()
        .into_owned()
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        query.get("code_challenge_method").map(String::as_str),
        Some("S256")
    );
    let state = query.get("state").expect("OAuth state").clone();
    let nonce = query.get("nonce").expect("OIDC nonce").clone();
    *provider.nonce.lock().await = Some(nonce);

    let callback_query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("code", "test-code")
        .append_pair("state", &state)
        .finish();
    let callback = application
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/auth/callback?{callback_query}"))
                .header(header::COOKIE, &login_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(callback.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        callback.headers().get(header::LOCATION).unwrap(),
        "/dashboard?view=risk"
    );
    let authenticated_cookie = session_cookie(callback.headers()).unwrap_or(login_cookie);

    let session_response = application
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/session")
                .header(header::COOKIE, &authenticated_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(session_response.status(), StatusCode::OK);
    let session: IdentitySession = serde_json::from_slice(
        &session_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    assert_eq!(session.status, AuthenticationStatus::Authenticated);
    assert_eq!(
        session.profile.as_ref().unwrap().subject.as_str(),
        "user-42"
    );
    let anti_forgery_token = session
        .anti_forgery_token
        .expect("logout anti-forgery token");

    for request in [
        Request::builder()
            .method("POST")
            .uri("/protected")
            .header(header::COOKIE, &authenticated_cookie)
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .method("POST")
            .uri("/protected")
            .header(header::COOKIE, &authenticated_cookie)
            .header(header::ORIGIN, "https://attacker.example")
            .header("x-anti-forgery-token", &anti_forgery_token)
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .method("POST")
            .uri("/protected")
            .header(header::COOKIE, &authenticated_cookie)
            .header(header::ORIGIN, "http://127.0.0.1:3000")
            .header("x-anti-forgery-token", "incorrect-session-token-value")
            .body(Body::empty())
            .unwrap(),
    ] {
        let rejected = application.clone().oneshot(request).await.unwrap();
        assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
    }
    for duplicated_header in [header::ORIGIN.as_str(), "sec-fetch-site"] {
        let mut request = Request::builder()
            .method("POST")
            .uri("/protected")
            .header(header::COOKIE, &authenticated_cookie)
            .header(header::ORIGIN, "http://127.0.0.1:3000")
            .header("sec-fetch-site", "same-origin")
            .header("x-anti-forgery-token", &anti_forgery_token)
            .body(Body::empty())
            .unwrap();
        request
            .headers_mut()
            .append(duplicated_header, "same-origin".parse().unwrap());
        let rejected = application.clone().oneshot(request).await.unwrap();
        assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
    }
    let accepted = application
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/protected")
                .header(header::COOKIE, &authenticated_cookie)
                .header(header::ORIGIN, "http://127.0.0.1:3000")
                .header("sec-fetch-site", "same-origin")
                .header("x-anti-forgery-token", &anti_forgery_token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::NO_CONTENT);

    let logout = application
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/logout")
                .header(header::COOKIE, &authenticated_cookie)
                .header(header::ORIGIN, "http://127.0.0.1:3000")
                .header("sec-fetch-site", "same-origin")
                .header("x-anti-forgery-token", anti_forgery_token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(logout.status(), StatusCode::OK);
    let logout: IdentityLogout =
        serde_json::from_slice(&logout.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let destination = url::Url::parse(&logout.redirect_to).unwrap();
    assert_eq!(
        destination.as_str().split('?').next().unwrap(),
        format!("{}/logout", provider.issuer)
    );
    let logout_query = destination
        .query_pairs()
        .into_owned()
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        logout_query.get("client_id").map(String::as_str),
        Some("browser-client")
    );
    assert!(!logout_query.contains_key("id_token_hint"));

    let revoked = application
        .oneshot(
            Request::builder()
                .uri("/auth/session")
                .header(header::COOKIE, authenticated_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let revoked: IdentitySession =
        serde_json::from_slice(&revoked.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(revoked.status, AuthenticationStatus::Anonymous);
}
