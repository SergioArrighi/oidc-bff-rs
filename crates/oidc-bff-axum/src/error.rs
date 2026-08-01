use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::IntoResponse,
};
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
/// Authentication, provider, callback, session, and token-validation failures.
pub enum IdentityError {
    #[error("identity configuration failed: {0}")]
    Configuration(String),
    #[error("identity provider discovery failed")]
    Discovery,
    #[error("identity provider request failed")]
    Provider,
    #[error("login transaction is missing or expired")]
    LoginTransactionMissing,
    #[error("login transaction state is invalid")]
    LoginStateInvalid,
    #[error("identity provider rejected the login")]
    LoginRejected,
    #[error("identity token is missing")]
    IdentityTokenMissing,
    #[error("identity token is invalid")]
    IdentityTokenInvalid,
    #[error("authenticated profile is invalid")]
    ProfileInvalid,
    #[error("authentication is required")]
    AuthenticationRequired,
    #[error("bearer authentication is required")]
    BearerTokenRequired,
    #[error("access token is invalid")]
    AccessTokenInvalid,
    #[error("cross-site request validation failed")]
    CsrfRejected,
    #[error("identity session storage failed")]
    Session,
    #[error("return location is invalid")]
    InvalidReturnLocation,
}

#[derive(Serialize)]
struct IdentityProblem {
    code: &'static str,
    message: String,
}

impl IntoResponse for IdentityError {
    fn into_response(self) -> axum::response::Response {
        let bearer_failure = matches!(&self, Self::BearerTokenRequired | Self::AccessTokenInvalid);
        let (status, code, message) = match self {
            Self::AuthenticationRequired => (
                StatusCode::UNAUTHORIZED,
                "authentication_required",
                "Authentication is required",
            ),
            Self::BearerTokenRequired | Self::AccessTokenInvalid => (
                StatusCode::UNAUTHORIZED,
                "bearer_authentication_required",
                "A valid bearer access token is required",
            ),
            Self::CsrfRejected | Self::LoginStateInvalid => (
                StatusCode::FORBIDDEN,
                "identity_request_rejected",
                "The identity request was rejected",
            ),
            Self::LoginTransactionMissing => (
                StatusCode::CONFLICT,
                "login_transaction_unavailable",
                "The login transaction is unavailable",
            ),
            Self::InvalidReturnLocation => (
                StatusCode::BAD_REQUEST,
                "invalid_return_location",
                "The return location is invalid",
            ),
            Self::LoginRejected => (
                StatusCode::UNAUTHORIZED,
                "login_rejected",
                "The identity provider rejected the login",
            ),
            _ => (
                StatusCode::BAD_GATEWAY,
                "identity_service_failed",
                "The identity service failed",
            ),
        };
        let mut response = (
            status,
            Json(IdentityProblem {
                code,
                message: message.to_owned(),
            }),
        )
            .into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        if bearer_failure {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer error=\"invalid_token\""),
            );
        }
        response
    }
}
