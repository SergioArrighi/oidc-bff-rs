use gloo_net::http::Request;
use js_sys::{Reflect, Uint8Array};
use oidc_bff_core::{IdentityLogout, IdentitySession};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{RequestCredentials, RequestRedirect};

const MAXIMUM_IDENTITY_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug)]
/// Same-origin client for the BFF session and logout endpoints.
pub struct IdentityClient {
    session_path: SameOriginIdentityPath,
    logout_path: SameOriginIdentityPath,
}

impl Default for IdentityClient {
    fn default() -> Self {
        Self {
            session_path: SameOriginIdentityPath::trusted("/auth/session"),
            logout_path: SameOriginIdentityPath::trusted("/auth/logout"),
        }
    }
}

impl IdentityClient {
    /// Creates a client for custom same-origin session and logout paths.
    pub fn new(
        session_path: impl Into<String>,
        logout_path: impl Into<String>,
    ) -> Result<Self, IdentityClientConfigurationError> {
        Ok(Self {
            session_path: SameOriginIdentityPath::new(session_path.into())?,
            logout_path: SameOriginIdentityPath::new(logout_path.into())?,
        })
    }

    /// Loads the current browser-safe identity session.
    pub async fn session(&self) -> Result<IdentitySession, IdentityClientError> {
        let response = Request::get(self.session_path.as_str())
            .credentials(RequestCredentials::SameOrigin)
            .redirect(RequestRedirect::Error)
            .send()
            .await
            .map_err(|_| IdentityClientError::Network)?;
        if !response.ok() {
            return Err(IdentityClientError::SessionRejected(response.status()));
        }
        let encoded = IdentityResponse::read(response).await?;
        serde_json::from_slice(encoded.as_bytes()).map_err(|_| IdentityClientError::InvalidSession)
    }

    /// Submits a CSRF-protected logout request.
    pub async fn logout(
        &self,
        anti_forgery_token: &str,
    ) -> Result<IdentityLogout, IdentityClientError> {
        if !(16..=512).contains(&anti_forgery_token.len())
            || anti_forgery_token.chars().any(char::is_control)
        {
            return Err(IdentityClientError::InvalidAntiForgeryToken);
        }
        let response = Request::post(self.logout_path.as_str())
            .header("x-anti-forgery-token", anti_forgery_token)
            .credentials(RequestCredentials::SameOrigin)
            .redirect(RequestRedirect::Error)
            .send()
            .await
            .map_err(|_| IdentityClientError::Network)?;
        if !response.ok() {
            return Err(IdentityClientError::LogoutRejected(response.status()));
        }
        let encoded = IdentityResponse::read(response).await?;
        serde_json::from_slice(encoded.as_bytes()).map_err(|_| IdentityClientError::InvalidLogout)
    }
}

#[derive(Clone, Debug)]
struct SameOriginIdentityPath(String);

impl SameOriginIdentityPath {
    fn new(value: String) -> Result<Self, IdentityClientConfigurationError> {
        if !value.starts_with('/')
            || value.starts_with("//")
            || value.contains('\\')
            || value.contains('#')
            || value.len() > 2_048
            || value.chars().any(char::is_control)
        {
            return Err(IdentityClientConfigurationError::UnsafePath);
        }
        Ok(Self(value))
    }

    fn trusted(value: &str) -> Self {
        Self(value.to_owned())
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

struct IdentityResponse(Vec<u8>);

impl IdentityResponse {
    async fn read(response: gloo_net::http::Response) -> Result<Self, IdentityClientError> {
        if response
            .headers()
            .get("content-length")
            .and_then(|value| value.parse::<usize>().ok())
            .is_some_and(|length| length > MAXIMUM_IDENTITY_RESPONSE_BYTES)
        {
            return Err(IdentityClientError::ResponseTooLarge);
        }
        let body = response
            .body()
            .ok_or(IdentityClientError::UnreadableResponse)?;
        let reader: web_sys::ReadableStreamDefaultReader = body.get_reader().unchecked_into();
        let mut encoded = Vec::with_capacity(
            response
                .headers()
                .get("content-length")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or_default()
                .min(MAXIMUM_IDENTITY_RESPONSE_BYTES),
        );
        loop {
            let result = JsFuture::from(reader.read())
                .await
                .map_err(|_| IdentityClientError::UnreadableResponse)?;
            let done = Reflect::get(&result, &"done".into())
                .ok()
                .and_then(|value| value.as_bool())
                .ok_or(IdentityClientError::UnreadableResponse)?;
            if done {
                break;
            }
            let value = Reflect::get(&result, &"value".into())
                .map_err(|_| IdentityClientError::UnreadableResponse)?;
            let chunk = Uint8Array::new(&value);
            if encoded.len().saturating_add(chunk.length() as usize)
                > MAXIMUM_IDENTITY_RESPONSE_BYTES
            {
                let _ = reader.cancel();
                return Err(IdentityClientError::ResponseTooLarge);
            }
            let offset = encoded.len();
            encoded.resize(offset + chunk.length() as usize, 0);
            chunk.copy_to(&mut encoded[offset..]);
        }
        Ok(Self(encoded))
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug, thiserror::Error)]
/// Sanitized failures from the same-origin browser identity boundary.
pub enum IdentityClientError {
    /// The BFF could not be reached.
    #[error("The identity service could not be reached")]
    Network,
    /// Session verification returned a non-success status.
    #[error("Session verification failed with HTTP {0}")]
    SessionRejected(u16),
    /// Logout returned a non-success status.
    #[error("Sign-out failed with HTTP {0}")]
    LogoutRejected(u16),
    /// The response stream could not be consumed.
    #[error("The identity response could not be read")]
    UnreadableResponse,
    /// The response exceeded its fixed browser-side limit.
    #[error("The identity response exceeded 64 KiB")]
    ResponseTooLarge,
    /// The caller supplied a value outside the bounded anti-forgery contract.
    #[error("The anti-forgery token was invalid")]
    InvalidAntiForgeryToken,
    /// Session JSON did not satisfy the identity contract.
    #[error("The sign-in response was invalid")]
    InvalidSession,
    /// Logout JSON did not satisfy the identity contract.
    #[error("The sign-out response was invalid")]
    InvalidLogout,
}

#[derive(Clone, Debug, thiserror::Error)]
/// Invalid browser endpoint configuration rejected before any credentialed request.
pub enum IdentityClientConfigurationError {
    /// Identity endpoints must remain absolute paths on the current origin.
    #[error("identity endpoint must be a same-origin absolute path")]
    UnsafePath,
}
