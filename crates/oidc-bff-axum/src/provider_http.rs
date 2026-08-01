use std::{future::Future, pin::Pin, time::Duration};

use futures::StreamExt;
use openidconnect::{AsyncHttpClient, HttpRequest, HttpResponse};
use serde::de::DeserializeOwned;
use url::Url;

const MAXIMUM_PROVIDER_RESPONSE_BYTES: usize = 1024 * 1024;
const MAXIMUM_PROVIDER_REQUEST_BYTES: usize = 64 * 1024;

enum ProviderJsonKind {
    Discovery,
    Jwks,
}

#[derive(Clone)]
/// Redirect-free, time-bounded and response-bounded OIDC back-channel transport.
pub(crate) struct ProviderHttpClient {
    client: openidconnect::reqwest::Client,
}

impl ProviderHttpClient {
    pub fn new() -> Result<Self, ProviderHttpError> {
        let client = openidconnect::reqwest::ClientBuilder::new()
            .redirect(openidconnect::reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|_| ProviderHttpError::ClientConstruction)?;
        Ok(Self { client })
    }

    pub fn raw(&self) -> &openidconnect::reqwest::Client {
        &self.client
    }

    pub async fn get_discovery_document<T>(&self, url: &Url) -> Result<T, ProviderHttpError>
    where
        T: DeserializeOwned,
    {
        self.get_json(url, ProviderJsonKind::Discovery).await
    }

    pub async fn get_jwks_document<T>(&self, url: &Url) -> Result<T, ProviderHttpError>
    where
        T: DeserializeOwned,
    {
        self.get_json(url, ProviderJsonKind::Jwks).await
    }

    async fn get_json<T>(&self, url: &Url, kind: ProviderJsonKind) -> Result<T, ProviderHttpError>
    where
        T: DeserializeOwned,
    {
        let request = axum::http::Request::builder()
            .method(axum::http::Method::GET)
            .uri(url.as_str())
            .header(axum::http::header::ACCEPT, "application/json")
            .body(Vec::new())
            .map_err(|_| ProviderHttpError::InvalidRequest)?;
        let response = self.execute(request).await?;
        if response.status() != axum::http::StatusCode::OK {
            return Err(ProviderHttpError::UnexpectedStatus);
        }
        let content_type = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim);
        let content_type_is_valid = match kind {
            ProviderJsonKind::Discovery => {
                content_type.is_some_and(|value| value.eq_ignore_ascii_case("application/json"))
            }
            ProviderJsonKind::Jwks => content_type.is_some_and(|value| {
                value.eq_ignore_ascii_case("application/json")
                    || value.eq_ignore_ascii_case("application/jwk-set+json")
            }),
        };
        if !content_type_is_valid {
            return Err(ProviderHttpError::UnexpectedContentType);
        }
        serde_json::from_slice(response.body()).map_err(|_| ProviderHttpError::InvalidJson)
    }

    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, ProviderHttpError> {
        if request.body().len() > MAXIMUM_PROVIDER_REQUEST_BYTES {
            return Err(ProviderHttpError::RequestTooLarge);
        }
        let response = self
            .client
            .execute(
                request
                    .try_into()
                    .map_err(|_| ProviderHttpError::InvalidRequest)?,
            )
            .await
            .map_err(|_| ProviderHttpError::RequestFailed)?;
        if response
            .content_length()
            .is_some_and(|length| length > MAXIMUM_PROVIDER_RESPONSE_BYTES as u64)
        {
            return Err(ProviderHttpError::ResponseTooLarge);
        }

        let mut builder = axum::http::Response::builder()
            .status(response.status())
            .version(response.version());
        for (name, value) in response.headers() {
            builder = builder.header(name, value);
        }
        let mut body = Vec::with_capacity(
            response
                .content_length()
                .unwrap_or_default()
                .min(MAXIMUM_PROVIDER_RESPONSE_BYTES as u64) as usize,
        );
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| ProviderHttpError::ResponseReadFailed)?;
            if body.len().saturating_add(chunk.len()) > MAXIMUM_PROVIDER_RESPONSE_BYTES {
                return Err(ProviderHttpError::ResponseTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        builder
            .body(body)
            .map_err(|_| ProviderHttpError::InvalidResponse)
    }
}

impl<'client> AsyncHttpClient<'client> for ProviderHttpClient {
    type Error = ProviderHttpError;
    type Future =
        Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + Send + Sync + 'client>>;

    fn call(&'client self, request: HttpRequest) -> Self::Future {
        Box::pin(self.execute(request))
    }
}

#[derive(Debug, thiserror::Error)]
/// Sanitized provider transport failures that never expose request secrets or response bodies.
pub(crate) enum ProviderHttpError {
    #[error("provider HTTP client construction failed")]
    ClientConstruction,
    #[error("provider request is invalid")]
    InvalidRequest,
    #[error("provider request is too large")]
    RequestTooLarge,
    #[error("provider request failed")]
    RequestFailed,
    #[error("provider response could not be read")]
    ResponseReadFailed,
    #[error("provider response is too large")]
    ResponseTooLarge,
    #[error("provider response is invalid")]
    InvalidResponse,
    #[error("provider returned an unexpected status")]
    UnexpectedStatus,
    #[error("provider returned an unexpected content type")]
    UnexpectedContentType,
    #[error("provider returned invalid JSON")]
    InvalidJson,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        http::{StatusCode, header},
        response::IntoResponse,
        routing::get,
    };

    struct ProviderHttpFixture {
        origin: String,
        task: tokio::task::JoinHandle<()>,
    }

    impl ProviderHttpFixture {
        async fn start() -> Self {
            let router = Router::new()
                .route(
                    "/large",
                    get(|| async { vec![b'x'; MAXIMUM_PROVIDER_RESPONSE_BYTES + 1] }),
                )
                .route(
                    "/redirect",
                    get(|| async {
                        (StatusCode::FOUND, [(header::LOCATION, "/destination")]).into_response()
                    }),
                )
                .route("/destination", get(|| async { "followed" }));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin = format!("http://{}", listener.local_addr().unwrap());
            let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
            Self { origin, task }
        }

        fn request(&self, path: &str) -> HttpRequest {
            axum::http::Request::builder()
                .uri(format!("{}{path}", self.origin))
                .body(Vec::new())
                .unwrap()
        }
    }

    impl Drop for ProviderHttpFixture {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    #[tokio::test]
    async fn bounds_decompressed_responses_and_never_follows_redirects() {
        let fixture = ProviderHttpFixture::start().await;
        let client = ProviderHttpClient::new().unwrap();
        assert!(matches!(
            client.call(fixture.request("/large")).await,
            Err(ProviderHttpError::ResponseTooLarge)
        ));
        let redirect = client.call(fixture.request("/redirect")).await.unwrap();
        assert_eq!(redirect.status(), StatusCode::FOUND);
        assert!(redirect.body().is_empty());
    }
}
