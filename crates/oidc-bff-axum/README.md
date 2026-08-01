# oidc-bff-axum

`oidc-bff-axum` is a strict OpenID Connect session BFF and JWT resource-server
boundary for Axum. It is designed for a co-located application resource server,
not as a generic OAuth token relay.

It provides confidential Authorization Code + PKCE login, server-side browser
sessions, origin- and token-bound anti-forgery protection, bounded provider
transport, RP-initiated logout, and separate human/workload JWT middleware.

## Provider profile

The provider must expose same-origin OIDC discovery, authorization, token,
JWKS, and optional logout endpoints; support `client_secret_basic`, PKCE S256,
and RS256 ID tokens; and issue RS256 JWT access tokens with the configured
`typ`, issuer, audience, `iat`, expiry, and `azp`.

## Axum integration

```rust,no_run
use axum::{Router, middleware, routing::get};
use oidc_bff_axum::{
    BrowserApplicationConfiguration, ClientSecretCredential, IdentityApplication,
    IdentityAuthentication, IdentityConfiguration, IdentityHttpApplication,
    IdentitySessionLayer, ProviderConfiguration, ResourceServerConfiguration,
    SessionCookieConfiguration,
};
use tower_sessions::MemoryStore;
use url::Url;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let configuration = IdentityConfiguration::new(
        ProviderConfiguration::new(
            Url::parse("https://identity.example.com/")?,
            "browser-client",
            ClientSecretCredential::new(std::env::var("OIDC_CLIENT_SECRET")?)?,
            Url::parse("https://identity.example.com/account")?,
        )?,
        BrowserApplicationConfiguration::new(
            Url::parse("https://app.example.com/")?,
            Url::parse("https://app.example.com/auth/callback")?,
            Url::parse("https://app.example.com/")?,
        )?,
        ResourceServerConfiguration::new(
            "application-api",
            "browser-client",
            "automation-client",
            "application_api",
            "at+jwt",
        )?,
        SessionCookieConfiguration::production("application", 1_800, 3_600)?,
    )?;
    let identity = IdentityApplication::discover(configuration.clone()).await?;
    let protected = Router::new()
        .route("/api/me", get(|| async { "authenticated" }))
        .route_layer(middleware::from_fn_with_state(
            IdentityAuthentication::new(identity.clone()),
            IdentityAuthentication::authorize,
        ));
    let session_layer = IdentitySessionLayer::new(configuration.cookie())
        .store(MemoryStore::default()); // Replace with an encrypted durable store.
    let app = Router::new()
        .merge(IdentityHttpApplication::new(identity).router())
        .merge(protected)
        .layer(session_layer);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

`IdentityHttpApplication` mounts `/auth/login`, `/auth/callback`,
`/auth/session`, and `/auth/logout`. Unsafe browser API requests must carry the
`anti_forgery_token` returned by `/auth/session` in
`x-anti-forgery-token`; the middleware also checks the exact `Origin`.

`MemoryStore` is deliberately shown only to keep the example executable. It is
not production storage. Read the repository
[production security profile](../../docs/oidc-bff-security.md) before deploying.

Licensed under the MIT License.
