use std::{
    ops::Deref,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use oidc_bff_core::{
    AuthenticationStatus, EmailAddress, IdentityLogout, IdentitySession, UserProfile, UserSubject,
};
use openidconnect::{
    AccessTokenHash, AuthType, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    EndpointMaybeSet, EndpointNotSet, EndpointSet, IssuerUrl, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, PkceCodeVerifier, ProviderMetadataWithLogout, RedirectUrl, Scope,
    TokenResponse,
    core::{
        CoreAuthenticationFlow, CoreClient, CoreClientAuthMethod, CoreJsonWebKeySet,
        CoreJwsSigningAlgorithm,
    },
};
use tower_sessions::Session;
use url::Url;

use crate::access_token::{AccessTokenVerificationPolicy, AccessTokenVerifier};
use crate::provider_http::ProviderHttpClient;
use crate::session::{AuthenticatedIdentitySession, IdentitySessionState, PendingLogin};
use crate::{IdentityConfiguration, IdentityError};

const LOGIN_TRANSACTION_LIFETIME_SECONDS: u64 = 300;

type DiscoveredClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

#[derive(Clone)]
/// Discovered OIDC relying party and JWT authentication service.
pub struct IdentityApplication {
    inner: Arc<IdentityApplicationInner>,
}

struct IdentityApplicationInner {
    client: DiscoveredClient,
    http_client: ProviderHttpClient,
    configuration: IdentityConfiguration,
    expected_browser_origin: String,
    end_session_endpoint: Option<Url>,
    access_token_verifier: AccessTokenVerifier,
}

#[derive(Clone)]
/// Authenticated human or workload inserted into Axum request extensions.
pub struct AuthenticatedUser {
    /// Validated profile projected from trusted token or ID-token claims.
    pub profile: UserProfile,
    /// Provider session/token identifier used for downstream session binding.
    pub authentication_session_id: String,
    /// Whether this principal represents a human or a workload.
    pub kind: AuthenticationPrincipalKind,
    /// Credential channel used to authenticate this request.
    pub method: AuthenticationMethod,
}

impl std::fmt::Debug for AuthenticatedUser {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedUser")
            .field("profile", &"[REDACTED]")
            .field("authentication_session_id", &"[REDACTED]")
            .field("kind", &self.kind)
            .field("method", &self.method)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Credential channel used by the authenticated request.
pub enum AuthenticationMethod {
    /// Opaque browser cookie resolved through the server-side session store.
    BrowserSession,
    /// OAuth bearer access token validated by the resource server.
    BearerToken,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Authentication class used to keep human and workload routes distinct.
pub enum AuthenticationPrincipalKind {
    /// Interactive or bearer-token human identity.
    Human,
    /// Client-credential workload identity satisfying the configured policy.
    Workload,
}

impl IdentityApplication {
    /// Validates configuration, discovers the provider, and retrieves initial JWKS.
    pub async fn discover(configuration: IdentityConfiguration) -> Result<Self, IdentityError> {
        let expected_browser_origin = configuration.browser().serialized_origin();
        let http_client = ProviderHttpClient::new()
            .map_err(|error| IdentityError::Configuration(error.to_string()))?;
        let provider_metadata =
            Self::discover_provider_metadata(&configuration, &http_client).await?;
        let end_session_endpoint = provider_metadata
            .additional_metadata()
            .end_session_endpoint
            .as_ref()
            .map(|endpoint| endpoint.url().to_owned());
        let jwks_url = provider_metadata.jwks_uri().url().to_owned();
        let access_token_verifier = AccessTokenVerifier::discover(
            http_client.raw().clone(),
            jwks_url,
            AccessTokenVerificationPolicy::from_configuration(&configuration),
        )
        .await?;
        let client = Self::configured_client(&configuration, provider_metadata)?;

        Ok(Self {
            inner: Arc::new(IdentityApplicationInner {
                client,
                http_client,
                configuration,
                expected_browser_origin,
                end_session_endpoint,
                access_token_verifier,
            }),
        })
    }

    /// Starts an authorization-code login and stores its bounded transaction state.
    pub async fn begin_login(
        &self,
        session: &Session,
        return_to: Option<&str>,
    ) -> Result<Url, IdentityError> {
        let return_to = self.valid_return_path(return_to.unwrap_or("/"))?;
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let (authorization_url, state, nonce) = self
            .inner
            .client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("profile".to_owned()))
            .add_scope(Scope::new("email".to_owned()))
            .add_scope(Scope::new("groups".to_owned()))
            .set_pkce_challenge(pkce_challenge)
            .url();
        IdentitySessionState::new(session)
            .set_pending(PendingLogin {
                state: state.secret().to_owned(),
                nonce: nonce.secret().to_owned(),
                pkce_verifier: pkce_verifier.secret().to_owned(),
                return_to,
                created_at_epoch_seconds: EpochSeconds::now()?.value(),
            })
            .await?;
        Ok(authorization_url)
    }

    /// Verifies and completes an authorization callback, rotating the session ID.
    pub async fn complete_login(
        &self,
        session: &Session,
        code: &str,
        state: &str,
    ) -> Result<String, IdentityError> {
        let session_state = IdentitySessionState::new(session);
        let pending = session_state
            .pending()
            .await?
            .ok_or(IdentityError::LoginTransactionMissing)?;
        let now = EpochSeconds::now()?.value();
        if now.saturating_sub(pending.created_at_epoch_seconds) > LOGIN_TRANSACTION_LIFETIME_SECONDS
        {
            session_state.clear_pending().await?;
            return Err(IdentityError::LoginTransactionMissing);
        }
        if !pending.matches_state(state) {
            session_state.clear_pending().await?;
            return Err(IdentityError::LoginStateInvalid);
        }
        // Consume the one-time browser transaction before contacting the provider so two
        // concurrent callbacks cannot both attempt to establish a session from it.
        session_state.clear_pending().await?;

        let current_provider =
            Self::discover_provider_metadata(&self.inner.configuration, &self.inner.http_client)
                .await?;
        let current_client = Self::configured_client(&self.inner.configuration, current_provider)?;
        let token_response = current_client
            .exchange_code(AuthorizationCode::new(code.to_owned()))
            .map_err(|_| IdentityError::Provider)?
            .set_pkce_verifier(PkceCodeVerifier::new(pending.pkce_verifier))
            .request_async(&self.inner.http_client)
            .await
            .map_err(|_| IdentityError::LoginRejected)?;
        let id_token = token_response
            .id_token()
            .ok_or(IdentityError::IdentityTokenMissing)?;
        let verifier = current_client
            .id_token_verifier()
            .set_allowed_algs([CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256]);
        let claims = id_token
            .claims(&verifier, &Nonce::new(pending.nonce))
            .map_err(|_| IdentityError::IdentityTokenInvalid)?;
        if let Some(expected_hash) = claims.access_token_hash() {
            let actual_hash = AccessTokenHash::from_token(
                token_response.access_token(),
                id_token
                    .signing_alg()
                    .map_err(|_| IdentityError::IdentityTokenInvalid)?,
                id_token
                    .signing_key(&verifier)
                    .map_err(|_| IdentityError::IdentityTokenInvalid)?,
            )
            .map_err(|_| IdentityError::IdentityTokenInvalid)?;
            if actual_hash != *expected_hash {
                return Err(IdentityError::IdentityTokenInvalid);
            }
        }

        let profile = VerifiedIdentityProfile::from_claims(claims)?.into_profile();
        let provider_expiry: u64 = claims
            .expiration()
            .timestamp()
            .try_into()
            .map_err(|_| IdentityError::IdentityTokenInvalid)?;
        let configured_expiry = now.saturating_add(
            self.inner
                .configuration
                .cookie()
                .absolute_lifetime_seconds(),
        );
        let expires_at_epoch_seconds = provider_expiry.min(configured_expiry);
        if expires_at_epoch_seconds <= now {
            return Err(IdentityError::IdentityTokenInvalid);
        }
        session_state
            .establish(AuthenticatedIdentitySession {
                profile,
                authentication_session_id: CsrfToken::new_random().secret().to_owned(),
                anti_forgery_token: CsrfToken::new_random().secret().to_owned(),
                expires_at_epoch_seconds,
            })
            .await?;
        Ok(pending.return_to)
    }

    /// Returns the browser-safe anonymous or authenticated session projection.
    pub async fn session(&self, session: &Session) -> Result<IdentitySession, IdentityError> {
        let session_state = IdentitySessionState::new(session);
        let Some(authenticated) = session_state.authenticated().await? else {
            return Ok(self.anonymous_session());
        };
        if authenticated.expires_at_epoch_seconds <= EpochSeconds::now()?.value() {
            session_state.revoke().await?;
            return Ok(self.anonymous_session());
        }
        Ok(IdentitySession {
            status: AuthenticationStatus::Authenticated,
            profile: Some(authenticated.profile),
            anti_forgery_token: Some(authenticated.anti_forgery_token),
            expires_at_epoch_seconds: Some(authenticated.expires_at_epoch_seconds),
            sign_in_path: "/auth/login".to_owned(),
            sign_out_path: "/auth/logout".to_owned(),
            account_url: self
                .inner
                .configuration
                .provider()
                .account_url()
                .to_string(),
        })
    }

    /// Resolves the authenticated human bound to a server-side browser session.
    pub async fn authenticated_user(
        &self,
        session: &Session,
    ) -> Result<AuthenticatedUser, IdentityError> {
        self.authenticated_browser_request(session, None).await
    }

    pub(crate) async fn authenticated_browser_request(
        &self,
        session: &Session,
        anti_forgery_token: Option<&str>,
    ) -> Result<AuthenticatedUser, IdentityError> {
        let session_state = IdentitySessionState::new(session);
        let authenticated = session_state
            .authenticated()
            .await?
            .ok_or(IdentityError::AuthenticationRequired)?;
        if authenticated.expires_at_epoch_seconds <= EpochSeconds::now()?.value() {
            session_state.revoke().await?;
            return Err(IdentityError::AuthenticationRequired);
        }
        if anti_forgery_token
            .is_some_and(|candidate| !authenticated.matches_anti_forgery_token(candidate))
        {
            return Err(IdentityError::CsrfRejected);
        }
        Ok(AuthenticatedUser {
            profile: authenticated.profile,
            authentication_session_id: authenticated.authentication_session_id,
            kind: AuthenticationPrincipalKind::Human,
            method: AuthenticationMethod::BrowserSession,
        })
    }

    /// Verifies a bearer JWT and projects its authenticated principal.
    pub async fn authenticated_access_token(
        &self,
        token: &str,
    ) -> Result<AuthenticatedUser, IdentityError> {
        self.inner.access_token_verifier.verify(token).await
    }

    /// Revokes the local session after constant-time CSRF verification.
    pub async fn logout(
        &self,
        session: &Session,
        anti_forgery_token: &str,
    ) -> Result<IdentityLogout, IdentityError> {
        let session_state = IdentitySessionState::new(session);
        let authenticated = session_state
            .authenticated()
            .await?
            .ok_or(IdentityError::AuthenticationRequired)?;
        if !authenticated.matches_anti_forgery_token(anti_forgery_token) {
            return Err(IdentityError::CsrfRejected);
        }
        session_state.revoke().await?;
        let redirect_to = self.logout_url();
        Ok(IdentityLogout {
            redirect_to: redirect_to.to_string(),
        })
    }

    fn anonymous_session(&self) -> IdentitySession {
        IdentitySession::anonymous(
            "/auth/login",
            "/auth/logout",
            self.inner
                .configuration
                .provider()
                .account_url()
                .to_string(),
        )
    }

    fn valid_return_path(&self, value: &str) -> Result<String, IdentityError> {
        if value.len() > 2_048
            || !value.starts_with('/')
            || value.starts_with("//")
            || value.contains('\\')
            || value.chars().any(char::is_control)
        {
            return Err(IdentityError::InvalidReturnLocation);
        }
        let resolved = self
            .inner
            .configuration
            .browser()
            .origin()
            .join(value)
            .map_err(|_| IdentityError::InvalidReturnLocation)?;
        if resolved.origin() != self.inner.configuration.browser().origin().origin() {
            return Err(IdentityError::InvalidReturnLocation);
        }
        Ok(value.to_owned())
    }

    fn logout_url(&self) -> Url {
        let Some(mut endpoint) = self.inner.end_session_endpoint.clone() else {
            return self
                .inner
                .configuration
                .browser()
                .post_logout_redirect_uri()
                .clone();
        };
        endpoint
            .query_pairs_mut()
            .append_pair("client_id", self.inner.configuration.provider().client_id())
            .append_pair(
                "post_logout_redirect_uri",
                self.inner
                    .configuration
                    .browser()
                    .post_logout_redirect_uri()
                    .as_str(),
            );
        endpoint
    }

    pub(crate) fn expected_browser_origin(&self) -> &str {
        &self.inner.expected_browser_origin
    }

    async fn discover_provider_metadata(
        configuration: &IdentityConfiguration,
        http_client: &ProviderHttpClient,
    ) -> Result<ProviderMetadataWithLogout, IdentityError> {
        let issuer = IssuerUrl::new(configuration.provider().issuer().to_string())
            .map_err(|error| IdentityError::Configuration(error.to_string()))?;
        let discovery_url = issuer
            .join(".well-known/openid-configuration")
            .map_err(|_| IdentityError::Discovery)?;
        configuration
            .validate_provider_endpoint(&discovery_url)
            .map_err(|error| IdentityError::Configuration(error.to_string()))?;
        let mut metadata: ProviderMetadataWithLogout = http_client
            .get_discovery_document(&discovery_url)
            .await
            .map_err(|_| IdentityError::Discovery)?;
        if metadata.issuer() != &issuer {
            return Err(IdentityError::Discovery);
        }
        // Validate every discovered destination before the first request to it. The
        // upstream convenience discovery fetches JWKS before returning metadata, which
        // is too late for this same-origin SSRF boundary.
        Self::validate_provider_metadata(configuration, &metadata)?;
        let jwks_document: serde_json::Value = http_client
            .get_jwks_document(metadata.jwks_uri().url())
            .await
            .map_err(|_| IdentityError::Discovery)?;
        AccessTokenVerifier::validate_jwks_document(&jwks_document)?;
        let jwks: CoreJsonWebKeySet =
            serde_json::from_value(jwks_document).map_err(|_| IdentityError::Discovery)?;
        metadata = metadata.set_jwks(jwks);
        Ok(metadata)
    }

    fn configured_client(
        configuration: &IdentityConfiguration,
        provider_metadata: ProviderMetadataWithLogout,
    ) -> Result<DiscoveredClient, IdentityError> {
        Ok(CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(configuration.provider().client_id().to_owned()),
            Some(ClientSecret::new(
                configuration.provider().client_secret().expose().to_owned(),
            )),
        )
        .set_auth_type(AuthType::BasicAuth)
        .set_redirect_uri(
            RedirectUrl::new(configuration.browser().redirect_uri().to_string())
                .map_err(|error| IdentityError::Configuration(error.to_string()))?,
        ))
    }

    fn validate_provider_metadata(
        configuration: &IdentityConfiguration,
        metadata: &ProviderMetadataWithLogout,
    ) -> Result<(), IdentityError> {
        configuration
            .validate_provider_endpoint(metadata.authorization_endpoint().url())
            .map_err(|error| IdentityError::Configuration(error.to_string()))?;
        configuration
            .validate_provider_endpoint(metadata.jwks_uri().url())
            .map_err(|error| IdentityError::Configuration(error.to_string()))?;
        let token_endpoint = metadata.token_endpoint().ok_or_else(|| {
            IdentityError::Configuration("provider token endpoint missing".to_owned())
        })?;
        configuration
            .validate_provider_endpoint(token_endpoint.url())
            .map_err(|error| IdentityError::Configuration(error.to_string()))?;
        if let Some(endpoint) = metadata.additional_metadata().end_session_endpoint.as_ref() {
            configuration
                .validate_provider_endpoint(endpoint.url())
                .map_err(|error| IdentityError::Configuration(error.to_string()))?;
        }
        if metadata
            .token_endpoint_auth_methods_supported()
            .is_some_and(|methods| !methods.contains(&CoreClientAuthMethod::ClientSecretBasic))
        {
            return Err(IdentityError::Configuration(
                "provider does not support client_secret_basic".to_owned(),
            ));
        }
        if !metadata
            .id_token_signing_alg_values_supported()
            .contains(&CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256)
        {
            return Err(IdentityError::Configuration(
                "provider does not support RS256 ID tokens".to_owned(),
            ));
        }
        Ok(())
    }
}

struct VerifiedIdentityProfile(UserProfile);

impl VerifiedIdentityProfile {
    fn from_claims(
        claims: &openidconnect::IdTokenClaims<
            openidconnect::EmptyAdditionalClaims,
            openidconnect::core::CoreGenderClaim,
        >,
    ) -> Result<Self, IdentityError> {
        let subject = UserSubject::parse(claims.subject().as_str())
            .map_err(|_| IdentityError::ProfileInvalid)?;
        let email = claims
            .email()
            .map(|value| EmailAddress::parse(value.as_str()))
            .transpose()
            .map_err(|_| IdentityError::ProfileInvalid)?;
        let preferred_username = claims
            .preferred_username()
            .map(|value| value.as_str().to_owned());
        let given_name = Self::localized(claims.given_name());
        let family_name = Self::localized(claims.family_name());
        let name = Self::localized(claims.name());
        let display_name = name
            .or_else(|| preferred_username.clone())
            .or_else(|| email.as_ref().map(|value| value.as_str().to_owned()))
            .unwrap_or_else(|| subject.as_str().to_owned());
        let profile = UserProfile {
            subject,
            email,
            email_verified: claims.email_verified().unwrap_or(false),
            preferred_username,
            given_name,
            family_name,
            display_name,
            roles: Vec::new(),
            groups: Vec::new(),
        }
        .validate()
        .map_err(|_| IdentityError::ProfileInvalid)?;
        Ok(Self(profile))
    }

    fn localized<T: Deref<Target = String>>(
        claim: Option<&openidconnect::LocalizedClaim<T>>,
    ) -> Option<String> {
        claim
            .and_then(|value| {
                value
                    .get(None)
                    .or_else(|| value.iter().next().map(|(_, item)| item))
            })
            .map(|value| value.as_str().to_owned())
    }

    fn into_profile(self) -> UserProfile {
        self.0
    }
}

struct EpochSeconds(u64);

impl EpochSeconds {
    fn now() -> Result<Self, IdentityError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| Self(duration.as_secs()))
            .map_err(|_| IdentityError::Session)
    }

    fn value(self) -> u64 {
        self.0
    }
}
