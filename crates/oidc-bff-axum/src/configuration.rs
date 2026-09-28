use std::fmt;

use url::Url;
use zeroize::Zeroizing;

const PRODUCTION_COOKIE_PREFIX: &str = "__Host-Http-";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Transport and cookie guarantees required by the deployment environment.
pub enum DeploymentMode {
    /// HTTPS is mandatory for the provider and browser application.
    Production,
    /// Plain HTTP is permitted only on loopback hosts for local development and tests.
    LoopbackDevelopment,
}

#[derive(Clone)]
/// Confidential OAuth client credential. Debug output is always redacted.
pub struct ClientSecretCredential(Zeroizing<String>);

impl ClientSecretCredential {
    /// Creates a bounded client secret suitable for HTTP Basic client authentication.
    pub fn new(value: impl Into<String>) -> Result<Self, ConfigurationError> {
        let value = value.into();
        if value.len() < 32 || value.len() > 4_096 || value.chars().any(char::is_control) {
            return Err(ConfigurationError::Invalid("provider.client_secret"));
        }
        Ok(Self(Zeroizing::new(value)))
    }

    pub(crate) fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for ClientSecretCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClientSecretCredential([REDACTED])")
    }
}

#[derive(Clone, Debug)]
/// OIDC provider and confidential relying-party registration.
pub struct ProviderConfiguration {
    issuer: Url,
    backchannel_base_url: Option<Url>,
    client_id: String,
    client_secret: ClientSecretCredential,
    account_url: Url,
}

impl ProviderConfiguration {
    /// Constructs provider configuration without performing network discovery.
    pub fn new(
        issuer: Url,
        client_id: impl Into<String>,
        client_secret: ClientSecretCredential,
        account_url: Url,
    ) -> Result<Self, ConfigurationError> {
        let configuration = Self {
            issuer,
            backchannel_base_url: None,
            client_id: client_id.into(),
            client_secret,
            account_url,
        };
        configuration.validate_identifiers()?;
        Ok(configuration)
    }

    /// Uses a distinct server-to-server origin for discovery, token exchange,
    /// and JWKS retrieval while retaining `issuer` for browser redirects and
    /// token validation.
    pub fn with_backchannel_base_url(
        mut self,
        backchannel_base_url: Url,
    ) -> Result<Self, ConfigurationError> {
        self.backchannel_base_url = Some(backchannel_base_url);
        self.validate_identifiers()?;
        Ok(self)
    }

    pub(crate) fn issuer(&self) -> &Url {
        &self.issuer
    }

    pub(crate) fn backchannel_base_url(&self) -> Option<&Url> {
        self.backchannel_base_url.as_ref()
    }

    pub(crate) fn client_id(&self) -> &str {
        &self.client_id
    }

    pub(crate) fn client_secret(&self) -> &ClientSecretCredential {
        &self.client_secret
    }

    pub(crate) fn account_url(&self) -> &Url {
        &self.account_url
    }

    fn validate_identifiers(&self) -> Result<(), ConfigurationError> {
        IdentityConfiguration::validate_identifier(&self.client_id, "provider.client_id")?;
        if self.issuer.query().is_some() {
            return Err(ConfigurationError::Invalid("provider.issuer"));
        }
        if self
            .backchannel_base_url
            .as_ref()
            .is_some_and(|url| url.query().is_some())
        {
            return Err(ConfigurationError::Invalid("provider.backchannel_base_url"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
/// Browser origin and the exact provider-registered redirect locations.
pub struct BrowserApplicationConfiguration {
    origin: Url,
    redirect_uri: Url,
    post_logout_redirect_uri: Url,
}

impl BrowserApplicationConfiguration {
    /// Creates a browser configuration and requires both redirects to remain on its origin.
    pub fn new(
        origin: Url,
        redirect_uri: Url,
        post_logout_redirect_uri: Url,
    ) -> Result<Self, ConfigurationError> {
        let configuration = Self {
            origin,
            redirect_uri,
            post_logout_redirect_uri,
        };
        configuration.validate_origins()?;
        Ok(configuration)
    }

    pub(crate) fn origin(&self) -> &Url {
        &self.origin
    }

    pub(crate) fn redirect_uri(&self) -> &Url {
        &self.redirect_uri
    }

    pub(crate) fn post_logout_redirect_uri(&self) -> &Url {
        &self.post_logout_redirect_uri
    }

    pub(crate) fn serialized_origin(&self) -> String {
        self.origin.origin().ascii_serialization()
    }

    fn validate_origins(&self) -> Result<(), ConfigurationError> {
        if self.origin.path() != "/"
            || self.origin.query().is_some()
            || self.origin.fragment().is_some()
            || self.redirect_uri.origin() != self.origin.origin()
            || self.post_logout_redirect_uri.origin() != self.origin.origin()
        {
            return Err(ConfigurationError::Invalid("browser.origin"));
        }
        if self.redirect_uri.path() != "/auth/callback"
            || self.redirect_uri.query().is_some()
            || self.redirect_uri.fragment().is_some()
        {
            return Err(ConfigurationError::Invalid("browser.redirect_uri"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
/// JWT resource-server rules for human and workload access tokens.
pub struct ResourceServerConfiguration {
    audience: String,
    human_client_id: String,
    workload_client_id: String,
    workload_required_scope: String,
    access_token_type: String,
}

impl ResourceServerConfiguration {
    /// Creates a resource policy with an exact JWT `typ` value.
    pub fn new(
        audience: impl Into<String>,
        human_client_id: impl Into<String>,
        workload_client_id: impl Into<String>,
        workload_required_scope: impl Into<String>,
        access_token_type: impl Into<String>,
    ) -> Result<Self, ConfigurationError> {
        let configuration = Self {
            audience: audience.into(),
            human_client_id: human_client_id.into(),
            workload_client_id: workload_client_id.into(),
            workload_required_scope: workload_required_scope.into(),
            access_token_type: access_token_type.into(),
        };
        configuration.validate()?;
        Ok(configuration)
    }

    pub(crate) fn audience(&self) -> &str {
        &self.audience
    }

    pub(crate) fn workload_client_id(&self) -> &str {
        &self.workload_client_id
    }

    pub(crate) fn human_client_id(&self) -> &str {
        &self.human_client_id
    }

    pub(crate) fn workload_required_scope(&self) -> &str {
        &self.workload_required_scope
    }

    pub(crate) fn access_token_type(&self) -> &str {
        &self.access_token_type
    }

    /// Revalidates all configuration invariants.
    pub fn validate(&self) -> Result<(), ConfigurationError> {
        IdentityConfiguration::validate_identifier(&self.audience, "resource.audience")?;
        IdentityConfiguration::validate_identifier(
            &self.human_client_id,
            "resource.human_client_id",
        )?;
        IdentityConfiguration::validate_identifier(
            &self.workload_client_id,
            "resource.workload_client_id",
        )?;
        IdentityConfiguration::validate_identifier(
            &self.workload_required_scope,
            "resource.workload_required_scope",
        )?;
        IdentityConfiguration::validate_identifier(
            &self.access_token_type,
            "resource.access_token_type",
        )?;
        if self
            .workload_required_scope
            .chars()
            .any(char::is_whitespace)
        {
            return Err(ConfigurationError::Invalid(
                "resource.workload_required_scope",
            ));
        }
        if self.human_client_id == self.workload_client_id {
            return Err(ConfigurationError::Invalid("resource.client_ids"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
/// HttpOnly browser-session cookie and lifetime policy.
pub struct SessionCookieConfiguration {
    mode: DeploymentMode,
    name: String,
    inactivity_seconds: i64,
    absolute_lifetime_seconds: u64,
}

impl SessionCookieConfiguration {
    /// Creates an HTTPS-only production cookie with the `__Host-Http-` prefix.
    pub fn production(
        name_suffix: impl AsRef<str>,
        inactivity_seconds: i64,
        absolute_lifetime_seconds: u64,
    ) -> Result<Self, ConfigurationError> {
        Self::create(
            DeploymentMode::Production,
            format!("{PRODUCTION_COOKIE_PREFIX}{}", name_suffix.as_ref()),
            inactivity_seconds,
            absolute_lifetime_seconds,
        )
    }

    /// Creates an explicitly insecure cookie accepted only on loopback HTTP origins.
    pub fn loopback_development(
        name: impl Into<String>,
        inactivity_seconds: i64,
        absolute_lifetime_seconds: u64,
    ) -> Result<Self, ConfigurationError> {
        Self::create(
            DeploymentMode::LoopbackDevelopment,
            name.into(),
            inactivity_seconds,
            absolute_lifetime_seconds,
        )
    }

    fn create(
        mode: DeploymentMode,
        name: String,
        inactivity_seconds: i64,
        absolute_lifetime_seconds: u64,
    ) -> Result<Self, ConfigurationError> {
        let configuration = Self {
            mode,
            name,
            inactivity_seconds,
            absolute_lifetime_seconds,
        };
        configuration.validate()?;
        Ok(configuration)
    }

    /// Returns the selected deployment mode.
    pub fn mode(&self) -> DeploymentMode {
        self.mode
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn secure(&self) -> bool {
        self.mode == DeploymentMode::Production
    }

    pub(crate) fn inactivity_seconds(&self) -> i64 {
        self.inactivity_seconds
    }

    pub(crate) fn absolute_lifetime_seconds(&self) -> u64 {
        self.absolute_lifetime_seconds
    }

    fn validate(&self) -> Result<(), ConfigurationError> {
        if self.name.is_empty()
            || self.name.len() > 96
            || !self
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || (self.mode == DeploymentMode::Production
                && !self.name.starts_with(PRODUCTION_COOKIE_PREFIX))
        {
            return Err(ConfigurationError::Invalid("session.cookie_name"));
        }
        if !(300..=7_200).contains(&self.inactivity_seconds)
            || !(300..=86_400).contains(&self.absolute_lifetime_seconds)
            || self.inactivity_seconds as u64 > self.absolute_lifetime_seconds
        {
            return Err(ConfigurationError::Invalid("session.lifetime"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
/// Validated relying-party, resource-server, browser, and session configuration.
pub struct IdentityConfiguration {
    provider: ProviderConfiguration,
    browser: BrowserApplicationConfiguration,
    resource_server: ResourceServerConfiguration,
    cookie: SessionCookieConfiguration,
}

impl IdentityConfiguration {
    /// Combines validated sections and enforces deployment-wide transport invariants.
    pub fn new(
        provider: ProviderConfiguration,
        browser: BrowserApplicationConfiguration,
        resource_server: ResourceServerConfiguration,
        cookie: SessionCookieConfiguration,
    ) -> Result<Self, ConfigurationError> {
        let configuration = Self {
            provider,
            browser,
            resource_server,
            cookie,
        };
        configuration.validate()?;
        Ok(configuration)
    }

    /// Returns the server-session cookie configuration needed by the host application.
    pub fn cookie(&self) -> &SessionCookieConfiguration {
        &self.cookie
    }

    pub(crate) fn provider(&self) -> &ProviderConfiguration {
        &self.provider
    }

    pub(crate) fn browser(&self) -> &BrowserApplicationConfiguration {
        &self.browser
    }

    pub(crate) fn resource_server(&self) -> &ResourceServerConfiguration {
        &self.resource_server
    }

    /// Revalidates all configuration invariants.
    pub fn validate(&self) -> Result<(), ConfigurationError> {
        self.provider.validate_identifiers()?;
        self.browser.validate_origins()?;
        self.resource_server.validate()?;
        self.cookie.validate()?;
        if self.resource_server.human_client_id() != self.provider.client_id() {
            return Err(ConfigurationError::Invalid("resource.human_client_id"));
        }
        for (url, field) in [
            (self.provider.issuer(), "provider.issuer"),
            (self.provider.account_url(), "provider.account_url"),
            (self.browser.origin(), "browser.origin"),
            (self.browser.redirect_uri(), "browser.redirect_uri"),
            (
                self.browser.post_logout_redirect_uri(),
                "browser.post_logout_redirect_uri",
            ),
        ] {
            Self::validate_url(url, field, self.cookie.mode)?;
        }
        if let Some(backchannel_base_url) = self.provider.backchannel_base_url() {
            Self::validate_backchannel_url(
                backchannel_base_url,
                self.provider.issuer(),
                self.cookie.mode,
            )?;
        }
        Ok(())
    }

    pub(crate) fn validate_provider_endpoint(&self, url: &Url) -> Result<(), ConfigurationError> {
        Self::validate_url(url, "provider.discovery_endpoint", self.cookie.mode)?;
        if url.origin() != self.provider.issuer().origin() {
            return Err(ConfigurationError::Invalid(
                "provider.discovery_endpoint_origin",
            ));
        }
        Ok(())
    }

    pub(crate) fn provider_transport_endpoint(
        &self,
        public_endpoint: &Url,
    ) -> Result<Url, ConfigurationError> {
        self.validate_provider_endpoint(public_endpoint)?;
        let Some(backchannel_base_url) = self.provider.backchannel_base_url() else {
            return Ok(public_endpoint.clone());
        };
        let mut transport_endpoint = public_endpoint.clone();
        transport_endpoint
            .set_scheme(backchannel_base_url.scheme())
            .map_err(|()| ConfigurationError::Invalid("provider.backchannel_base_url"))?;
        transport_endpoint
            .set_host(backchannel_base_url.host_str())
            .map_err(|_| ConfigurationError::Invalid("provider.backchannel_base_url"))?;
        transport_endpoint
            .set_port(backchannel_base_url.port())
            .map_err(|()| ConfigurationError::Invalid("provider.backchannel_base_url"))?;
        Ok(transport_endpoint)
    }

    fn validate_identifier(value: &str, field: &'static str) -> Result<(), ConfigurationError> {
        if value.is_empty()
            || value.len() > 255
            || value.chars().any(char::is_control)
            || value.trim() != value
        {
            return Err(ConfigurationError::Invalid(field));
        }
        Ok(())
    }

    fn validate_url(
        url: &Url,
        field: &'static str,
        mode: DeploymentMode,
    ) -> Result<(), ConfigurationError> {
        let transport_is_valid = match mode {
            DeploymentMode::Production => url.scheme() == "https",
            DeploymentMode::LoopbackDevelopment => {
                url.scheme() == "http"
                    && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
            }
        };
        if !transport_is_valid
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(ConfigurationError::Invalid(field));
        }
        Ok(())
    }

    fn validate_backchannel_url(
        url: &Url,
        issuer: &Url,
        mode: DeploymentMode,
    ) -> Result<(), ConfigurationError> {
        let transport_is_valid = match mode {
            DeploymentMode::Production => url.scheme() == "https",
            DeploymentMode::LoopbackDevelopment => matches!(url.scheme(), "http" | "https"),
        };
        if !transport_is_valid
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != issuer.path()
        {
            return Err(ConfigurationError::Invalid("provider.backchannel_base_url"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, thiserror::Error)]
/// Invalid identity configuration supplied before provider discovery.
pub enum ConfigurationError {
    /// A named configuration field violates a construction invariant.
    #[error("identity configuration field `{0}` is invalid")]
    Invalid(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ConfigurationFixture;

    impl ConfigurationFixture {
        fn production() -> IdentityConfiguration {
            IdentityConfiguration::new(
                ProviderConfiguration::new(
                    "https://identity.example.com".parse().unwrap(),
                    "browser-client",
                    ClientSecretCredential::new("a".repeat(32)).unwrap(),
                    "https://identity.example.com/account".parse().unwrap(),
                )
                .unwrap(),
                BrowserApplicationConfiguration::new(
                    "https://app.example.com".parse().unwrap(),
                    "https://app.example.com/auth/callback".parse().unwrap(),
                    "https://app.example.com/".parse().unwrap(),
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
                SessionCookieConfiguration::production("application", 3_600, 7_200).unwrap(),
            )
            .unwrap()
        }
    }

    #[test]
    fn production_configuration_is_confidential_and_https_only() {
        let configuration = ConfigurationFixture::production();
        assert_eq!(configuration.cookie().mode(), DeploymentMode::Production);
        assert!(
            configuration
                .cookie()
                .name()
                .starts_with(PRODUCTION_COOKIE_PREFIX)
        );
        assert_eq!(
            format!("{:?}", configuration.provider.client_secret),
            "ClientSecretCredential([REDACTED])"
        );

        let result = BrowserApplicationConfiguration::new(
            "http://localhost:4200".parse().unwrap(),
            "http://localhost:4200/auth/callback".parse().unwrap(),
            "http://localhost:4200/".parse().unwrap(),
        )
        .and_then(|browser| {
            IdentityConfiguration::new(
                configuration.provider.clone(),
                browser,
                configuration.resource_server.clone(),
                configuration.cookie.clone(),
            )
        });
        assert!(matches!(
            result,
            Err(ConfigurationError::Invalid("browser.origin"))
        ));
    }

    #[test]
    fn loopback_mode_rejects_non_loopback_plain_http() {
        let cookie = SessionCookieConfiguration::loopback_development("test", 600, 1_200).unwrap();
        let browser = BrowserApplicationConfiguration::new(
            "http://app.internal".parse().unwrap(),
            "http://app.internal/auth/callback".parse().unwrap(),
            "http://app.internal/".parse().unwrap(),
        )
        .unwrap();
        let result = IdentityConfiguration::new(
            ConfigurationFixture::production().provider.clone(),
            browser,
            ConfigurationFixture::production().resource_server.clone(),
            cookie,
        );
        assert!(result.is_err());
    }

    #[test]
    fn issuer_and_callback_have_canonical_shapes() {
        let secret = ClientSecretCredential::new("a".repeat(32)).unwrap();
        assert!(matches!(
            ProviderConfiguration::new(
                "https://identity.example.com?tenant=one".parse().unwrap(),
                "browser-client",
                secret,
                "https://identity.example.com/account".parse().unwrap(),
            ),
            Err(ConfigurationError::Invalid("provider.issuer"))
        ));
        assert!(matches!(
            BrowserApplicationConfiguration::new(
                "https://app.example.com".parse().unwrap(),
                "https://app.example.com/another-callback".parse().unwrap(),
                "https://app.example.com/".parse().unwrap(),
            ),
            Err(ConfigurationError::Invalid("browser.redirect_uri"))
        ));
    }

    #[test]
    fn loopback_development_accepts_an_explicit_internal_backchannel() {
        let configuration = IdentityConfiguration::new(
            ProviderConfiguration::new(
                "http://localhost:18090/auth/v1/".parse().unwrap(),
                "browser-client",
                ClientSecretCredential::new("a".repeat(32)).unwrap(),
                "http://localhost:18090/auth/v1/account".parse().unwrap(),
            )
            .unwrap()
            .with_backchannel_base_url("http://identity-authority:18090/auth/v1/".parse().unwrap())
            .unwrap(),
            BrowserApplicationConfiguration::new(
                "http://localhost:3000/".parse().unwrap(),
                "http://localhost:3000/auth/callback".parse().unwrap(),
                "http://localhost:3000/".parse().unwrap(),
            )
            .unwrap(),
            ResourceServerConfiguration::new(
                "application-api",
                "browser-client",
                "automation-client",
                "application_mcp",
                "JWT",
            )
            .unwrap(),
            SessionCookieConfiguration::loopback_development("backchannel", 600, 1_200).unwrap(),
        )
        .unwrap();
        let public_endpoint: Url = "http://localhost:18090/auth/v1/oidc/token".parse().unwrap();
        assert_eq!(
            configuration
                .provider_transport_endpoint(&public_endpoint)
                .unwrap()
                .as_str(),
            "http://identity-authority:18090/auth/v1/oidc/token"
        );
    }

    #[test]
    fn backchannel_must_match_the_issuer_path_and_production_transport() {
        let fixture = ConfigurationFixture::production();
        let wrong_path = IdentityConfiguration::new(
            fixture
                .provider
                .clone()
                .with_backchannel_base_url("https://identity.internal/another/".parse().unwrap())
                .unwrap(),
            fixture.browser.clone(),
            fixture.resource_server.clone(),
            fixture.cookie.clone(),
        );
        assert!(matches!(
            wrong_path,
            Err(ConfigurationError::Invalid("provider.backchannel_base_url"))
        ));
        let insecure_transport = IdentityConfiguration::new(
            fixture
                .provider
                .with_backchannel_base_url("http://identity.internal/".parse().unwrap())
                .unwrap(),
            fixture.browser,
            fixture.resource_server,
            fixture.cookie,
        );
        assert!(matches!(
            insecure_transport,
            Err(ConfigurationError::Invalid("provider.backchannel_base_url"))
        ));
    }
}
