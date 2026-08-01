#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod access_token;
mod application;
mod configuration;
mod error;
mod http;
mod provider_http;
mod session;
mod session_encryption;

pub use application::{
    AuthenticatedUser, AuthenticationMethod, AuthenticationPrincipalKind, IdentityApplication,
};
pub use configuration::{
    BrowserApplicationConfiguration, ClientSecretCredential, ConfigurationError, DeploymentMode,
    IdentityConfiguration, ProviderConfiguration, ResourceServerConfiguration,
    SessionCookieConfiguration,
};
pub use error::IdentityError;
pub use http::{IdentityAuthentication, IdentityHttpApplication};
pub use session::IdentitySessionLayer;
pub use session_encryption::{
    EncryptedSessionStore, SessionEncryptionConfigurationError, SessionEncryptionKey,
    SessionEncryptionKeyring,
};
