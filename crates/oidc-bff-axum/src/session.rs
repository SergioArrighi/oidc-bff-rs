use oidc_bff_core::UserProfile;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::Duration;
use tower_sessions::{
    Expiry, MemoryStore, Session, SessionManagerLayer, SessionStore, cookie::SameSite,
};

use crate::{IdentityError, SessionCookieConfiguration};

const PENDING_LOGIN_KEY: &str = "identity.pending_login";
const AUTHENTICATED_SESSION_KEY: &str = "identity.authenticated";

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct PendingLogin {
    pub state: String,
    pub nonce: String,
    pub pkce_verifier: String,
    pub return_to: String,
    pub created_at_epoch_seconds: u64,
}

impl std::fmt::Debug for PendingLogin {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingLogin")
            .field("state", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .field("pkce_verifier", &"[REDACTED]")
            .field("return_to", &self.return_to)
            .field("created_at_epoch_seconds", &self.created_at_epoch_seconds)
            .finish()
    }
}

impl PendingLogin {
    pub fn matches_state(&self, candidate: &str) -> bool {
        let candidate_hash = Sha256::digest(candidate.as_bytes());
        let stored_hash = Sha256::digest(self.state.as_bytes());
        bool::from(candidate_hash.ct_eq(&stored_hash))
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct AuthenticatedIdentitySession {
    pub profile: UserProfile,
    pub authentication_session_id: String,
    pub anti_forgery_token: String,
    pub expires_at_epoch_seconds: u64,
}

impl std::fmt::Debug for AuthenticatedIdentitySession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedIdentitySession")
            .field("profile", &self.profile)
            .field("authentication_session_id", &self.authentication_session_id)
            .field("anti_forgery_token", &"[REDACTED]")
            .field("expires_at_epoch_seconds", &self.expires_at_epoch_seconds)
            .finish()
    }
}

impl AuthenticatedIdentitySession {
    pub fn matches_anti_forgery_token(&self, candidate: &str) -> bool {
        let candidate_hash = Sha256::digest(candidate.as_bytes());
        let stored_hash = Sha256::digest(self.anti_forgery_token.as_bytes());
        bool::from(candidate_hash.ct_eq(&stored_hash))
    }
}

pub(crate) struct IdentitySessionState<'session> {
    session: &'session Session,
}

impl<'session> IdentitySessionState<'session> {
    pub fn new(session: &'session Session) -> Self {
        Self { session }
    }

    pub async fn pending(&self) -> Result<Option<PendingLogin>, IdentityError> {
        self.session
            .get(PENDING_LOGIN_KEY)
            .await
            .map_err(|_| IdentityError::Session)
    }

    pub async fn set_pending(&self, pending: PendingLogin) -> Result<(), IdentityError> {
        self.session
            .insert(PENDING_LOGIN_KEY, pending)
            .await
            .map_err(|_| IdentityError::Session)
    }

    pub async fn clear_pending(&self) -> Result<(), IdentityError> {
        self.session
            .remove::<PendingLogin>(PENDING_LOGIN_KEY)
            .await
            .map(|_| ())
            .map_err(|_| IdentityError::Session)
    }

    pub async fn authenticated(
        &self,
    ) -> Result<Option<AuthenticatedIdentitySession>, IdentityError> {
        self.session
            .get(AUTHENTICATED_SESSION_KEY)
            .await
            .map_err(|_| IdentityError::Session)
    }

    pub async fn establish(
        &self,
        authenticated: AuthenticatedIdentitySession,
    ) -> Result<(), IdentityError> {
        self.session
            .cycle_id()
            .await
            .map_err(|_| IdentityError::Session)?;
        self.session
            .insert(AUTHENTICATED_SESSION_KEY, authenticated)
            .await
            .map_err(|_| IdentityError::Session)?;
        self.clear_pending().await
    }

    pub async fn revoke(&self) -> Result<(), IdentityError> {
        self.session
            .flush()
            .await
            .map_err(|_| IdentityError::Session)
    }
}

/// Builder for secure `tower-sessions` browser session layers.
#[derive(Clone, Debug)]
pub struct IdentitySessionLayer {
    configuration: SessionCookieConfiguration,
}

impl IdentitySessionLayer {
    /// Creates a session-layer factory from an already validated cookie policy.
    pub fn new(configuration: &SessionCookieConfiguration) -> Self {
        Self {
            configuration: configuration.clone(),
        }
    }

    /// Builds a session layer over a caller-provided persistent store.
    pub fn store<S>(&self, store: S) -> SessionManagerLayer<S>
    where
        S: SessionStore + Clone,
    {
        SessionManagerLayer::new(store)
            .with_name(self.configuration.name().to_owned())
            .with_path("/")
            .with_http_only(true)
            .with_same_site(SameSite::Lax)
            .with_secure(self.configuration.secure())
            .with_expiry(Expiry::OnInactivity(Duration::seconds(
                self.configuration.inactivity_seconds(),
            )))
    }

    /// Builds an in-memory session layer for tests and local development.
    pub fn memory(&self) -> SessionManagerLayer<MemoryStore> {
        self.store(MemoryStore::default())
    }
}
