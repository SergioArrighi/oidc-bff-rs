//! Fresh, read-only browser-login observations for long-running native operations.
//! This is not a provider revocation feed, session-renewal service or corpus lease.
use super::{AUTHENTICATED_SESSION_KEY, AuthenticatedIdentitySession};
use crate::{AuthenticatedUser, AuthenticationMethod, AuthenticationPrincipalKind};
use oidc_bff_core::UserSubject;
use std::{
    fmt, io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tower_sessions::{Session, SessionStore, session::Id};
use zeroize::Zeroizing;

const MAXIMUM_STATE_BYTES: usize = 1024 * 1024;

/// Bounds a single authoritative store read; never a model-generation deadline.
#[derive(Clone, Copy, Debug)]
pub struct LiveBrowserLoginLimits {
    pub read_timeout: Duration,
}

impl Default for LiveBrowserLoginLimits {
    fn default() -> Self {
        Self {
            read_timeout: Duration::from_secs(5),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LiveBrowserLoginError {
    #[error("a persisted authenticated browser-human session is required")]
    BrowserSessionRequired,
    #[error("live browser-login read limits are invalid")]
    InvalidLimits,
    #[error("the original browser login is no longer current")]
    NotCurrent,
    #[error("live browser-login storage is unavailable")]
    Unavailable,
    #[error("live browser-login read deadline elapsed")]
    Deadline,
    #[error("stored browser-login state is invalid")]
    InvalidState,
}

/// Opaque binding to the original store ID, subject and authentication-session ID.
/// The caller supplies its authoritative decrypting store and authenticated request.
/// `SessionStore` alone does not guarantee freshness: independently stale caches
/// or read replicas are not suitable. Its `load` must not renew session lifetime.
/// A failed check permanently invalidates this handle and all its clones. A new
/// request may establish a new handle; this object never switches logins or renews.
#[derive(Clone)]
pub struct LiveBrowserLogin {
    inner: Arc<LiveLoginBinding>,
}

struct LiveLoginBinding {
    store: Arc<dyn SessionStore>,
    anchor: LoginAnchor,
    absolute_deadline_epoch_ms: u64,
    limits: LiveBrowserLoginLimits,
    invalidated: AtomicBool,
}

struct LoginAnchor {
    session_id: Id,
    subject: UserSubject,
    authentication_session_id: Zeroizing<String>,
}

/// A sampled observation, not a transferable or renewable authentication lease.
/// Recheck the handle and application policy before later use/delivery.
pub struct CurrentBrowserLogin {
    user: AuthenticatedUser,
    checked_at_epoch_ms: u64,
    valid_until_epoch_ms: u64,
    absolute_deadline_epoch_ms: u64,
}

impl CurrentBrowserLogin {
    pub fn user(&self) -> &AuthenticatedUser {
        &self.user
    }
    pub fn checked_at_epoch_ms(&self) -> u64 {
        self.checked_at_epoch_ms
    }
    /// Earlier of persisted inactivity expiry and the pinned absolute deadline.
    pub fn valid_until_epoch_ms(&self) -> u64 {
        self.valid_until_epoch_ms
    }

    fn now_epoch_ms() -> Result<u64, LiveBrowserLoginError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| LiveBrowserLoginError::Unavailable)?
            .as_millis()
            .try_into()
            .map_err(|_| LiveBrowserLoginError::Unavailable)
    }
}

impl fmt::Debug for LiveBrowserLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LiveBrowserLogin { [REDACTED] }")
    }
}
impl fmt::Debug for CurrentBrowserLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CurrentBrowserLogin { [REDACTED] }")
    }
}

impl LiveBrowserLogin {
    /// Mint only after request authentication. Cached/unsaved Session data is not
    /// proof: the persisted record is loaded directly before the handle is returned.
    pub async fn bind(
        session: &Session,
        authenticated: &AuthenticatedUser,
        store: Arc<dyn SessionStore>,
        limits: LiveBrowserLoginLimits,
    ) -> Result<Self, LiveBrowserLoginError> {
        if !(Duration::from_millis(10)..=Duration::from_secs(30)).contains(&limits.read_timeout) {
            return Err(LiveBrowserLoginError::InvalidLimits);
        }
        if authenticated.kind != AuthenticationPrincipalKind::Human
            || authenticated.method != AuthenticationMethod::BrowserSession
            || authenticated.authentication_session_id.is_empty()
            || authenticated.authentication_session_id.len() > 512
            || authenticated
                .authentication_session_id
                .chars()
                .any(char::is_control)
        {
            return Err(LiveBrowserLoginError::BrowserSessionRequired);
        }
        let anchor = LoginAnchor {
            session_id: session
                .id()
                .ok_or(LiveBrowserLoginError::BrowserSessionRequired)?,
            subject: authenticated.profile.subject.clone(),
            authentication_session_id: Zeroizing::new(
                authenticated.authentication_session_id.clone(),
            ),
        };
        let current = StoredLoginRead::load(store.as_ref(), &anchor, limits, None).await?;
        Ok(Self {
            inner: Arc::new(LiveLoginBinding {
                store,
                anchor,
                absolute_deadline_epoch_ms: current.absolute_deadline_epoch_ms,
                limits,
                invalidated: AtomicBool::new(false),
            }),
        })
    }

    /// Fresh store read: no cached Session::get, load/save, flush, renewal or logout.
    /// Local deletion/expiry is detected when sampled, not atomically with delivery.
    /// Cancelling this future produces no observation and does not invalidate the
    /// handle. Withhold delivery until a subsequent check succeeds.
    pub async fn current(&self) -> Result<CurrentBrowserLogin, LiveBrowserLoginError> {
        if self.inner.invalidated.load(Ordering::Acquire) {
            return Err(LiveBrowserLoginError::NotCurrent);
        }
        let current = StoredLoginRead::load(
            self.inner.store.as_ref(),
            &self.inner.anchor,
            self.inner.limits,
            Some(self.inner.absolute_deadline_epoch_ms),
        )
        .await
        .inspect_err(|_| self.inner.invalidated.store(true, Ordering::Release))?;
        // A concurrent failing observation invalidates all clones, including a
        // successful read that was already in flight. This is still a sampled fence.
        if self.inner.invalidated.load(Ordering::Acquire) {
            return Err(LiveBrowserLoginError::NotCurrent);
        }
        Ok(current)
    }
}

struct StoredLoginRead;
impl StoredLoginRead {
    async fn load(
        store: &dyn SessionStore,
        anchor: &LoginAnchor,
        limits: LiveBrowserLoginLimits,
        pinned_absolute: Option<u64>,
    ) -> Result<CurrentBrowserLogin, LiveBrowserLoginError> {
        let deadline = tokio::time::Instant::now() + limits.read_timeout;
        let mut record = tokio::time::timeout_at(deadline, store.load(&anchor.session_id))
            .await
            .map_err(|_| LiveBrowserLoginError::Deadline)?
            .map_err(|_| LiveBrowserLoginError::Unavailable)?
            .ok_or(LiveBrowserLoginError::NotCurrent)?;
        let inactivity_deadline: u64 = (record.expiry_date.unix_timestamp_nanos() / 1_000_000)
            .try_into()
            .map_err(|_| LiveBrowserLoginError::NotCurrent)?;
        if record.id != anchor.session_id
            || inactivity_deadline <= CurrentBrowserLogin::now_epoch_ms()?
        {
            return Err(LiveBrowserLoginError::NotCurrent);
        }
        // The configured store owns allocation/decoding before returning Record.
        // Bound subsequent processing without allocating another serialized copy.
        serde_json::to_writer(
            &mut LoginStateSize {
                remaining: MAXIMUM_STATE_BYTES,
            },
            &record.data,
        )
        .map_err(|_| LiveBrowserLoginError::InvalidState)?;
        let authenticated: AuthenticatedIdentitySession = serde_json::from_value(
            record
                .data
                .remove(AUTHENTICATED_SESSION_KEY)
                .ok_or(LiveBrowserLoginError::NotCurrent)?,
        )
        .map_err(|_| LiveBrowserLoginError::InvalidState)?;
        if authenticated.profile.subject != anchor.subject
            || authenticated.authentication_session_id != *anchor.authentication_session_id
        {
            return Err(LiveBrowserLoginError::NotCurrent);
        }
        let absolute = authenticated
            .expires_at_epoch_seconds
            .checked_mul(1000)
            .ok_or(LiveBrowserLoginError::InvalidState)?;
        let absolute = pinned_absolute.map_or(absolute, |pinned| pinned.min(absolute));
        let valid_until = inactivity_deadline.min(absolute);
        let now = CurrentBrowserLogin::now_epoch_ms()?;
        if valid_until <= now {
            return Err(LiveBrowserLoginError::NotCurrent);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(LiveBrowserLoginError::Deadline);
        }
        Ok(CurrentBrowserLogin {
            user: AuthenticatedUser {
                profile: authenticated.profile,
                authentication_session_id: authenticated.authentication_session_id,
                kind: AuthenticationPrincipalKind::Human,
                method: AuthenticationMethod::BrowserSession,
            },
            checked_at_epoch_ms: now,
            valid_until_epoch_ms: valid_until,
            absolute_deadline_epoch_ms: absolute,
        })
    }
}

struct LoginStateSize {
    remaining: usize,
}
impl io::Write for LoginStateSize {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.remaining = self
            .remaining
            .checked_sub(bytes.len())
            .ok_or_else(|| io::Error::other("browser-login state allowance"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
