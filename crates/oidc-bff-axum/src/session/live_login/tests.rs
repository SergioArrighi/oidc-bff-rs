use super::*;
use async_trait::async_trait;
use oidc_bff_core::{EmailAddress, UserProfile};
use std::sync::{Mutex, atomic::AtomicUsize};
use time::OffsetDateTime;
use tokio::sync::Notify;
use tower_sessions::{
    session::Record,
    session_store::{Error as StoreError, Result as StoreResult},
};

const NORMAL: usize = 0;
const ERROR: usize = 1;
const PENDING: usize = 2;
const HOLD_SNAPSHOT: usize = 3;

/// Deliberately does not filter expiry or record IDs: the reader must check both.
#[derive(Debug)]
struct ControlledStore {
    record: Mutex<Option<Record>>,
    mode: AtomicUsize,
    loads: AtomicUsize,
    lookup_ids: Mutex<Vec<Id>>,
    writes: AtomicUsize,
    entered: Notify,
    release: Notify,
}

#[async_trait]
impl SessionStore for ControlledStore {
    async fn create(&self, record: &mut Record) -> StoreResult<()> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        *self.record.lock().unwrap() = Some(record.clone());
        Ok(())
    }

    async fn save(&self, record: &Record) -> StoreResult<()> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        *self.record.lock().unwrap() = Some(record.clone());
        Ok(())
    }

    async fn load(&self, id: &Id) -> StoreResult<Option<Record>> {
        self.loads.fetch_add(1, Ordering::SeqCst);
        self.lookup_ids.lock().unwrap().push(*id);
        match self.mode.load(Ordering::SeqCst) {
            ERROR => Err(StoreError::Decode("PRIVATE_STORE_FAILURE".to_owned())),
            PENDING => std::future::pending().await,
            HOLD_SNAPSHOT => {
                let snapshot = self.record.lock().unwrap().clone();
                self.entered.notify_one();
                self.release.notified().await;
                Ok(snapshot)
            }
            _ => Ok(self.record.lock().unwrap().clone()),
        }
    }

    async fn delete(&self, _id: &Id) -> StoreResult<()> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        *self.record.lock().unwrap() = None;
        Ok(())
    }
}

struct Fixture {
    store: Arc<ControlledStore>,
    session: Session,
    user: AuthenticatedUser,
    absolute_seconds: u64,
}

impl Fixture {
    fn new() -> Self {
        let absolute_seconds = CurrentBrowserLogin::now_epoch_ms().unwrap() / 1000 + 3600;
        let profile = UserProfile {
            subject: UserSubject::parse("PRIVATE_SUBJECT").unwrap(),
            email: Some(EmailAddress::parse("private@example.com").unwrap()),
            email_verified: true,
            preferred_username: None,
            given_name: None,
            family_name: None,
            display_name: "PRIVATE_NAME".to_owned(),
            roles: vec!["reader".to_owned()],
            groups: vec!["PRIVATE_GROUP".to_owned()],
        };
        let user = AuthenticatedUser {
            profile: profile.clone(),
            authentication_session_id: "PRIVATE_LOGIN".to_owned(),
            kind: AuthenticationPrincipalKind::Human,
            method: AuthenticationMethod::BrowserSession,
        };
        let authenticated = AuthenticatedIdentitySession {
            profile,
            authentication_session_id: user.authentication_session_id.clone(),
            anti_forgery_token: "PRIVATE_CSRF".to_owned(),
            expires_at_epoch_seconds: absolute_seconds,
        };
        let id = Id::default();
        let record = Record {
            id,
            data: [(
                AUTHENTICATED_SESSION_KEY.to_owned(),
                serde_json::to_value(authenticated).unwrap(),
            )]
            .into_iter()
            .collect(),
            expiry_date: OffsetDateTime::now_utc() + time::Duration::hours(2),
        };
        let store = Arc::new(ControlledStore {
            record: Mutex::new(Some(record)),
            mode: AtomicUsize::new(NORMAL),
            loads: AtomicUsize::new(0),
            lookup_ids: Mutex::new(Vec::new()),
            writes: AtomicUsize::new(0),
            entered: Notify::new(),
            release: Notify::new(),
        });
        let session = Session::new(Some(id), store.clone(), None);
        Self {
            store,
            session,
            user,
            absolute_seconds,
        }
    }

    async fn bind(&self) -> LiveBrowserLogin {
        LiveBrowserLogin::bind(
            &self.session,
            &self.user,
            self.store.clone(),
            Default::default(),
        )
        .await
        .unwrap()
    }

    fn change(&self, change: impl FnOnce(&mut Record)) {
        change(self.store.record.lock().unwrap().as_mut().unwrap());
    }

    fn no_writes(&self) {
        assert_eq!(self.store.writes.load(Ordering::SeqCst), 0);
        assert!(
            self.store
                .lookup_ids
                .lock()
                .unwrap()
                .iter()
                .all(|id| Some(*id) == self.session.id())
        );
    }
}

#[tokio::test]
async fn fresh_read_detects_logout_while_original_session_remains_cached() {
    let fixture = Fixture::new();
    let cached: AuthenticatedIdentitySession = fixture
        .session
        .get(AUTHENTICATED_SESSION_KEY)
        .await
        .unwrap()
        .unwrap();
    let login = fixture.bind().await;
    let separate_request = Session::new(fixture.session.id(), fixture.store.clone(), None);
    separate_request.flush().await.unwrap();
    let loads_after_logout = fixture.store.loads.load(Ordering::SeqCst);
    let still_cached: AuthenticatedIdentitySession = fixture
        .session
        .get(AUTHENTICATED_SESSION_KEY)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        still_cached.authentication_session_id,
        cached.authentication_session_id
    );
    assert_eq!(
        fixture.store.loads.load(Ordering::SeqCst),
        loads_after_logout
    );
    assert_eq!(
        login.current().await.unwrap_err(),
        LiveBrowserLoginError::NotCurrent
    );
    assert_eq!(
        fixture.store.loads.load(Ordering::SeqCst),
        loads_after_logout + 1
    );
    // Only the explicit logout above wrote; neither binding nor monitoring did.
    assert_eq!(fixture.store.writes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn same_login_refreshes_roles_without_renewing_or_writing() {
    let fixture = Fixture::new();
    let login = fixture.bind().await;
    fixture.change(|record| {
        record.data.get_mut(AUTHENTICATED_SESSION_KEY).unwrap()["profile"]["roles"] =
            serde_json::json!(["editor"]);
    });
    let current = login.current().await.unwrap();
    assert_eq!(current.user().profile.roles, vec!["editor"]);
    assert_eq!(
        current.user().authentication_session_id,
        fixture.user.authentication_session_id
    );
    assert_eq!(current.user().method, AuthenticationMethod::BrowserSession);
    assert_eq!(current.user().kind, AuthenticationPrincipalKind::Human);
    assert!(current.checked_at_epoch_ms() < current.valid_until_epoch_ms());
    assert_eq!(
        current.valid_until_epoch_ms(),
        fixture.absolute_seconds * 1000
    );
    assert_eq!(fixture.user.profile.roles, vec!["reader"]);
    fixture.no_writes();
}

#[tokio::test]
async fn changed_subject_login_record_id_or_missing_identity_never_rebinds() {
    for case in 0..4 {
        let fixture = Fixture::new();
        let login = fixture.bind().await;
        fixture.change(|record| match case {
            0 => record.data.get_mut(AUTHENTICATED_SESSION_KEY).unwrap()["profile"]["subject"] =
                serde_json::json!("another-subject"),
            1 => record.data.get_mut(AUTHENTICATED_SESSION_KEY).unwrap()["authentication_session_id"] =
                serde_json::json!("another-login"),
            2 => record.id = Id::default(),
            _ => { record.data.remove(AUTHENTICATED_SESSION_KEY); }
        });
        assert_eq!(
            login.current().await.unwrap_err(),
            LiveBrowserLoginError::NotCurrent,
            "case {case}"
        );
        fixture.no_writes();
    }
}

#[tokio::test]
async fn checks_absolute_and_inactivity_expiry_and_rejects_overflow() {
    for case in 0..3 {
        let fixture = Fixture::new();
        let login = fixture.bind().await;
        fixture.change(|record| match case {
            0 => record.data.get_mut(AUTHENTICATED_SESSION_KEY).unwrap()["expires_at_epoch_seconds"] =
                serde_json::json!(1),
            1 => record.expiry_date = OffsetDateTime::UNIX_EPOCH,
            _ => record.data.get_mut(AUTHENTICATED_SESSION_KEY).unwrap()["expires_at_epoch_seconds"] =
                serde_json::json!(u64::MAX),
        });
        let expected = if case == 2 {
            LiveBrowserLoginError::InvalidState
        } else {
            LiveBrowserLoginError::NotCurrent
        };
        assert_eq!(login.current().await.unwrap_err(), expected, "case {case}");
        fixture.no_writes();
    }
}

#[tokio::test]
async fn initial_absolute_ceiling_is_pinned_and_current_shorter_deadlines_apply() {
    let fixture = Fixture::new();
    let login = fixture.bind().await;
    fixture.change(|record| {
        record.data.get_mut(AUTHENTICATED_SESSION_KEY).unwrap()["expires_at_epoch_seconds"] =
            serde_json::json!(fixture.absolute_seconds + 3600);
    });
    assert_eq!(
        login.current().await.unwrap().valid_until_epoch_ms(),
        fixture.absolute_seconds * 1000
    );
    let shorter = fixture.absolute_seconds - 600;
    fixture.change(|record| {
        record.data.get_mut(AUTHENTICATED_SESSION_KEY).unwrap()["expires_at_epoch_seconds"] =
            serde_json::json!(shorter);
    });
    assert_eq!(
        login.current().await.unwrap().valid_until_epoch_ms(),
        shorter * 1000
    );
    let inactivity = OffsetDateTime::from_unix_timestamp((shorter - 600) as i64).unwrap();
    fixture.change(|record| record.expiry_date = inactivity);
    assert_eq!(
        login.current().await.unwrap().valid_until_epoch_ms(),
        (shorter - 600) * 1000
    );
    fixture.no_writes();
}

#[tokio::test]
async fn binding_requires_persisted_browser_human_and_valid_limits() {
    let fixture = Fixture::new();
    for case in 0..5 {
        let mut user = fixture.user.clone();
        match case {
            0 => user.method = AuthenticationMethod::BearerToken,
            1 => user.kind = AuthenticationPrincipalKind::Workload,
            2 => user.authentication_session_id.clear(),
            3 => user.authentication_session_id = "x".repeat(513),
            _ => user.authentication_session_id = "invalid\nlogin".to_owned(),
        }
        assert_eq!(
            LiveBrowserLogin::bind(
                &fixture.session,
                &user,
                fixture.store.clone(),
                Default::default()
            )
            .await
            .unwrap_err(),
            LiveBrowserLoginError::BrowserSessionRequired
        );
    }
    let unsaved = Session::new(None, fixture.store.clone(), None);
    assert_eq!(
        LiveBrowserLogin::bind(
            &unsaved,
            &fixture.user,
            fixture.store.clone(),
            Default::default()
        )
        .await
        .unwrap_err(),
        LiveBrowserLoginError::BrowserSessionRequired
    );
    for read_timeout in [Duration::from_millis(9), Duration::from_secs(31)] {
        assert_eq!(
            LiveBrowserLogin::bind(
                &fixture.session,
                &fixture.user,
                fixture.store.clone(),
                LiveBrowserLoginLimits { read_timeout }
            )
            .await
            .unwrap_err(),
            LiveBrowserLoginError::InvalidLimits
        );
    }
    assert_eq!(fixture.store.loads.load(Ordering::SeqCst), 0);
    fixture.no_writes();
}

#[tokio::test]
async fn binding_does_not_accept_cached_or_unsaved_identity_as_persisted_proof() {
    let fixture = Fixture::new();
    let _: AuthenticatedIdentitySession = fixture
        .session
        .get(AUTHENTICATED_SESSION_KEY)
        .await
        .unwrap()
        .unwrap();
    *fixture.store.record.lock().unwrap() = None;
    assert_eq!(
        LiveBrowserLogin::bind(
            &fixture.session,
            &fixture.user,
            fixture.store.clone(),
            Default::default()
        )
        .await
        .unwrap_err(),
        LiveBrowserLoginError::NotCurrent
    );
    fixture.no_writes();
}

#[tokio::test]
async fn store_failures_deadlines_corrupt_and_oversize_state_are_static_and_read_only() {
    for case in 0..4 {
        let fixture = Fixture::new();
        let login = LiveBrowserLogin::bind(
            &fixture.session,
            &fixture.user,
            fixture.store.clone(),
            LiveBrowserLoginLimits {
                read_timeout: Duration::from_millis(100),
            },
        )
        .await
        .unwrap();
        match case {
            0 => fixture.store.mode.store(ERROR, Ordering::SeqCst),
            1 => fixture.store.mode.store(PENDING, Ordering::SeqCst),
            2 => fixture.change(|record| {
                record.data.insert(
                    AUTHENTICATED_SESSION_KEY.to_owned(),
                    serde_json::json!("PRIVATE_CORRUPT"),
                );
            }),
            _ => fixture.change(|record| {
                record.data.insert(
                    "unrelated".to_owned(),
                    serde_json::json!("z".repeat(MAXIMUM_STATE_BYTES)),
                );
            }),
        }
        let error = login.current().await.unwrap_err();
        let expected = match case {
            0 => LiveBrowserLoginError::Unavailable,
            1 => LiveBrowserLoginError::Deadline,
            _ => LiveBrowserLoginError::InvalidState,
        };
        assert_eq!(error, expected, "case {case}");
        assert!(!format!("{error} {error:?}").contains("PRIVATE"));
        let loads = fixture.store.loads.load(Ordering::SeqCst);
        fixture.store.mode.store(NORMAL, Ordering::SeqCst);
        assert_eq!(
            login.clone().current().await.unwrap_err(),
            LiveBrowserLoginError::NotCurrent
        );
        assert_eq!(fixture.store.loads.load(Ordering::SeqCst), loads);
        fixture.no_writes();
    }
}

#[tokio::test]
async fn concurrent_failed_check_invalidates_an_already_inflight_success_and_all_clones() {
    let fixture = Fixture::new();
    let login = fixture.bind().await;
    let clone = login.clone();
    fixture.store.mode.store(HOLD_SNAPSHOT, Ordering::SeqCst);
    let in_flight = login.current();
    tokio::pin!(in_flight);
    assert!(futures::poll!(in_flight.as_mut()).is_pending());
    fixture.store.entered.notified().await;
    fixture.store.mode.store(ERROR, Ordering::SeqCst);
    assert_eq!(
        clone.current().await.unwrap_err(),
        LiveBrowserLoginError::Unavailable
    );
    fixture.store.mode.store(NORMAL, Ordering::SeqCst);
    fixture.store.release.notify_one();
    assert_eq!(
        in_flight.await.unwrap_err(),
        LiveBrowserLoginError::NotCurrent
    );
    let loads = fixture.store.loads.load(Ordering::SeqCst);
    assert_eq!(
        login.current().await.unwrap_err(),
        LiveBrowserLoginError::NotCurrent
    );
    assert_eq!(
        clone.current().await.unwrap_err(),
        LiveBrowserLoginError::NotCurrent
    );
    assert_eq!(fixture.store.loads.load(Ordering::SeqCst), loads);
    fixture.no_writes();
}

#[tokio::test]
async fn login_handle_and_observation_debug_never_expose_identity_or_store_details() {
    let fixture = Fixture::new();
    let login = fixture.bind().await;
    let current = login.current().await.unwrap();
    let debug = format!("{login:?} {current:?}");
    for private in [
        "PRIVATE",
        "private@example.com",
        "reader",
        "ControlledStore",
    ] {
        assert!(!debug.contains(private));
    }
    assert!(!debug.contains(&fixture.session.id().unwrap().to_string()));
    assert!(debug.contains("[REDACTED]"));
    fixture.no_writes();
}

#[tokio::test]
async fn cancelled_observation_requires_a_new_check_but_does_not_invalidate_login() {
    let fixture = Fixture::new();
    let login = fixture.bind().await;
    fixture.store.mode.store(PENDING, Ordering::SeqCst);
    {
        let pending = login.current();
        tokio::pin!(pending);
        assert!(futures::poll!(pending.as_mut()).is_pending());
    }
    let previous_loads = fixture.store.loads.load(Ordering::SeqCst);
    fixture.store.mode.store(NORMAL, Ordering::SeqCst);
    assert_eq!(
        login.current().await.unwrap().user().profile.subject,
        fixture.user.profile.subject
    );
    assert_eq!(
        fixture.store.loads.load(Ordering::SeqCst),
        previous_loads + 1
    );
    fixture.no_writes();
}

#[tokio::test]
async fn encrypted_store_observations_preserve_ciphertext_and_detect_backing_deletion() {
    use crate::{EncryptedSessionStore, SessionEncryptionKey, SessionEncryptionKeyring};
    use base64::{Engine, engine::general_purpose::STANDARD};
    use tower_sessions::MemoryStore;

    let fixture = Fixture::new();
    let backing = MemoryStore::default();
    // Synthetic test key; no application secrets or persistent database are read.
    let key =
        SessionEncryptionKey::from_base64("live-login-test", STANDARD.encode([7u8; 32])).unwrap();
    let store = Arc::new(EncryptedSessionStore::new(
        backing.clone(),
        SessionEncryptionKeyring::new(key, Vec::new()).unwrap(),
    ));
    let mut record = fixture.store.record.lock().unwrap().clone().unwrap();
    store.create(&mut record).await.unwrap();
    let session = Session::new(Some(record.id), store.clone(), None);
    let _: AuthenticatedIdentitySession = session
        .get(AUTHENTICATED_SESSION_KEY)
        .await
        .unwrap()
        .unwrap();
    let before = backing.load(&record.id).await.unwrap().unwrap();
    assert!(
        !serde_json::to_string(&before.data)
            .unwrap()
            .contains("PRIVATE")
    );
    let login = LiveBrowserLogin::bind(&session, &fixture.user, store, Default::default())
        .await
        .unwrap();
    assert_eq!(
        login.current().await.unwrap().user().profile.subject,
        fixture.user.profile.subject
    );
    // Re-encryption/renewal would alter the envelope or expiry; neither occurs.
    assert_eq!(backing.load(&record.id).await.unwrap().unwrap(), before);
    backing.delete(&record.id).await.unwrap();
    assert!(
        session
            .get::<AuthenticatedIdentitySession>(AUTHENTICATED_SESSION_KEY)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        login.current().await.unwrap_err(),
        LiveBrowserLoginError::NotCurrent
    );
}
