use std::{collections::HashMap, fmt, sync::Arc};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use tower_sessions::{
    SessionStore,
    session::{Id, Record},
    session_store::{Error as StoreError, Result as StoreResult},
};
use zeroize::Zeroizing;

const ENVELOPE_DATA_KEY: &str = "oidc-bff.encrypted-session.v1";
const ENVELOPE_VERSION: u8 = 1;
const MAX_DECRYPTION_KEYS: usize = 4;
const MAX_SESSION_PLAINTEXT_BYTES: usize = 1024 * 1024;
const MAX_ENCODED_CIPHERTEXT_BYTES: usize = (MAX_SESSION_PLAINTEXT_BYTES + 16).div_ceil(3) * 4;

/// Configuration failures for application-level session encryption.
#[derive(Debug, thiserror::Error)]
pub enum SessionEncryptionConfigurationError {
    #[error(
        "session encryption key id must contain 1 to 32 ASCII letters, digits, '.', '_' or '-'"
    )]
    InvalidKeyId,
    #[error("session encryption key must be standard base64 encoding of exactly 32 bytes")]
    InvalidKeyMaterial,
    #[error("session encryption key ids must be unique")]
    DuplicateKeyId,
    #[error("at most {MAX_DECRYPTION_KEYS} previous session encryption keys are supported")]
    TooManyPreviousKeys,
}

/// A named AES-256-GCM key. Debug output never exposes key material.
#[derive(Clone)]
pub struct SessionEncryptionKey {
    id: String,
    cipher: Aes256Gcm,
}

impl SessionEncryptionKey {
    /// Decodes a standard-base64 256-bit key and associates it with a rotation id.
    pub fn from_base64(
        id: impl Into<String>,
        encoded_key: impl AsRef<str>,
    ) -> Result<Self, SessionEncryptionConfigurationError> {
        let id = id.into();
        if id.is_empty()
            || id.len() > 32
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(SessionEncryptionConfigurationError::InvalidKeyId);
        }

        let decoded = Zeroizing::new(
            STANDARD
                .decode(encoded_key.as_ref())
                .map_err(|_| SessionEncryptionConfigurationError::InvalidKeyMaterial)?,
        );
        if decoded.len() != 32 {
            return Err(SessionEncryptionConfigurationError::InvalidKeyMaterial);
        }
        let cipher = Aes256Gcm::new_from_slice(decoded.as_slice())
            .map_err(|_| SessionEncryptionConfigurationError::InvalidKeyMaterial)?;
        Ok(Self { id, cipher })
    }

    fn seal(&self, nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> StoreResult<Vec<u8>> {
        let nonce = Nonce::from(*nonce);
        self.cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| StoreError::Encode("session encryption failed".to_owned()))
    }

    fn open(&self, nonce: &[u8; 12], ciphertext: &[u8], aad: &[u8]) -> StoreResult<Vec<u8>> {
        let nonce = Nonce::from(*nonce);
        self.cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| StoreError::Decode("session authentication failed".to_owned()))
    }
}

impl fmt::Debug for SessionEncryptionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionEncryptionKey")
            .field("id", &self.id)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

/// Active encryption key plus decryption-only keys retained during online rotation.
#[derive(Clone, Debug)]
pub struct SessionEncryptionKeyring {
    active: SessionEncryptionKey,
    previous: Vec<SessionEncryptionKey>,
}

impl SessionEncryptionKeyring {
    pub fn new(
        active: SessionEncryptionKey,
        previous: Vec<SessionEncryptionKey>,
    ) -> Result<Self, SessionEncryptionConfigurationError> {
        if previous.len() > MAX_DECRYPTION_KEYS {
            return Err(SessionEncryptionConfigurationError::TooManyPreviousKeys);
        }
        let mut ids = std::collections::HashSet::with_capacity(previous.len() + 1);
        ids.insert(active.id.as_str());
        if previous.iter().any(|key| !ids.insert(key.id.as_str())) {
            return Err(SessionEncryptionConfigurationError::DuplicateKeyId);
        }
        Ok(Self { active, previous })
    }

    fn key(&self, id: &str) -> Option<&SessionEncryptionKey> {
        if self.active.id == id {
            Some(&self.active)
        } else {
            self.previous.iter().find(|key| key.id == id)
        }
    }
}

/// Encrypts complete server-side session payloads before delegating persistence.
///
/// The backing store can see session identifiers and expiry timestamps for lookup and cleanup.
/// Both are authenticated as additional data, so encrypted records cannot be moved between ids
/// or expiry windows. No plaintext profile, anti-forgery token, or login transaction is persisted.
#[derive(Clone)]
pub struct EncryptedSessionStore<S> {
    inner: S,
    keyring: Arc<SessionEncryptionKeyring>,
}

impl<S> EncryptedSessionStore<S> {
    pub fn new(inner: S, keyring: SessionEncryptionKeyring) -> Self {
        Self {
            inner,
            keyring: Arc::new(keyring),
        }
    }

    pub fn inner(&self) -> &S {
        &self.inner
    }

    fn aad(record: &Record) -> Vec<u8> {
        format!(
            "oidc-bff-session:v{ENVELOPE_VERSION}:{}:{}",
            record.id,
            record.expiry_date.unix_timestamp_nanos()
        )
        .into_bytes()
    }

    fn encrypted_record(&self, record: &Record) -> StoreResult<Record> {
        let plaintext = Zeroizing::new(
            serde_json::to_vec(&record.data)
                .map_err(|error| StoreError::Encode(error.to_string()))?,
        );
        if plaintext.len() > MAX_SESSION_PLAINTEXT_BYTES {
            return Err(StoreError::Encode(
                "session payload exceeds the encryption limit".to_owned(),
            ));
        }
        let mut nonce = [0_u8; 12];
        getrandom::fill(&mut nonce)
            .map_err(|_| StoreError::Encode("secure random generation failed".to_owned()))?;
        let ciphertext =
            self.keyring
                .active
                .seal(&nonce, plaintext.as_slice(), &Self::aad(record))?;
        let envelope = EncryptedEnvelope {
            version: ENVELOPE_VERSION,
            key_id: self.keyring.active.id.clone(),
            nonce: STANDARD.encode(nonce),
            ciphertext: STANDARD.encode(ciphertext),
        };
        let mut data = HashMap::with_capacity(1);
        data.insert(
            ENVELOPE_DATA_KEY.to_owned(),
            serde_json::to_value(envelope)
                .map_err(|error| StoreError::Encode(error.to_string()))?,
        );
        Ok(Record {
            id: record.id,
            data,
            expiry_date: record.expiry_date,
        })
    }

    fn decrypted_record(&self, record: Record) -> StoreResult<Record> {
        if record.data.len() != 1 {
            return Err(StoreError::Decode(
                "unencrypted or malformed session record".to_owned(),
            ));
        }
        let envelope = record
            .data
            .get(ENVELOPE_DATA_KEY)
            .ok_or_else(|| StoreError::Decode("encrypted session envelope is missing".to_owned()))
            .and_then(|value| {
                serde_json::from_value::<EncryptedEnvelope>(value.clone()).map_err(|_| {
                    StoreError::Decode("encrypted session envelope is invalid".to_owned())
                })
            })?;
        if envelope.version != ENVELOPE_VERSION {
            return Err(StoreError::Decode(
                "encrypted session version is unsupported".to_owned(),
            ));
        }
        if envelope.nonce.len() != 16
            || !(24..=MAX_ENCODED_CIPHERTEXT_BYTES).contains(&envelope.ciphertext.len())
        {
            return Err(StoreError::Decode(
                "encrypted session payload size is invalid".to_owned(),
            ));
        }
        let key = self
            .keyring
            .key(&envelope.key_id)
            .ok_or_else(|| StoreError::Decode("encrypted session key is unavailable".to_owned()))?;
        let nonce_bytes = STANDARD
            .decode(envelope.nonce)
            .map_err(|_| StoreError::Decode("encrypted session nonce is invalid".to_owned()))?;
        let nonce: [u8; 12] = nonce_bytes
            .try_into()
            .map_err(|_| StoreError::Decode("encrypted session nonce is invalid".to_owned()))?;
        let ciphertext = STANDARD
            .decode(envelope.ciphertext)
            .map_err(|_| StoreError::Decode("encrypted session payload is invalid".to_owned()))?;
        let plaintext = Zeroizing::new(key.open(&nonce, &ciphertext, &Self::aad(&record))?);
        if plaintext.len() > MAX_SESSION_PLAINTEXT_BYTES {
            return Err(StoreError::Decode(
                "decrypted session payload exceeds the limit".to_owned(),
            ));
        }
        let data = serde_json::from_slice(plaintext.as_slice())
            .map_err(|_| StoreError::Decode("decrypted session payload is invalid".to_owned()))?;
        Ok(Record {
            id: record.id,
            data,
            expiry_date: record.expiry_date,
        })
    }
}

impl<S> fmt::Debug for EncryptedSessionStore<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedSessionStore")
            .field("inner", &std::any::type_name::<S>())
            .field("keyring", &self.keyring)
            .finish()
    }
}

#[async_trait]
impl<S> SessionStore for EncryptedSessionStore<S>
where
    S: SessionStore + Clone,
{
    async fn create(&self, session_record: &mut Record) -> StoreResult<()> {
        let plaintext = session_record.clone();
        let mut encrypted = self.encrypted_record(&plaintext)?;
        self.inner.create(&mut encrypted).await?;

        if encrypted.id != plaintext.id {
            let moved_plaintext = Record {
                id: encrypted.id,
                data: plaintext.data,
                expiry_date: encrypted.expiry_date,
            };
            encrypted = self.encrypted_record(&moved_plaintext)?;
            self.inner.save(&encrypted).await?;
        }
        session_record.id = encrypted.id;
        session_record.expiry_date = encrypted.expiry_date;
        Ok(())
    }

    async fn save(&self, session_record: &Record) -> StoreResult<()> {
        self.inner
            .save(&self.encrypted_record(session_record)?)
            .await
    }

    async fn load(&self, session_id: &Id) -> StoreResult<Option<Record>> {
        self.inner
            .load(session_id)
            .await?
            .map(|record| self.decrypted_record(record))
            .transpose()
    }

    async fn delete(&self, session_id: &Id) -> StoreResult<()> {
        self.inner.delete(session_id).await
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EncryptedEnvelope {
    version: u8,
    key_id: String,
    nonce: String,
    ciphertext: String,
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use time::{Duration, OffsetDateTime};
    use tower_sessions::{MemoryStore, SessionStore, session::Record};

    use super::{
        ENVELOPE_DATA_KEY, ENVELOPE_VERSION, EncryptedEnvelope, EncryptedSessionStore,
        MAX_ENCODED_CIPHERTEXT_BYTES, MAX_SESSION_PLAINTEXT_BYTES, STANDARD, SessionEncryptionKey,
        SessionEncryptionKeyring,
    };

    fn key(id: &str, byte: u8) -> SessionEncryptionKey {
        SessionEncryptionKey::from_base64(id, STANDARD.encode([byte; 32])).unwrap()
    }

    fn record(secret: &str) -> Record {
        let mut data = std::collections::HashMap::new();
        data.insert(
            "profile".to_owned(),
            serde_json::json!({ "secret": secret }),
        );
        Record {
            id: Default::default(),
            data,
            expiry_date: OffsetDateTime::now_utc() + Duration::hours(1),
        }
    }

    #[tokio::test]
    async fn backing_store_never_receives_plaintext() {
        let backing = MemoryStore::default();
        let store = EncryptedSessionStore::new(
            backing.clone(),
            SessionEncryptionKeyring::new(key("2026-08", 7), Vec::new()).unwrap(),
        );
        let mut original = record("private-profile-value");
        store.create(&mut original).await.unwrap();

        let raw = backing.load(&original.id).await.unwrap().unwrap();
        assert!(
            !serde_json::to_string(&raw.data)
                .unwrap()
                .contains("private-profile-value")
        );
        assert_eq!(store.load(&original.id).await.unwrap().unwrap(), original);
    }

    #[tokio::test]
    async fn previous_key_supports_online_rotation() {
        let backing = MemoryStore::default();
        let old_key = key("old", 1);
        let old_store = EncryptedSessionStore::new(
            backing.clone(),
            SessionEncryptionKeyring::new(old_key.clone(), Vec::new()).unwrap(),
        );
        let mut original = record("rotatable");
        old_store.create(&mut original).await.unwrap();

        let rotated = EncryptedSessionStore::new(
            backing,
            SessionEncryptionKeyring::new(key("new", 2), vec![old_key]).unwrap(),
        );
        assert_eq!(rotated.load(&original.id).await.unwrap().unwrap(), original);
        rotated.save(&original).await.unwrap();
        assert_eq!(rotated.load(&original.id).await.unwrap().unwrap(), original);
    }

    #[tokio::test]
    async fn oversized_plaintext_is_rejected_before_persistence() {
        let backing = MemoryStore::default();
        let store = EncryptedSessionStore::new(
            backing.clone(),
            SessionEncryptionKeyring::new(key("active", 1), Vec::new()).unwrap(),
        );
        let mut oversized = record(&"x".repeat(MAX_SESSION_PLAINTEXT_BYTES));

        assert!(store.create(&mut oversized).await.is_err());
        assert!(backing.load(&oversized.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn oversized_untrusted_ciphertext_is_rejected_before_decoding() {
        let backing = MemoryStore::default();
        let store = EncryptedSessionStore::new(
            backing.clone(),
            SessionEncryptionKeyring::new(key("active", 3), Vec::new()).unwrap(),
        );
        let mut raw = record("placeholder");
        raw.data.clear();
        raw.data.insert(
            ENVELOPE_DATA_KEY.to_owned(),
            serde_json::to_value(EncryptedEnvelope {
                version: ENVELOPE_VERSION,
                key_id: "active".to_owned(),
                nonce: STANDARD.encode([0_u8; 12]),
                ciphertext: "A".repeat(MAX_ENCODED_CIPHERTEXT_BYTES + 1),
            })
            .unwrap(),
        );
        backing.create(&mut raw).await.unwrap();

        assert!(store.load(&raw.id).await.is_err());
    }
}
