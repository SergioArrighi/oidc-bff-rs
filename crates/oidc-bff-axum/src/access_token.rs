use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::StreamExt;
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    jwk::{AlgorithmParameters, JwkSet, KeyAlgorithm, KeyOperations, PublicKeyUse},
};
use oidc_bff_core::{EmailAddress, UserProfile, UserSubject};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, RwLock};
use url::Url;

use crate::{
    AuthenticatedUser, AuthenticationMethod, AuthenticationPrincipalKind, IdentityConfiguration,
    IdentityError,
};

const MINIMUM_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const MAXIMUM_JWKS_AGE: Duration = Duration::from_secs(5 * 60);
const MAXIMUM_JWKS_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
pub(crate) struct AccessTokenVerifier {
    inner: Arc<AccessTokenVerifierInner>,
}

struct AccessTokenVerifierInner {
    http_client: openidconnect::reqwest::Client,
    jwks_url: Url,
    policy: AccessTokenVerificationPolicy,
    keys: RwLock<CachedJwks>,
    refresh: Mutex<JwksRefreshState>,
}

struct JwksRefreshState {
    last_attempt: Option<Instant>,
}

struct CachedJwks {
    keys: VerifiedKeySet,
    refreshed_at: Instant,
}

struct VerifiedKeySet {
    decoding_keys: HashMap<String, DecodingKey>,
}

#[derive(Clone)]
pub(crate) struct AccessTokenVerificationPolicy {
    issuer: String,
    audience: String,
    human_client_id: String,
    workload_client_id: String,
    workload_required_scope: String,
    access_token_type: String,
}

impl AccessTokenVerificationPolicy {
    pub fn from_configuration(configuration: &IdentityConfiguration) -> Self {
        Self {
            issuer: configuration.provider().issuer().to_string(),
            audience: configuration.resource_server().audience().to_owned(),
            human_client_id: configuration.resource_server().human_client_id().to_owned(),
            workload_client_id: configuration
                .resource_server()
                .workload_client_id()
                .to_owned(),
            workload_required_scope: configuration
                .resource_server()
                .workload_required_scope()
                .to_owned(),
            access_token_type: configuration
                .resource_server()
                .access_token_type()
                .to_owned(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct AccessTokenClaims {
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    azp: Option<String>,
    #[serde(rename = "exp")]
    _expiration: u64,
    #[serde(rename = "iat")]
    issued_at: u64,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: bool,
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    given_name: Option<String>,
    #[serde(default)]
    family_name: Option<String>,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    jti: Option<String>,
    #[serde(default)]
    scope: String,
}

impl AccessTokenVerifier {
    pub(crate) fn validate_jwks_document(
        document: &serde_json::Value,
    ) -> Result<(), IdentityError> {
        let set = serde_json::from_value(document.clone()).map_err(|_| IdentityError::Discovery)?;
        Self::validate_set(set).map(|_| ())
    }

    pub async fn discover(
        http_client: openidconnect::reqwest::Client,
        jwks_url: Url,
        policy: AccessTokenVerificationPolicy,
    ) -> Result<Self, IdentityError> {
        let keys = Self::fetch(&http_client, &jwks_url).await?;
        Ok(Self {
            inner: Arc::new(AccessTokenVerifierInner {
                http_client,
                jwks_url,
                policy,
                keys: RwLock::new(CachedJwks {
                    keys,
                    refreshed_at: Instant::now(),
                }),
                refresh: Mutex::new(JwksRefreshState { last_attempt: None }),
            }),
        })
    }

    pub async fn verify(&self, token: &str) -> Result<AuthenticatedUser, IdentityError> {
        if token.len() > 16 * 1024 {
            return Err(IdentityError::AccessTokenInvalid);
        }
        let header = decode_header(token).map_err(|_| IdentityError::AccessTokenInvalid)?;
        if header.alg != Algorithm::RS256 {
            return Err(IdentityError::AccessTokenInvalid);
        }
        if header.typ.as_deref() != Some(self.inner.policy.access_token_type.as_str()) {
            return Err(IdentityError::AccessTokenInvalid);
        }
        let kid = header.kid.ok_or(IdentityError::AccessTokenInvalid)?;
        self.refresh_if_stale().await?;
        let mut key = self.decoding_key(&kid).await;
        if key.is_none() {
            self.refresh_for_unknown_key().await?;
            key = self.decoding_key(&kid).await;
        }
        let key = key.ok_or(IdentityError::AccessTokenInvalid)?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_required_spec_claims(&["exp", "iat", "iss", "aud"]);
        validation.set_issuer(&[self.inner.policy.issuer.as_str()]);
        validation.set_audience(&[self.inner.policy.audience.as_str()]);
        validation.leeway = 30;
        validation.validate_nbf = true;
        validation.reject_tokens_expiring_in_less_than = 5;
        let claims = decode::<AccessTokenClaims>(token, &key, &validation)
            .map_err(|_| IdentityError::AccessTokenInvalid)?
            .claims;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| IdentityError::AccessTokenInvalid)?
            .as_secs();
        if claims.issued_at > now.saturating_add(validation.leeway) {
            return Err(IdentityError::AccessTokenInvalid);
        }
        self.project(claims, token)
    }

    async fn decoding_key(&self, kid: &str) -> Option<DecodingKey> {
        self.inner
            .keys
            .read()
            .await
            .keys
            .decoding_keys
            .get(kid)
            .cloned()
    }

    async fn refresh_if_stale(&self) -> Result<(), IdentityError> {
        {
            let keys = self.inner.keys.read().await;
            if keys.refreshed_at.elapsed() < MAXIMUM_JWKS_AGE {
                return Ok(());
            }
        }
        let mut refresh = self.inner.refresh.lock().await;
        {
            let keys = self.inner.keys.read().await;
            if keys.refreshed_at.elapsed() < MAXIMUM_JWKS_AGE {
                return Ok(());
            }
        }
        if refresh
            .last_attempt
            .is_some_and(|attempt| attempt.elapsed() < MINIMUM_REFRESH_INTERVAL)
        {
            return Err(IdentityError::Discovery);
        }
        refresh.last_attempt = Some(Instant::now());
        let verified_keys = Self::fetch(&self.inner.http_client, &self.inner.jwks_url).await?;
        let mut keys = self.inner.keys.write().await;
        if keys.refreshed_at.elapsed() >= MAXIMUM_JWKS_AGE {
            keys.keys = verified_keys;
            keys.refreshed_at = Instant::now();
        }
        Ok(())
    }

    async fn refresh_for_unknown_key(&self) -> Result<(), IdentityError> {
        let mut refresh = self.inner.refresh.lock().await;
        if refresh
            .last_attempt
            .is_some_and(|attempt| attempt.elapsed() < MINIMUM_REFRESH_INTERVAL)
        {
            return Ok(());
        }
        refresh.last_attempt = Some(Instant::now());
        let verified_keys = Self::fetch(&self.inner.http_client, &self.inner.jwks_url).await?;
        let mut keys = self.inner.keys.write().await;
        keys.keys = verified_keys;
        keys.refreshed_at = Instant::now();
        Ok(())
    }

    async fn fetch(
        client: &openidconnect::reqwest::Client,
        url: &Url,
    ) -> Result<VerifiedKeySet, IdentityError> {
        let response = client
            .get(url.clone())
            .send()
            .await
            .map_err(|_| IdentityError::Discovery)?
            .error_for_status()
            .map_err(|_| IdentityError::Discovery)?;
        if response
            .content_length()
            .is_some_and(|length| length > MAXIMUM_JWKS_BYTES as u64)
        {
            return Err(IdentityError::Discovery);
        }
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| IdentityError::Discovery)?;
            if body.len().saturating_add(chunk.len()) > MAXIMUM_JWKS_BYTES {
                return Err(IdentityError::Discovery);
            }
            body.extend_from_slice(&chunk);
        }
        let set: JwkSet = serde_json::from_slice(&body).map_err(|_| IdentityError::Discovery)?;
        Self::validate_set(set)
    }

    fn validate_set(set: JwkSet) -> Result<VerifiedKeySet, IdentityError> {
        if set.keys.is_empty() || set.keys.len() > 128 {
            return Err(IdentityError::Discovery);
        }
        let mut decoding_keys = HashMap::with_capacity(set.keys.len());
        for key in &set.keys {
            let key_id = key
                .common
                .key_id
                .as_deref()
                .filter(|value| {
                    !value.is_empty() && value.len() <= 255 && !value.chars().any(char::is_control)
                })
                .ok_or(IdentityError::Discovery)?;
            let AlgorithmParameters::RSA(parameters) = &key.algorithm else {
                return Err(IdentityError::Discovery);
            };
            let modulus = URL_SAFE_NO_PAD
                .decode(&parameters.n)
                .map_err(|_| IdentityError::Discovery)?;
            let exponent = URL_SAFE_NO_PAD
                .decode(&parameters.e)
                .map_err(|_| IdentityError::Discovery)?;
            if decoding_keys.contains_key(key_id)
                || key.common.key_algorithm != Some(KeyAlgorithm::RS256)
                || !(256..=1024).contains(&modulus.len())
                || modulus.first().is_none_or(|byte| byte & 0x80 == 0)
                || exponent.as_slice() != [0x01, 0x00, 0x01]
                || key
                    .common
                    .public_key_use
                    .as_ref()
                    .is_some_and(|usage| usage != &PublicKeyUse::Signature)
                || key.common.public_key_use.is_some() && key.common.key_operations.is_some()
                || key
                    .common
                    .key_operations
                    .as_ref()
                    .is_some_and(|operations| {
                        operations.is_empty()
                            || operations
                                .iter()
                                .any(|operation| operation != &KeyOperations::Verify)
                    })
            {
                return Err(IdentityError::Discovery);
            }
            let decoding_key = DecodingKey::from_jwk(key).map_err(|_| IdentityError::Discovery)?;
            decoding_keys.insert(key_id.to_owned(), decoding_key);
        }
        Ok(VerifiedKeySet { decoding_keys })
    }

    fn project(
        &self,
        claims: AccessTokenClaims,
        token: &str,
    ) -> Result<AuthenticatedUser, IdentityError> {
        let (subject_value, kind) = match (claims.sub, claims.azp) {
            (_, Some(client_id)) if client_id == self.inner.policy.workload_client_id => {
                let has_required_scope = claims
                    .scope
                    .split_ascii_whitespace()
                    .any(|scope| scope == self.inner.policy.workload_required_scope);
                if !has_required_scope {
                    return Err(IdentityError::AccessTokenInvalid);
                }
                (
                    format!("workload:{client_id}"),
                    AuthenticationPrincipalKind::Workload,
                )
            }
            (Some(subject), Some(client_id)) if client_id == self.inner.policy.human_client_id => {
                (subject, AuthenticationPrincipalKind::Human)
            }
            _ => return Err(IdentityError::AccessTokenInvalid),
        };
        let subject =
            UserSubject::parse(subject_value).map_err(|_| IdentityError::AccessTokenInvalid)?;
        let email = claims
            .email
            .map(EmailAddress::parse)
            .transpose()
            .map_err(|_| IdentityError::AccessTokenInvalid)?;
        let display_name = claims
            .preferred_username
            .clone()
            .or_else(|| email.as_ref().map(|value| value.as_str().to_owned()))
            .unwrap_or_else(|| subject.as_str().to_owned());
        let profile = UserProfile {
            subject,
            email,
            email_verified: claims.email_verified,
            preferred_username: claims.preferred_username,
            given_name: claims.given_name,
            family_name: claims.family_name,
            display_name,
            roles: claims.roles,
            groups: claims.groups,
        }
        .validate()
        .map_err(|_| IdentityError::AccessTokenInvalid)?;
        let authentication_session_id = claims
            .jti
            .filter(|value| {
                !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
            })
            .unwrap_or_else(|| {
                let fingerprint = Sha256::digest(token.as_bytes());
                format!("jwt:{}", URL_SAFE_NO_PAD.encode(&fingerprint[..16]))
            });
        Ok(AuthenticatedUser {
            profile,
            authentication_session_id,
            kind,
            method: AuthenticationMethod::BearerToken,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::{Json, Router, routing::get};

    struct JwksFixture;

    impl JwksFixture {
        fn key(key_id: &str, modulus_bytes: usize) -> serde_json::Value {
            serde_json::json!({
                "kty": "RSA",
                "use": "sig",
                "kid": key_id,
                "alg": "RS256",
                "n": URL_SAFE_NO_PAD.encode(vec![0x80; modulus_bytes]),
                "e": URL_SAFE_NO_PAD.encode([0x01, 0x00, 0x01])
            })
        }

        fn set(keys: Vec<serde_json::Value>) -> JwkSet {
            serde_json::from_value(serde_json::json!({ "keys": keys })).unwrap()
        }
    }

    fn verifier() -> AccessTokenVerifier {
        AccessTokenVerifier {
            inner: Arc::new(AccessTokenVerifierInner {
                http_client: openidconnect::reqwest::Client::new(),
                jwks_url: Url::parse("https://identity.example.com/jwks").unwrap(),
                policy: AccessTokenVerificationPolicy {
                    issuer: "https://identity.example.com".to_owned(),
                    audience: "https://api.example.com".to_owned(),
                    human_client_id: "browser-client".to_owned(),
                    workload_client_id: "automation-client".to_owned(),
                    workload_required_scope: "api".to_owned(),
                    access_token_type: "at+jwt".to_owned(),
                },
                keys: RwLock::new(CachedJwks {
                    keys: VerifiedKeySet {
                        decoding_keys: HashMap::new(),
                    },
                    refreshed_at: Instant::now(),
                }),
                refresh: Mutex::new(JwksRefreshState { last_attempt: None }),
            }),
        }
    }

    fn claims(
        subject: Option<&str>,
        authorized_party: Option<&str>,
        scope: &str,
    ) -> AccessTokenClaims {
        AccessTokenClaims {
            sub: subject.map(str::to_owned),
            azp: authorized_party.map(str::to_owned),
            _expiration: u64::MAX,
            issued_at: 1,
            email: None,
            email_verified: false,
            preferred_username: None,
            given_name: None,
            family_name: None,
            roles: Vec::new(),
            groups: Vec::new(),
            jti: Some("token-session".to_owned()),
            scope: scope.to_owned(),
        }
    }

    #[test]
    fn classifies_configured_workload_even_when_provider_includes_subject() {
        let authenticated = verifier()
            .project(
                claims(
                    Some("provider-client-subject"),
                    Some("automation-client"),
                    "api",
                ),
                "encoded-token",
            )
            .unwrap();

        assert_eq!(authenticated.kind, AuthenticationPrincipalKind::Workload);
        assert_eq!(
            authenticated.profile.subject.as_str(),
            "workload:automation-client"
        );
    }

    #[test]
    fn rejects_configured_workload_without_required_scope() {
        let result = verifier().project(
            claims(
                Some("provider-client-subject"),
                Some("automation-client"),
                "openid",
            ),
            "encoded-token",
        );

        assert!(matches!(result, Err(IdentityError::AccessTokenInvalid)));
    }

    #[test]
    fn preserves_human_subject_for_other_authorized_parties() {
        let authenticated = verifier()
            .project(
                claims(Some("user-42"), Some("browser-client"), "openid"),
                "encoded-token",
            )
            .unwrap();

        assert_eq!(authenticated.kind, AuthenticationPrincipalKind::Human);
        assert_eq!(authenticated.profile.subject.as_str(), "user-42");
    }

    #[test]
    fn rejects_weak_or_ambiguous_verification_keys() {
        let weak = JwksFixture::set(vec![JwksFixture::key("weak", 128)]);
        assert!(AccessTokenVerifier::validate_set(weak).is_err());

        let duplicate = JwksFixture::set(vec![
            JwksFixture::key("same", 256),
            JwksFixture::key("same", 256),
        ]);
        assert!(AccessTokenVerifier::validate_set(duplicate).is_err());

        let valid = JwksFixture::set(vec![JwksFixture::key("current", 256)]);
        assert!(AccessTokenVerifier::validate_set(valid).is_ok());
    }

    #[test]
    fn rejects_human_tokens_from_an_unregistered_authorized_party() {
        let result = verifier().project(
            claims(Some("user-42"), Some("other-client"), "openid"),
            "encoded-token",
        );
        assert!(matches!(result, Err(IdentityError::AccessTokenInvalid)));
    }

    #[tokio::test]
    async fn refreshes_stale_verification_keys_once() {
        let requests = Arc::new(AtomicUsize::new(0));
        let observed_requests = Arc::clone(&requests);
        let document = serde_json::json!({
            "keys": [JwksFixture::key("current", 256)]
        });
        let router = Router::new().route(
            "/jwks",
            get(move || {
                let observed_requests = Arc::clone(&observed_requests);
                let document = document.clone();
                async move {
                    observed_requests.fetch_add(1, Ordering::SeqCst);
                    Json(document)
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let jwks_url = format!("http://{}/jwks", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let verifier = verifier();
        let verifier = AccessTokenVerifier {
            inner: Arc::new(AccessTokenVerifierInner {
                jwks_url,
                keys: RwLock::new(CachedJwks {
                    keys: VerifiedKeySet {
                        decoding_keys: HashMap::new(),
                    },
                    refreshed_at: Instant::now() - MAXIMUM_JWKS_AGE,
                }),
                ..Arc::try_unwrap(verifier.inner).ok().unwrap()
            }),
        };

        verifier.refresh_if_stale().await.unwrap();
        verifier.refresh_if_stale().await.unwrap();
        assert!(verifier.decoding_key("current").await.is_some());
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        task.abort();
    }
}
