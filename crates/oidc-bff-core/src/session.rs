use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use url::Url;

use crate::UserProfile;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Authentication state exposed by the same-origin session endpoint.
pub enum AuthenticationStatus {
    /// No valid server-side identity session exists.
    Anonymous,
    /// A valid server-side identity session exists.
    Authenticated,
}

const MAXIMUM_ANTI_FORGERY_TOKEN_BYTES: usize = 512;
const MAXIMUM_NAVIGATION_PATH_BYTES: usize = 2_048;
const MAXIMUM_ACCOUNT_URL_BYTES: usize = 4_096;

#[derive(Clone, Eq, PartialEq, Serialize)]
/// Browser-safe projection of a server-owned identity session.
pub struct IdentitySession {
    /// Current authentication state.
    pub status: AuthenticationStatus,
    /// Authenticated profile, present only for an authenticated session.
    pub profile: Option<UserProfile>,
    /// Per-session anti-forgery value required on every unsafe browser request.
    pub anti_forgery_token: Option<String>,
    /// Absolute session expiry in Unix epoch seconds.
    pub expires_at_epoch_seconds: Option<u64>,
    /// Persisted inactivity deadline, bounded by the absolute deadline.
    pub inactivity_expires_at_epoch_seconds: Option<u64>,
    /// Same-origin sign-in path.
    pub sign_in_path: String,
    /// Same-origin sign-out path.
    pub sign_out_path: String,
    /// Provider account-management URL.
    pub account_url: String,
}

impl std::fmt::Debug for IdentitySession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IdentitySession")
            .field("status", &self.status)
            .field("profile", &self.profile.as_ref().map(|_| "[REDACTED]"))
            .field(
                "anti_forgery_token",
                &self.anti_forgery_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("expires_at_epoch_seconds", &self.expires_at_epoch_seconds)
            .field("sign_in_path", &self.sign_in_path)
            .field("sign_out_path", &self.sign_out_path)
            .field("account_url", &self.account_url)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
/// Successful logout response directing the browser to its next location.
pub struct IdentityLogout {
    /// Provider or application URL to visit after the local session is revoked.
    pub redirect_to: String,
}

impl std::fmt::Debug for IdentityLogout {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IdentityLogout")
            .field("redirect_to", &"[REDACTED]")
            .finish()
    }
}

impl IdentitySession {
    /// Constructs an anonymous session projection with navigation endpoints.
    pub fn anonymous(
        sign_in_path: impl Into<String>,
        sign_out_path: impl Into<String>,
        account_url: impl Into<String>,
    ) -> Self {
        Self {
            status: AuthenticationStatus::Anonymous,
            profile: None,
            anti_forgery_token: None,
            expires_at_epoch_seconds: None,
            inactivity_expires_at_epoch_seconds: None,
            sign_in_path: sign_in_path.into(),
            sign_out_path: sign_out_path.into(),
            account_url: account_url.into(),
        }
    }

    /// Validates bounded fields and authentication-state invariants.
    pub fn validate(self) -> Result<Self, IdentitySessionValidationError> {
        Self::validate_path(&self.sign_in_path)?;
        Self::validate_path(&self.sign_out_path)?;
        Self::validate_http_url(&self.account_url)?;
        let anti_forgery_token_is_valid = self.anti_forgery_token.as_ref().is_none_or(|value| {
            (16..=MAXIMUM_ANTI_FORGERY_TOKEN_BYTES).contains(&value.len())
                && !value.chars().any(char::is_control)
        });
        let state_is_valid = match self.status {
            AuthenticationStatus::Anonymous => {
                self.profile.is_none()
                    && self.anti_forgery_token.is_none()
                    && self.expires_at_epoch_seconds.is_none()
                    && self.inactivity_expires_at_epoch_seconds.is_none()
            }
            AuthenticationStatus::Authenticated => {
                self.profile.is_some()
                    && self.anti_forgery_token.is_some()
                    && self.expires_at_epoch_seconds.is_some()
            }
        };
        let deadlines_valid = self.inactivity_expires_at_epoch_seconds.is_none_or(|idle| {
            self.expires_at_epoch_seconds
                .is_some_and(|absolute| idle <= absolute)
        });
        if !anti_forgery_token_is_valid || !state_is_valid || !deadlines_valid {
            return Err(IdentitySessionValidationError::Session);
        }
        Ok(self)
    }

    fn validate_path(value: &str) -> Result<(), IdentitySessionValidationError> {
        if value.is_empty()
            || value.len() > MAXIMUM_NAVIGATION_PATH_BYTES
            || !value.starts_with('/')
            || value.starts_with("//")
            || value.contains('\\')
            || value.chars().any(char::is_control)
        {
            return Err(IdentitySessionValidationError::Navigation);
        }
        Ok(())
    }

    fn validate_http_url(value: &str) -> Result<(), IdentitySessionValidationError> {
        if value.is_empty()
            || value.len() > MAXIMUM_ACCOUNT_URL_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(IdentitySessionValidationError::Navigation);
        }
        let url = Url::parse(value).map_err(|_| IdentitySessionValidationError::Navigation)?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(IdentitySessionValidationError::Navigation);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct IdentitySessionWire {
    status: AuthenticationStatus,
    profile: Option<UserProfile>,
    anti_forgery_token: Option<String>,
    expires_at_epoch_seconds: Option<u64>,
    inactivity_expires_at_epoch_seconds: Option<u64>,
    sign_in_path: String,
    sign_out_path: String,
    account_url: String,
}

impl<'de> Deserialize<'de> for IdentitySession {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = IdentitySessionWire::deserialize(deserializer)?;
        Self {
            status: wire.status,
            profile: wire.profile,
            anti_forgery_token: wire.anti_forgery_token,
            expires_at_epoch_seconds: wire.expires_at_epoch_seconds,
            inactivity_expires_at_epoch_seconds: wire.inactivity_expires_at_epoch_seconds,
            sign_in_path: wire.sign_in_path,
            sign_out_path: wire.sign_out_path,
            account_url: wire.account_url,
        }
        .validate()
        .map_err(D::Error::custom)
    }
}

impl IdentityLogout {
    /// Validates the bounded HTTP(S) post-logout destination.
    pub fn validate(self) -> Result<Self, IdentitySessionValidationError> {
        IdentitySession::validate_http_url(&self.redirect_to)?;
        Ok(self)
    }
}

#[derive(Deserialize)]
struct IdentityLogoutWire {
    redirect_to: String,
}

impl<'de> Deserialize<'de> for IdentityLogout {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = IdentityLogoutWire::deserialize(deserializer)?;
        Self {
            redirect_to: wire.redirect_to,
        }
        .validate()
        .map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, thiserror::Error)]
/// Validation failures for browser-visible session and navigation data.
pub enum IdentitySessionValidationError {
    /// Authentication state and optional fields are inconsistent or unbounded.
    #[error("identity session is invalid")]
    Session,
    /// A navigation path or URL is unsafe or unbounded.
    #[error("identity navigation target is invalid")]
    Navigation,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_inconsistent_or_unsafe_session_wire_values() {
        let inconsistent = serde_json::json!({
            "status": "authenticated",
            "profile": null,
            "anti_forgery_token": null,
            "expires_at_epoch_seconds": null,
            "sign_in_path": "/auth/login",
            "sign_out_path": "/auth/logout",
            "account_url": "https://identity.example.com/account"
        });
        assert!(serde_json::from_value::<IdentitySession>(inconsistent).is_err());

        let unsafe_navigation = serde_json::json!({
            "status": "anonymous",
            "profile": null,
            "anti_forgery_token": null,
            "expires_at_epoch_seconds": null,
            "sign_in_path": "//attacker.example/login",
            "sign_out_path": "/auth/logout",
            "account_url": "javascript:alert(1)"
        });
        assert!(serde_json::from_value::<IdentitySession>(unsafe_navigation).is_err());

        let unsafe_logout = serde_json::json!({"redirect_to": "javascript:alert(1)"});
        assert!(serde_json::from_value::<IdentityLogout>(unsafe_logout).is_err());

        let short_anti_forgery_token = serde_json::json!({
            "status": "authenticated",
            "profile": {
                "subject": "user-42",
                "email": null,
                "email_verified": false,
                "preferred_username": null,
                "given_name": null,
                "family_name": null,
                "display_name": "User",
                "roles": [],
                "groups": []
            },
            "anti_forgery_token": "short",
            "expires_at_epoch_seconds": 1,
            "sign_in_path": "/auth/login",
            "sign_out_path": "/auth/logout",
            "account_url": "https://identity.example.com/account"
        });
        assert!(serde_json::from_value::<IdentitySession>(short_anti_forgery_token).is_err());
    }

    #[test]
    fn debug_output_redacts_browser_secrets_and_profile() {
        let session = IdentitySession {
            status: AuthenticationStatus::Authenticated,
            profile: Some(UserProfile {
                subject: crate::UserSubject::parse("user-42").unwrap(),
                email: None,
                email_verified: false,
                preferred_username: None,
                given_name: None,
                family_name: None,
                display_name: "User".to_owned(),
                roles: Vec::new(),
                groups: Vec::new(),
            }),
            anti_forgery_token: Some("secret-anti-forgery-value".to_owned()),
            expires_at_epoch_seconds: Some(1),
            inactivity_expires_at_epoch_seconds: Some(1),
            sign_in_path: "/auth/login".to_owned(),
            sign_out_path: "/auth/logout".to_owned(),
            account_url: "https://identity.example.com/account".to_owned(),
        };
        let session_debug = format!("{session:?}");
        assert!(!session_debug.contains("user-42"));
        assert!(!session_debug.contains("secret-anti-forgery-value"));

        let logout = IdentityLogout {
            redirect_to: "https://identity.example.com/logout?logout_hint=secret".to_owned(),
        };
        assert!(!format!("{logout:?}").contains("secret"));
    }
}
