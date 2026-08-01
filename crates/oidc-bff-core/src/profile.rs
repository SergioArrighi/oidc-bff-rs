use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

const MAXIMUM_SUBJECT_BYTES: usize = 255;
const MAXIMUM_EMAIL_BYTES: usize = 254;
const MAXIMUM_PROFILE_FIELD_BYTES: usize = 128;
const MAXIMUM_MEMBERSHIPS: usize = 128;

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
/// Stable provider subject projected into the application identity domain.
pub struct UserSubject(String);

impl UserSubject {
    /// Parses a non-empty, bounded subject without control characters.
    pub fn parse(value: impl Into<String>) -> Result<Self, ProfileValidationError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAXIMUM_SUBJECT_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(ProfileValidationError::Subject);
        }
        Ok(Self(value))
    }

    /// Returns the validated subject value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for UserSubject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
/// Bounded email-address projection supplied by a verified identity claim.
pub struct EmailAddress(String);

impl EmailAddress {
    /// Parses a structurally valid, bounded email address.
    pub fn parse(value: impl Into<String>) -> Result<Self, ProfileValidationError> {
        let value = value.into();
        let mut parts = value.split('@');
        let local = parts.next().unwrap_or_default();
        let domain = parts.next().unwrap_or_default();
        if value.len() > MAXIMUM_EMAIL_BYTES
            || local.is_empty()
            || domain.is_empty()
            || parts.next().is_some()
            || domain.starts_with('.')
            || domain.ends_with('.')
            || value.chars().any(char::is_whitespace)
        {
            return Err(ProfileValidationError::Email);
        }
        Ok(Self(value))
    }

    /// Returns the validated email address.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for EmailAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// Application-safe profile projected from verified provider claims.
pub struct UserProfile {
    /// Stable provider subject.
    pub subject: UserSubject,
    /// Optional email address.
    pub email: Option<EmailAddress>,
    /// Whether the identity provider marked the email as verified.
    pub email_verified: bool,
    /// Optional provider username.
    pub preferred_username: Option<String>,
    /// Optional given name.
    pub given_name: Option<String>,
    /// Optional family name.
    pub family_name: Option<String>,
    /// Non-empty display label chosen by the trusted server projection.
    pub display_name: String,
    /// Bounded provider role claims; authorization remains application-owned.
    pub roles: Vec<String>,
    /// Bounded provider group claims; authorization remains application-owned.
    pub groups: Vec<String>,
}

impl UserProfile {
    /// Validates every field and returns the bounded profile.
    pub fn validate(self) -> Result<Self, ProfileValidationError> {
        Self::validate_optional_field(&self.preferred_username)?;
        Self::validate_optional_field(&self.given_name)?;
        Self::validate_optional_field(&self.family_name)?;
        if self.display_name.is_empty()
            || self.display_name.len() > MAXIMUM_PROFILE_FIELD_BYTES
            || self.display_name.chars().any(char::is_control)
            || self.roles.len() > MAXIMUM_MEMBERSHIPS
            || self.groups.len() > MAXIMUM_MEMBERSHIPS
        {
            return Err(ProfileValidationError::Profile);
        }
        for membership in self.roles.iter().chain(&self.groups) {
            if membership.is_empty()
                || membership.len() > MAXIMUM_PROFILE_FIELD_BYTES
                || membership.chars().any(char::is_control)
            {
                return Err(ProfileValidationError::Profile);
            }
        }
        Ok(self)
    }

    fn validate_optional_field(value: &Option<String>) -> Result<(), ProfileValidationError> {
        if value.as_ref().is_some_and(|value| {
            value.is_empty()
                || value.len() > MAXIMUM_PROFILE_FIELD_BYTES
                || value.chars().any(char::is_control)
        }) {
            return Err(ProfileValidationError::Profile);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct UserProfileWire {
    subject: UserSubject,
    email: Option<EmailAddress>,
    email_verified: bool,
    preferred_username: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    display_name: String,
    roles: Vec<String>,
    groups: Vec<String>,
}

impl<'de> Deserialize<'de> for UserProfile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = UserProfileWire::deserialize(deserializer)?;
        Self {
            subject: wire.subject,
            email: wire.email,
            email_verified: wire.email_verified,
            preferred_username: wire.preferred_username,
            given_name: wire.given_name,
            family_name: wire.family_name,
            display_name: wire.display_name,
            roles: wire.roles,
            groups: wire.groups,
        }
        .validate()
        .map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, thiserror::Error)]
/// Validation failures for externally sourced identity profile data.
pub enum ProfileValidationError {
    #[error("user subject is invalid")]
    Subject,
    #[error("user email address is invalid")]
    Email,
    #[error("user profile is invalid")]
    Profile,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_ambiguous_or_unbounded_identity_values() {
        assert!(UserSubject::parse("").is_err());
        assert!(UserSubject::parse("subject\nspoof").is_err());
        assert!(EmailAddress::parse("not-an-email").is_err());
        assert!(EmailAddress::parse("two@@example.com").is_err());
    }

    #[test]
    fn deserialization_cannot_bypass_profile_bounds() {
        let invalid_subject = serde_json::json!({
            "subject": "subject\nspoof",
            "email": null,
            "email_verified": false,
            "preferred_username": null,
            "given_name": null,
            "family_name": null,
            "display_name": "User",
            "roles": [],
            "groups": []
        });
        assert!(serde_json::from_value::<UserProfile>(invalid_subject).is_err());

        let oversized_membership = serde_json::json!({
            "subject": "user-42",
            "email": "user@example.com",
            "email_verified": true,
            "preferred_username": "user",
            "given_name": null,
            "family_name": null,
            "display_name": "User",
            "roles": ["r".repeat(MAXIMUM_PROFILE_FIELD_BYTES + 1)],
            "groups": []
        });
        assert!(serde_json::from_value::<UserProfile>(oversized_membership).is_err());
    }
}
