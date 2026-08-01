# oidc-bff-core

`oidc-bff-core` provides bounded, provider-neutral wire contracts for an
OpenID Connect Backend-for-Frontend (BFF). It contains no HTTP client, server,
cookie, token-validation, or identity-provider implementation.

The contracts are shared by [`oidc-bff-axum`](https://docs.rs/oidc-bff-axum)
and [`oidc-bff-leptos`](https://docs.rs/oidc-bff-leptos), so a browser can ask
its same-origin application whether a server-side session is authenticated
without receiving OAuth tokens.

## Security boundary

- `UserSubject`, `EmailAddress`, and profile fields are length-bounded and
  reject ambiguous control characters, including during Serde deserialization.
- `IdentitySession` contains projected profile data and a per-session
  anti-forgery value; it never contains an access token, refresh token, ID
  token, client secret, or session-store credential.
- Session and logout deserialization rejects inconsistent authentication state,
  unsafe navigation targets, and oversized browser-visible fields.
- Roles and groups are data supplied by a trusted server projection. This crate
  does not validate provider signatures or make authorization decisions.

## Example

```rust
use oidc_bff_core::{EmailAddress, UserProfile, UserSubject};

let profile = UserProfile {
    subject: UserSubject::parse("user-42")?,
    email: Some(EmailAddress::parse("user@example.com")?),
    email_verified: true,
    preferred_username: Some("user".to_owned()),
    given_name: None,
    family_name: None,
    display_name: "Example User".to_owned(),
    roles: vec!["owner".to_owned()],
    groups: Vec::new(),
}
.validate()?;

assert_eq!(profile.subject.as_str(), "user-42");
# Ok::<(), oidc_bff_core::ProfileValidationError>(())
```

## Compatibility

The serialized shapes are part of the public API. Version `0.1` uses
snake-case authentication states and optional profile/session fields so an
anonymous response and an authenticated response share one bounded contract.

Licensed under the MIT License.
