# oidc-bff-rs

Reusable Rust building blocks for an OpenID Connect Backend-for-Frontend.
The project keeps OAuth credentials and browser sessions on the server while
exposing a small, bounded identity projection to browser applications.

Its scope is a session BFF for a co-located resource server. The authorization
response access token is validated when required by OIDC and then discarded;
this is not a generic token relay or refresh-token vault.

## Crates

- `oidc-bff-core`: provider-neutral profile, session, and logout contracts.
- `oidc-bff-axum`: OIDC Authorization Code + PKCE, server-side sessions, JWT
  resource-server verification, and Axum middleware.
- `oidc-bff-leptos`: an SSR-safe Leptos session client, identity gate, and
  profile menu.

This repository is intentionally application- and agent-runtime-neutral. Host
authorization policy, reverse proxies, agent identity, and workload topology
belong to the integrating application or platform.

For long-running server operations, Axum integrations can use
[live browser-login observations](docs/live-browser-login.md) to recheck the
original persisted login without renewing it. This supplements, rather than
replaces, the host's current authorization checks.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo check -p oidc-bff-leptos --target wasm32-unknown-unknown --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```

See [the security model](docs/oidc-bff-security.md) before deployment and
[the release procedure](docs/oidc-bff-release.md) before publishing.

Licensed under the MIT License.
