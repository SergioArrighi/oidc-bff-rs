# Publishing the OIDC BFF crates

The crates.io namespace is:

1. `oidc-bff-core`
2. `oidc-bff-axum`
3. `oidc-bff-leptos`

The packages must be published in that order because the Axum and Leptos
packages depend on the public `oidc-bff-core` package. Platform-specific
gateways and host authorization policy are deliberately outside this release
family.

The crate family declares Rust 1.88 as its minimum supported Rust version,
matching Leptos 0.8.20 and the selected JWT/time dependency line.

Before publishing:

```bash
cargo fmt --all -- --check
cargo clippy -p oidc-bff-core -p oidc-bff-axum -p oidc-bff-leptos \
  --all-targets -- -D warnings
cargo test -p oidc-bff-core -p oidc-bff-axum -p oidc-bff-leptos
cargo doc -p oidc-bff-core -p oidc-bff-axum --no-deps
cargo package -p oidc-bff-core
cargo audit
```

Review every audit result. The currently accepted upstream exception and its
production impact are recorded in `docs/oidc-bff-security.md`; do not silently
add new exceptions.

Inspect the core `.crate` archive under `target/package`, publish
`oidc-bff-core`, and wait until its crates.io index entry is available. Cargo
cannot package the adapters before that point because their published
manifests intentionally resolve `oidc-bff-core` from crates.io. Then run:

```bash
cargo package -p oidc-bff-axum
cargo package -p oidc-bff-leptos
```

Inspect those archives before publishing them.

Actual publication is intentionally not performed by repository validation:

```bash
cargo publish -p oidc-bff-core
cargo publish -p oidc-bff-axum
cargo publish -p oidc-bff-leptos
```
