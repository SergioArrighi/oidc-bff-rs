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
cargo package --workspace --no-verify
cargo audit
```

All GitHub Actions are pinned to immutable commits. A `vX.Y.Z` tag whose
version matches the workspace packages builds the three source archives,
generates an SPDX JSON SBOM and checksums, uploads one immutable workflow
artifact, and issues GitHub artifact attestations for every file. Verify that
workflow and its attestations before publishing any archive to crates.io.

Review every audit result. The currently accepted upstream exception and its
production impact are recorded in `docs/oidc-bff-security.md`; do not silently
add new exceptions.

Workspace packaging is required for the initial release because Cargo can
resolve unpublished sibling packages together; packaging an adapter by itself
requires `oidc-bff-core` to already exist in the crates.io index. Inspect all
three `.crate` archives under `target/package`, then publish
`oidc-bff-core`, and wait until its crates.io index entry is available. Cargo
cannot verify the adapters in isolation before that point because their
published manifests intentionally resolve `oidc-bff-core` from crates.io.
After the index entry appears, run the verified package checks:

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
