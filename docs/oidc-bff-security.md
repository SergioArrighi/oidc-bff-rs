# OIDC BFF production security profile

`oidc-bff-rs` is a session BFF for an application whose resource server is
co-located with the BFF. It is not an authorization server, identity provider,
token vault, generic API proxy, or refresh-token client.

The profile is based on OAuth 2.0 Security Best Current Practice (RFC 9700),
OAuth 2.0 for Browser-Based Applications (RFC 10017), JWT Best Current
Practices (RFC 8725), PKCE (RFC 7636), and OpenID Connect Core 1.0.

## Enforced invariants

- The BFF is a confidential client. A client secret of 32 to 4096 bytes is
  mandatory, is redacted from `Debug`, and is sent only with
  `client_secret_basic` at the token endpoint.
- Authorization Code is always combined with PKCE S256, a random `state`, and
  an OIDC `nonce`. The callback consumes its one-use server-held login
  transaction before token exchange, rejects transactions older than five
  minutes, and rotates the session identifier on success.
- Provider discovery, JWKS, and token responses use a redirect-free transport,
  five-second connection timeout, fifteen-second request timeout, 64 KiB
  request limit, and one MiB decompressed response limit.
- Discovered authorization, token, JWKS, and logout endpoints must use the
  configured deployment transport and the issuer origin. This is a deliberate
  SSRF and token-exfiltration restriction. Discovery metadata is parsed and
  validated before the first request to its JWKS URI.
- An operator-configured backchannel base URL may replace only the transport
  origin used for discovery, token exchange, and JWKS retrieval. Its path must
  match the public issuer path and its production transport must remain HTTPS.
  Provider-advertised endpoints are validated against the public issuer before
  this deterministic rewrite; authorization/logout redirects and JWT issuer
  validation always retain the public origin.
- ID tokens are pinned to RS256, issuer, audience, nonce, expiry, and optional
  access-token hash validation. Algorithms advertised by a provider do not
  widen the accepted set.
- JWT access tokens are pinned to RS256 and an exact configured `typ`, issuer,
  audience, `iat`, optional `nbf`, and expiry. Human and workload tokens use
  mutually exclusive `azp` rules; workloads additionally require one exact
  scope.
- JWKS documents are capped at one MiB and 128 keys. Key IDs must be unique and
  bounded. Verification keys must be RS256 RSA signing keys with a modulus of
  2048 to 8192 bits and exponent 65537. Unknown-key refresh is serialized and
  rate-limited. A cached access-token key set older than five minutes is
  refreshed before another token is accepted, and current ID-token keys are
  fetched for each login callback.
- Production construction requires HTTPS and an HttpOnly, Secure, Path `/`,
  SameSite=Lax cookie named with the `__Host-Http-` prefix. Plain HTTP is a
  separate type-level mode restricted to loopback development.
- Every unsafe cookie-authenticated request must present the exact application
  `Origin` and the session-specific `x-anti-forgery-token`. A contradictory
  `Sec-Fetch-Site` value is rejected. SameSite is defense in depth, not the
  primary CSRF control.
- Identity responses are `no-store`, `no-cache`, `no-referrer`, and `nosniff`.
  OAuth/provider errors, request contents, and credentials are not reflected
  in public error bodies.
- Browser session and logout documents are field-bounded during
  deserialization. The Leptos client reads response streams incrementally and
  stops at 64 KiB; it rejects cross-origin endpoint configuration and HTTP
  redirects.
- OAuth access, refresh, and ID tokens are not retained in browser sessions or
  exposed by session/logout responses. RP-initiated logout identifies the
  relying party with its `client_id`. Secret-bearing session, callback,
  authenticated-user, client-credential, and logout values are redacted from
  `Debug` output.
- Application-level AES-256-GCM encryption bounds each serialized session to
  one MiB before persistence, authenticates the visible id and expiry as
  additional data, and rejects oversized envelopes before base64 decoding.
  Rotation supports one active and at most four decryption-only prior keys.
- A local session is flushed on logout. It expires at the earlier of the ID
  token expiry and the configured absolute lifetime, which cannot exceed two
  hours. The BFF does not request or retain refresh tokens and discards the
  authorization response access token after validating `at_hash` when present.

SameSite is Lax because the provider's top-level authorization redirect must
carry the pending-login cookie back to `/auth/callback`. The per-session token
and exact Origin check protect mutations, including against hostile same-site
subdomains that SameSite alone does not isolate.

## Trust boundaries and retained data

The identity provider owns credentials, authentication, OAuth grants, signing
keys, and account lifecycle. The Axum host owns authorization and the
server-side session. The browser receives a bounded user projection and an
anti-forgery token; it never receives an OAuth access token, refresh token,
client secret, ID token, or session-store record identifier.

The server session record contains only the projected profile, anti-forgery
value, random authentication binding, and expiry. Treat the session store as
confidential identity data even though it contains no OAuth token.

## Mandatory deployment gates

A deployment is not production-ready unless all of these are true:

1. TLS 1.2 or newer is enforced from the browser to the application, with HSTS
   at the public edge. The configured public origin exactly matches that edge.
2. The client secret is generated by the provider, stored in a secret manager,
   never built into browser assets, and covered by a tested rotation procedure.
3. The `tower-sessions` store is durable, shared by every application replica,
   encrypted at rest and in backups, access-controlled, and configured to
   delete expired sessions. `MemoryStore` is not used.
4. `/auth/*` and cookie-authenticated application routes do not have permissive
   CORS. In particular, no untrusted origin may read `/auth/session` or submit
   credentialed requests.
5. `IdentityAuthentication::authorize` or
   `authorize_user_or_access_token` protects every cookie-authenticated route;
   no mutation bypasses the anti-forgery middleware.
6. Login, callback, token-bearing APIs, and expensive application operations
   have edge rate limits and request-body limits. Proxy-derived client IPs are
   trusted only from an explicit proxy allowlist.
7. Host authorization is applied after authentication and defaults to deny.
   Profile roles and groups are data, not authorization decisions.
8. Security headers and a restrictive CSP protect the host UI. Sensitive
   values and callback query strings are redacted from access logs and tracing.
9. Provider signing-key rotation, client-secret rotation, backup restoration,
   logout, clock synchronization, and identity-provider outage behavior are
   exercised before release.
10. Dependency scanning, SBOM/provenance generation, and the repository test,
    Clippy, rustdoc, WASM, and package checks pass for the exact lockfile.

## Explicit limits

- Opaque access tokens and algorithms other than RS256 are unsupported.
- One audience, one human client, and one workload client/scope are supported
  per `IdentityApplication`.
- OIDC front-channel and back-channel logout notification endpoints are not
  implemented. Provider-side account revocation therefore becomes visible no
  later than the earlier ID-token/session expiry. Deployments requiring
  immediate central logout must add a shared revocation adapter before use.
- DPoP and mutual-TLS sender-constrained access tokens are not implemented.
  Workload bearer tokens must remain on protected server-to-server channels
  and should have short provider lifetimes.
- The provider endpoint same-origin rule intentionally excludes OIDC providers
  whose discovery document delegates endpoints to other origins. A configured
  backchannel is not provider delegation and never changes advertised metadata.

## Dependency advisory

`cargo audit` reports `RUSTSEC-2023-0071` for `rsa 0.9.10`, transitively used by
`openidconnect`. No fixed RustCrypto release is available. The advisory concerns
timing leakage in private-key operations; production code in these crates uses
that dependency only for public-key verification. Access-token verification
uses the AWS-LC backend. The fake provider's private RSA operation is test-only.
This is a reviewed, narrow exception—not a claim that the advisory is fixed.
Remove it when the upstream OIDC dependency offers a non-vulnerable backend.

The audit also reports unmaintained proc-macro dependencies below Leptos. They
execute at build time and are not linked into the WASM/runtime artifact, but
they remain supply-chain inputs. Dependabot and the CI audit keep them visible;
remove the exception by upgrading Leptos when its dependency graph migrates.

Report vulnerabilities privately to the repository owner. Do not include
tokens, client secrets, or real identity data in a report.
