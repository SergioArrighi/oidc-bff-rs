# Live browser-login observations

`oidc_bff_axum::LiveBrowserLogin` is an opaque, browser-human-only handle for
long-running application operations. It binds the original persisted session ID,
subject and authentication-session ID. It never accepts browser-supplied identity
claims. The native caller supplies its authenticated request, `Session`, and
authoritative decrypting `SessionStore`. The trait alone
does not establish freshness: do not supply an independently stale cache or read
replica. In particular, `CachingSessionStore::load` can return a cached record
without consulting its backing store and can populate its cache on a miss.
The freshness contract requires a backing store whose `load` observes
authoritative records without extending their lifetime. ClustEU's existing
encrypted SQLite session store is the intended caller, not a second cache layer.

`LiveBrowserLogin::bind` is the original read-only form.
`IdentityApplication::live_browser_login` additionally permits rotating the provider
refresh credential before the current ID token expires. It does not renew inactivity:
automated work is not user presence. Both forms read the store before returning. `current` performs a fresh `load` of the
original record on every call: cached `Session::get` data and a cloned request
session are not evidence that local logout has not occurred. Missing records,
different IDs/subjects/logins, corruption, expired deadlines and unavailable
storage fail closed. A failed check invalidates the handle and all its clones;
recovering storage requires a new authenticated request/handle, not resuming an
uncertain stream automatically.

The current provider identity deadline, persisted inactivity deadline and private
local absolute authentication deadline must remain live. The local absolute
deadline is pinned when binding, so an existing handle cannot gain time from a
subsequently lengthened stored deadline. A renewable handle refreshes provider
identity sixty seconds before expiry. Explicit CSRF-protected browser activity at
`POST /auth/session/activity` renews inactivity and the cookie together, using the
authoritative store supplied through `IdentityHttpApplication::with_session_store`.
`GET /auth/session` only reads the deadlines. Provider rotation and inactivity can never move the
pinned local deadline. A transient provider failure is tolerated only while the
previous identity credential remains current; expiry without successful refresh
fails closed. The plain `bind` form never writes or renews.

The refresh credential and original nonce exist only in the encrypted server
record. A refreshed ID token may omit nonce as OIDC permits; if it contains one,
it must match the original. Subject, issuer, audience, expiry, signature and any
access-token hash are revalidated. Refresh responses must contain an ID token.
Signing-key rotation is handled by validating the already-issued response once
against fresh discovery/JWKS, never by submitting a rotating refresh token twice.
Logout and local refresh are process-serialized, and the record is re-read after
the provider call so deletion or a changed login wins.

The returned `CurrentBrowserLogin` exposes current authenticated profile/login
identity and the sampled observation/deadline times. It is not an authorization
lease that stays valid indefinitely. Recheck the handle and application-specific
corpus/journal policy before later use or delivery. Neither public type serializes
itself; Debug redacts identity/session/profile values. CSRF material and the store
session ID are not exposed by this API. Errors do not include stored data or
underlying database failures.

The default read timeout is five seconds, configurable from 10 ms to 30 s. It bounds a
single store observation, not model generation or a complete research turn. State
processing has a 1-MiB encoded-data ceiling without allocating a second serialized
copy, aligned with the encrypted-store plaintext bound. The store still owns its
initial allocation/decryption. Async timeout cannot preempt synchronous decoding;
the read checks elapsed time again before releasing its result.

## Limits of this guarantee

- This detects local deletion/logout and local deadlines when sampled. Provider
  refresh detects revoked/invalid refresh grants at the next identity deadline;
  it is not immediate revocation, introspection or back-channel logout.
- A successful read is not atomic with later delivery. A timer driven by a polled
  response stream is not an independent watchdog for a backpressured reader.
- Once this handle observes failure it stays invalid, including across clones.
  Renewal is serialized only inside one BFF process. A multi-replica deployment
  needs an atomic store compare-and-swap contract before enabling renewable live
  handles; the current contract deliberately requires one active BFF replica.
- Dropping an unfinished `current` future supplies no observation and does not
  invalidate the handle. A consumer that cancels a check must withhold delivery
  and obtain a new successful check; cancellation is not authorization evidence.
- It does not authorize evidence scope, restore conversation, erase model context,
  select diagnostic capture or change provider/memory defaults.

Swarmhole's ambient gateway and ClustEU use this boundary. Each consumer must
still verify revocation/expiry during its actual streams. A library test is not
evidence of a complete application journey or production rollout.

The [tests](../crates/oidc-bff-axum/src/session/live_login/tests.rs) include actual `EncryptedSessionStore` encryption/decryption over
`MemoryStore`, unchanged ciphertext/expiry during observation and backing deletion
despite cached request state. They do not run ClustEU's SQLite store or claim a
complete Navigator journey. Controlled-store tests assert exact lookup keys and
zero writes for the plain binding, and use explicit notifications for concurrency
ordering. The browser-flow integration test exercises refresh-token rotation,
nonce-optional refreshed ID-token validation and the unchanged local session ID.
