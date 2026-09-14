# Live browser-login observations

`oidc_bff_axum::LiveBrowserLogin` is an opaque, browser-human-only handle for
long-running application operations. It binds the original persisted session ID,
subject and authentication-session ID. It does not discover a provider or accept
browser-supplied identity claims. The native caller supplies its authenticated
request, `Session`, and authoritative decrypting `SessionStore`. The trait alone
does not establish freshness: do not supply an independently stale cache or read
replica. In particular, `CachingSessionStore::load` can return a cached record
without consulting its backing store and can populate its cache on a miss.
The read-only/freshness contract requires a backing store whose `load` observes
authoritative records without extending their lifetime. ClustEU's existing
encrypted SQLite session store is the intended caller, not a second cache layer.

`bind` reads that store before returning. `current` performs a fresh `load` of the
original record on every call: cached `Session::get` data and a cloned request
session are not evidence that local logout has not occurred. Missing records,
different IDs/subjects/logins, corruption, expired deadlines and unavailable
storage fail closed. A failed check invalidates the handle and all its clones;
recovering storage requires a new authenticated request/handle, not resuming an
uncertain stream automatically.

Both the persisted inactivity deadline and private absolute authentication
deadline must remain live. The absolute deadline is pinned when binding, so an
existing handle cannot gain time from a subsequently lengthened stored deadline.
Other legitimate foreground activity can change the persisted inactivity expiry,
but these observations never write, save, flush, renew, extend expiry or log out.
In particular, they do not calculate `now + inactivity duration` as a new deadline.

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

- This detects local deletion/logout and local deadlines when sampled. It does
  not implement immediate identity-provider revocation, token introspection,
  back-channel logout or bearer-token lifetime monitoring.
- A successful read is not atomic with later delivery. A timer driven by a polled
  response stream is not an independent watchdog for a backpressured reader.
- Once this handle observes failure it stays invalid, including across clones.
  This does not prevent every stale concurrent writer from resurrecting a deleted
  session between observations. That would require a separately designed store
  generation/tombstone contract.
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
zero observation writes, and use explicit notifications for concurrency ordering.
