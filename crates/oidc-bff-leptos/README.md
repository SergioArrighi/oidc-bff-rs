# oidc-bff-leptos

`oidc-bff-leptos` provides an SSR-safe Leptos client and identity gate for the
same-origin session API exposed by
[`oidc-bff-axum`](https://docs.rs/oidc-bff-axum).

The browser receives only the bounded `IdentitySession` projection. OAuth
access tokens, refresh tokens, ID tokens, and server-side session credentials
remain outside browser storage.

Session and logout responses are capped at 64 KiB and validated through the
bounded core wire types before they enter reactive UI state.

## Components

- `IdentityGate` renders loading, anonymous, authenticated, and failed states.
- `IdentityProfileMenu` renders the authenticated display name, account link,
  and anti-forgery-protected sign-out action.
- `IdentityContext` allows descendants to inspect or refresh session state and
  obtain the anti-forgery token for unsafe same-origin API requests.
- `IdentityClient` can target custom session and logout paths.

```rust,ignore
use leptos::prelude::*;
use oidc_bff_leptos::{IdentityGate, IdentityProfileMenu};

#[component]
fn Application() -> impl IntoView {
    view! {
        <IdentityGate>
            <header><IdentityProfileMenu /></header>
            <main>"Authenticated application"</main>
        </IdentityGate>
    }
}
```

The components intentionally ship without a visual stylesheet. Applications
own the `.identity-state` and `.identity-profile` presentation while retaining
the component's semantic and accessible structure.

The default client expects `/auth/session` and `/auth/logout`. Sign-in uses
`/auth/login?return_to=...` on the current origin.

Licensed under the MIT License.
