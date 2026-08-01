use leptos::prelude::*;
use oidc_bff_core::{AuthenticationStatus, IdentitySession};
use wasm_bindgen_futures::spawn_local;
use web_sys::js_sys;

use crate::IdentityClient;

#[derive(Clone, Debug, PartialEq)]
/// Reactive state exposed while resolving and maintaining browser identity.
pub enum IdentityGateState {
    /// The same-origin session request is in progress.
    Loading,
    /// No authenticated server-side session exists.
    Anonymous(IdentitySession),
    /// A valid server-side session exists.
    Authenticated(IdentitySession),
    /// The identity boundary could not be reached or returned invalid data.
    Failed(String),
}

#[derive(Clone, Copy)]
/// Leptos context supplied to descendants of [`IdentityGate`].
pub struct IdentityContext {
    state: ReadSignal<IdentityGateState>,
    refresh: Callback<()>,
    logout: Callback<IdentitySession>,
}

impl IdentityContext {
    /// Returns the current reactive identity state.
    pub fn state(&self) -> IdentityGateState {
        self.state.get()
    }

    /// Reloads session state from the same-origin BFF.
    pub fn refresh(&self) {
        self.refresh.run(());
    }

    /// Revokes an authenticated session and follows the logout redirect.
    pub fn logout(&self, session: IdentitySession) {
        self.logout.run(session);
    }

    /// Returns the current per-session token for unsafe same-origin requests.
    pub fn anti_forgery_token(&self) -> Option<String> {
        match self.state() {
            IdentityGateState::Authenticated(session) => session.anti_forgery_token,
            _ => None,
        }
    }
}

#[derive(Clone)]
struct IdentityGateController {
    client: IdentityClient,
    state: RwSignal<IdentityGateState>,
}

impl IdentityGateController {
    fn refresh(&self) {
        let controller = self.clone();
        controller.state.set(IdentityGateState::Loading);
        spawn_local(async move {
            let state = match controller.client.session().await {
                Ok(session) if session.status == AuthenticationStatus::Authenticated => {
                    IdentityGateState::Authenticated(session)
                }
                Ok(session) => IdentityGateState::Anonymous(session),
                Err(problem) => IdentityGateState::Failed(problem.to_string()),
            };
            controller.state.set(state);
        });
    }

    fn begin_sign_in(&self, path: &str) {
        let return_to = js_sys::encode_uri_component(path);
        let destination = format!("/auth/login?return_to={return_to}");
        if let Some(window) = web_sys::window() {
            let _ = window.location().assign(&destination);
        }
    }

    fn logout(&self, session: &IdentitySession) {
        let Some(anti_forgery_token) = session.anti_forgery_token.clone() else {
            self.state.set(IdentityGateState::Failed(
                "The authenticated session has no anti-forgery token".to_owned(),
            ));
            return;
        };
        let controller = self.clone();
        spawn_local(async move {
            match controller.client.logout(&anti_forgery_token).await {
                Ok(logout) => {
                    if let Some(window) = web_sys::window() {
                        let _ = window.location().assign(&logout.redirect_to);
                    }
                }
                Err(problem) => controller
                    .state
                    .set(IdentityGateState::Failed(problem.to_string())),
            }
        });
    }
}

#[component]
/// Gates child rendering on a valid authenticated server-side identity session.
pub fn IdentityGate(children: ChildrenFn) -> impl IntoView {
    let state = RwSignal::new(IdentityGateState::Loading);
    let controller = IdentityGateController {
        client: IdentityClient::default(),
        state,
    };
    let refresh_controller = controller.clone();
    let refresh = Callback::new(move |_: ()| refresh_controller.refresh());
    let logout_controller = controller.clone();
    let logout = Callback::new(move |session: IdentitySession| {
        logout_controller.logout(&session);
    });
    provide_context(IdentityContext {
        state: state.read_only(),
        refresh,
        logout,
    });
    controller.refresh();

    view! {
        {move || match state.get() {
            IdentityGateState::Loading => view! {
                <main class="identity-state identity-state--loading" aria-busy="true">
                    <p role="status">"Checking your session…"</p>
                </main>
            }.into_any(),
            IdentityGateState::Anonymous(session) => {
                let controller = controller.clone();
                let return_path = BrowserReturnLocation::current().path;
                view! {
                    <main class="identity-state identity-state--anonymous">
                        <section aria-labelledby="identity-sign-in-title">
                            <p class="eyebrow">"Secure workspace"</p>
                            <h1 id="identity-sign-in-title">"Sign in to continue"</h1>
                            <p>"Your credentials stay with the configured identity provider."</p>
                            <button
                                class="button button--primary"
                                type="button"
                                on:click=move |_| controller.begin_sign_in(&return_path)
                            >"Sign in"</button>
                            <a href=session.account_url>"Create or manage an account"</a>
                        </section>
                    </main>
                }.into_any()
            },
            IdentityGateState::Authenticated(_) => children().into_any(),
            IdentityGateState::Failed(problem) => {
                let controller = controller.clone();
                view! {
                    <main class="identity-state identity-state--failed">
                        <section role="alert" aria-labelledby="identity-error-title">
                            <p class="eyebrow">"Identity unavailable"</p>
                            <h1 id="identity-error-title">"We could not verify your session"</h1>
                            <p>{problem}</p>
                            <button type="button" on:click=move |_| controller.refresh()>
                                "Try again"
                            </button>
                        </section>
                    </main>
                }.into_any()
            },
        }}
    }
}

#[component]
/// Renders the authenticated display name, account link, and sign-out action.
pub fn IdentityProfileMenu() -> impl IntoView {
    let context = expect_context::<IdentityContext>();
    view! {
        {move || match context.state() {
            IdentityGateState::Authenticated(session) => {
                let display_name = session.profile.as_ref()
                    .map(|profile| profile.display_name.clone())
                    .unwrap_or_else(|| "Signed-in user".to_owned());
                let account_url = session.account_url.clone();
                let logout_session = session.clone();
                view! {
                    <div class="identity-profile">
                        <span>{display_name}</span>
                        <a href=account_url>"Profile"</a>
                        <button
                            type="button"
                            on:click=move |_| context.logout(logout_session.clone())
                        >"Sign out"</button>
                    </div>
                }.into_any()
            },
            _ => ().into_any(),
        }}
    }
}

struct BrowserReturnLocation {
    path: String,
}

impl BrowserReturnLocation {
    fn current() -> Self {
        let path = web_sys::window()
            .and_then(|window| {
                let location = window.location();
                let pathname = location.pathname().ok()?;
                let search = location.search().unwrap_or_default();
                Some(format!("{pathname}{search}"))
            })
            .unwrap_or_else(|| "/".to_owned());
        Self { path }
    }
}
