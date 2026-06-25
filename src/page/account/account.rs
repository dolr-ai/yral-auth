use leptos::either::Either;
use leptos::prelude::*;
use leptos_router::components::Redirect;

use crate::api::delete_account::{
    delete_account, get_delete_account_session, sign_out, SELF_SERVICE_CLIENT_ID,
};
use crate::components::{spinner::Spinner, yral_symbol::YralSymbol};
use crate::oauth::SupportedOAuthProviders;

/// Generates the OAuth redirect URL for self-service login.
/// The user is sent through the standard `/oauth/auth` flow with our
/// self-service client_id and a redirect back to `/account/callback`.
fn oauth_login_url(provider: SupportedOAuthProviders) -> String {
    use base64::{prelude::BASE64_URL_SAFE, Engine};

    // We use a fixed PKCE challenge (32 zero bytes) since we decode the
    // auth code JWT directly rather than doing a full token exchange.
    // The challenge is required by the AuthQuery struct but the verifier
    // is never checked in our self-service callback flow.
    let code_challenge = BASE64_URL_SAFE.encode([0u8; 32]);

    // Generate a random state from the current time (good enough for CSRF).
    let state = format!(
        "{}",
        web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );

    // Build the URL using url::Url for proper query encoding.
    let mut url = url::Url::parse("https://auth.yral.com/oauth/auth").unwrap();
    {
        let mut query = url.query_pairs_mut();
        query
            .append_pair("response_type", "code")
            .append_pair("client_id", SELF_SERVICE_CLIENT_ID)
            .append_pair(
                "redirect_uri",
                "https://auth.yral.com/account/callback",
            )
            .append_pair("code_challenge", &code_challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("state", &state)
            .append_pair("provider", &provider.to_string());
    }

    // Convert to a relative path (strip the origin) so it works regardless
    // of whether we're on localhost or production.
    url.path_and_query()
        .map(|pq| pq.to_string())
        .unwrap_or_else(|| format!("/oauth/auth?client_id={SELF_SERVICE_CLIENT_ID}"))
}

#[component]
fn GoogleLoginButton() -> impl IntoView {
    let url = oauth_login_url(SupportedOAuthProviders::Google);

    view! {
        <a
            href=url
            class="flex flex-row justify-center cursor-pointer items-center justify-between gap-3 rounded-full bg-white pr-6 pl-2 py-2 hover:bg-neutral-200 transition-colors"
        >
            <div class="grid grid-cols-1 place-items-center">
                <svg class="w-5 h-5" viewBox="0 0 24 24">
                    <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                    <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                    <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                    <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                </svg>
            </div>
            <span class="text-gray-800 font-medium text-sm">Sign in with Google</span>
        </a>
    }
}

#[component]
fn DeleteAccountPopup(show_popup: RwSignal<bool>) -> impl IntoView {
    let (is_deleting, set_is_deleting) = signal(false);
    let (error_msg, set_error_msg) = signal(None::<String>);
    let (success, set_success) = signal(false);

    let handle_delete = Action::new(move |&()| {
        set_is_deleting(true);
        set_error_msg.set(None);
        async move {
            match delete_account().await {
                Ok(_) => {
                    set_is_deleting(false);
                    set_success.set(true);
                }
                Err(e) => {
                    set_is_deleting(false);
                    set_error_msg.set(Some(e.to_string()));
                }
            }
        }
    });

    view! {
        <Show when=move || show_popup.get() fallback=|| ()>
            <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
                <div class="relative w-full max-w-md rounded-lg bg-neutral-900 p-6 text-white mx-4">
                    <button
                        on:click=move |_| show_popup.set(false)
                        class="absolute top-4 right-4 flex items-center justify-center size-6 rounded-full bg-neutral-600 text-white hover:bg-neutral-700"
                        disabled=move || is_deleting.get()
                    >
                        <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="18" y1="6" x2="6" y2="18" />
                            <line x1="6" y1="6" x2="18" y2="18" />
                        </svg>
                    </button>

                    <Show
                        when=move || success.get()
                        fallback=move || view! {
                            <h2 class="mb-4 text-center text-lg font-bold">"Delete your account"</h2>
                            <p class="mb-6 text-center text-sm text-neutral-300">
                                <span class="font-medium">"Are you sure you want to delete your account?"</span>
                                <br/><br/>
                                "This action is permanent and cannot be undone."
                                <br/><br/>
                                "All your data — including your Bitcoin and token balances — will be permanently removed from the platform."
                            </p>

                            {move || error_msg.get().map(|e| view! {
                                <div class="mb-4 rounded-md bg-red-900/50 border border-red-700 px-4 py-2 text-sm text-red-200">
                                    {e}
                                </div>
                            })}

                            <div class="flex justify-center gap-4">
                                <button
                                    class="flex-1 rounded-md bg-neutral-700 px-4 py-2 text-sm text-white hover:bg-neutral-600 disabled:opacity-50"
                                    on:click=move |_| show_popup.set(false)
                                    disabled=move || is_deleting.get()
                                >
                                    "No, take me back"
                                </button>
                                <button
                                    class="flex flex-1 items-center justify-center gap-2 rounded-md bg-red-600 px-4 py-2 text-sm font-semibold text-white hover:bg-red-700 disabled:opacity-50"
                                    on:click=move |_| handle_delete.dispatch(())
                                    disabled=move || is_deleting.get()
                                >
                                    <Show
                                        when=move || is_deleting.get()
                                        fallback=|| "Yes, Delete"
                                    >
                                        <div class="h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent"></div>
                                        "Deleting..."
                                    </Show>
                                </button>
                            </div>
                        }
                    >
                        <div class="text-center">
                            <h2 class="mb-4 text-lg font-bold text-green-400">"Account Deleted"</h2>
                            <p class="mb-6 text-sm text-neutral-300">
                                "Your account has been permanently deleted."
                            </p>
                            <button
                                class="rounded-md bg-primary-600 px-6 py-2 text-sm font-semibold text-white hover:bg-primary-700"
                                on:click=move |_| {
                                    show_popup.set(false);
                                    // Reload the page to go back to the login screen
                                    let nav = leptos_router::hooks::use_navigate();
                                    nav("/account", Default::default());
                                }
                            >
                                "Done"
                            </button>
                        </div>
                    </Show>
                </div>
            </div>
        </Show>
    }
}

#[component]
fn AuthenticatedContent(principal: String) -> impl IntoView {
    let show_popup = RwSignal::new(false);
    let sign_out_action = Action::new(move |&()| async move {
        sign_out().await.ok();
        let nav = leptos_router::hooks::use_navigate();
        nav("/account", Default::default());
    });

    view! {
        <div class="flex flex-col items-center gap-8 text-white">
            <div class="flex flex-col items-center gap-2">
                <div class="flex h-16 w-16 items-center justify-center rounded-full bg-green-600/20 border-2 border-green-600">
                    <svg class="w-8 h-8 text-green-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M20 6L9 17l-5-5" />
                    </svg>
                </div>
                <span class="text-sm text-neutral-400">"Signed in as"</span>
                <span class="text-xs font-mono text-neutral-500 break-all max-w-xs">{principal}</span>
            </div>

            <div class="flex flex-col gap-3 w-full max-w-sm">
                <button
                    class="flex items-center justify-between rounded-lg bg-neutral-800 px-5 py-4 text-left hover:bg-neutral-700 transition-colors"
                    on:click=move |_| show_popup.set(true)
                >
                    <div class="flex items-center gap-3">
                        <svg class="w-5 h-5 text-red-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
                        </svg>
                        <span class="text-sm font-medium">"Delete account"</span>
                    </div>
                    <svg class="w-4 h-4 text-neutral-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="9 18 15 12 9 6" />
                    </svg>
                </button>

                <button
                    class="flex items-center justify-between rounded-lg bg-neutral-800 px-5 py-4 text-left hover:bg-neutral-700 transition-colors"
                    on:click=move |_| sign_out_action.dispatch(())
                    disabled=move || sign_out_action.pending().get()
                >
                    <div class="flex items-center gap-3">
                        <svg class="w-5 h-5 text-neutral-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9" />
                        </svg>
                        <span class="text-sm font-medium">"Sign out"</span>
                    </div>
                </button>
            </div>
        </div>

        <DeleteAccountPopup show_popup />
    }
}

#[component]
pub fn AccountPage() -> impl IntoView {
    let session = Resource::new(
        || (),
        async move |_| get_delete_account_session().await.unwrap_or(None),
    );

    view! {
        <div class="flex min-h-dvh w-dvw flex-col items-center justify-center bg-neutral-900 px-4">
            <Suspense fallback=move || view! {
                <div class="flex min-h-dvh w-dvw items-center justify-center bg-neutral-900">
                    <Spinner />
                </div>
            }>
                {move || Suspend::new(async move {
                    let principal = session.await;
                    view! {
                        <div class="flex w-full max-w-sm flex-col items-center gap-8">
                            <YralSymbol class="mb-2 rounded-full text-7xl" />

                            {match principal {
                                Some(p) => Either::Left(view! { <AuthenticatedContent principal=p /> }),
                                None => Either::Right(view! {
                                    <div class="flex flex-col items-center gap-6 w-full">
                                        <div class="text-center">
                                            <h1 class="text-2xl font-bold text-white mb-2">"Yral Account"</h1>
                                            <p class="text-sm text-neutral-400">"Sign in to manage your account"</p>
                                        </div>
                                        <GoogleLoginButton />
                                    </div>
                                }),
                            }}
                        </div>
                    }
                })}
            </Suspense>
        </div>
    }
}