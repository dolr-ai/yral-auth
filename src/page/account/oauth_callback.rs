use leptos::either::Either;
use leptos::prelude::*;
use leptos_router::{components::Redirect, hooks::use_query, params::Params};

use crate::components::spinner::Spinner;

#[derive(Debug, Clone, PartialEq, Params)]
struct CallbackQuery {
    code: Option<String>,
    error: Option<String>,
}

/// Completes the OAuth login by decoding the auth code JWT and storing
/// the principal in an encrypted session cookie.
#[server(endpoint = "complete_account_login")]
pub async fn complete_account_login(code: String) -> Result<(), ServerFnError> {
    #[cfg(feature = "ssr")]
    {
        use crate::api::delete_account::complete_account_login_impl;
        complete_account_login_impl(code).await
    }
    #[cfg(not(feature = "ssr"))]
    {
        Ok(())
    }
}

#[component]
pub fn OauthCallbackPage() -> impl IntoView {
    let query = use_query::<CallbackQuery>();

    let result = Resource::new(
        move || query.get(),
        async move |query| {
            let query = match query {
                Ok(q) => q,
                Err(_) => return "Invalid callback parameters".to_string(),
            };

            if let Some(error) = query.error {
                return format!("Login error: {error}");
            }

            let Some(code) = query.code else {
                return "Missing authorization code".to_string();
            };

            match complete_account_login(code).await {
                Ok(_) => String::new(),
                Err(e) => format!("Failed to complete login: {e}"),
            }
        },
    );

    view! {
        <div class="flex min-h-dvh w-dvw items-center justify-center bg-neutral-900">
            <Suspense fallback=move || view! { <Spinner /> }>
                {move || Suspend::new(async move {
                    let res = result.await;
                    if res.is_empty() {
                        Either::Left(view! { <Redirect path="/account" /> })
                    } else {
                        Either::Right(view! {
                            <div class="flex flex-col items-center gap-4 px-8 text-center">
                                <h1 class="text-xl font-bold text-white">"Login Failed"</h1>
                                <p class="text-sm text-neutral-400">{res}</p>
                                <a
                                    href="/account"
                                    class="mt-4 rounded-md bg-primary-600 px-6 py-2 text-sm font-semibold text-white hover:bg-primary-700"
                                >
                                    "Back to login"
                                </a>
                            </div>
                        })
                    }
                })}
            </Suspense>
        </div>
    }
}