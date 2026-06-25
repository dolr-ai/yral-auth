use leptos::prelude::*;
use leptos_router::{components::Redirect, hooks::use_query, params::Params};
use serde::Deserialize;

use crate::api::delete_account::complete_account_login;
use crate::components::spinner::Spinner;

#[derive(Debug, Clone, Deserialize, PartialEq)]
struct CallbackQuery {
    code: Option<String>,
    error: Option<String>,
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
                Ok(_) => String::new(), // success — empty string signals redirect
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
                        view! { <Redirect path="/account" /> }
                    } else {
                        view! {
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
                        }
                    }
                })}
            </Suspense>
        </div>
    }
}