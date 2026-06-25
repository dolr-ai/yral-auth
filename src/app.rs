use leptos::prelude::*;
use leptos_meta::{provide_meta_context, HashedStylesheet, MetaTags, Title};
use leptos_router::{
    components::{Route, Router, Routes},
    path,
};

use crate::{
    context::provide_client_id_validator,
    page::{
        account::{oauth_callback::OauthCallbackPage, page::AccountPage},
        auth::AuthPage,
        error_page::ErrorPage,
        oauth_login::{oauth_callback::OAuthCallbackPage, oauth_redirector::OAuthRedirectorPage},
    },
};

#[cfg(feature = "phone-auth")]
use crate::page::oauth_login::{
    phone_auth_login::PhoneAuthLogin, verify_phone_auth::VerifyPhoneAuth,
};

pub fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1" />
                <AutoReload options=options.clone() />
                <HydrationScripts options=options.clone() />
                // injects a stylesheet into the document <head>
                // id=leptos means cargo-leptos will hot-reload this stylesheet
                <HashedStylesheet options=options id="leptos" />
                <MetaTags />
            </head>
            <body>
                <App />
            </body>
        </html>
    }
}

#[component]
pub fn App() -> impl IntoView {
    // Provides context that manages stylesheets, titles, meta tags, etc.
    provide_meta_context();
    provide_client_id_validator();

    view! {
        // sets the document title
        <Title text="Yral Authentication" />

        // content for this welcome page
        <Router>
            <main>
                <Routes fallback=|| "Page not found.".into_view()>
                    <Route path=path!("/account") view=AccountPage />
                    <Route path=path!("/account/callback") view=OauthCallbackPage />
                    <Route path=path!("/oauth/auth") view=AuthPage />
                    <Route path=path!("/oauth_redirector") view=OAuthRedirectorPage />
                    <Route path=path!("/oauth_callback") view=OAuthCallbackPage />
                    <Route
                        path=path!("/phone/verify")
                        view=|| {
                            #[cfg(feature = "phone-auth")]
                            {
                                view! { <VerifyPhoneAuth /> }
                            }
                            #[cfg(not(feature = "phone-auth"))]
                            {
                                view! { <ErrorPage /> }
                            }
                        }
                    />
                    <Route
                        path=path!("/phone/auth")
                        view=|| {
                            #[cfg(feature = "phone-auth")]
                            {
                                view! { <PhoneAuthLogin /> }
                            }
                            #[cfg(not(feature = "phone-auth"))]
                            {
                                view! { <ErrorPage /> }
                            }
                        }
                    />
                    <Route path=path!("/error") view=ErrorPage />
                </Routes>
            </main>
        </Router>
    }
}
