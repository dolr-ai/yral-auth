use std::collections::HashMap;

use super::{OAuthClient, OAuthClientType};

macro_rules! whitelist {
    ($hm:ident, ) => {};
    ($hm:ident,{ $id:literal, [$($redirect_url:literal),*], $client_type:expr }, $($tail:tt)*) => {
        let client = OAuthClient {
            client_id: $id.to_string(),
            redirect_urls: vec![$($redirect_url.parse().unwrap()),*],
            client_type: $client_type,
        };
        $hm.insert(client.client_id.clone(), client);
        whitelist!($hm, $($tail)*);
    };
}

pub fn default_oauth_clients() -> HashMap<String, OAuthClient> {
    let mut oauth_clients = HashMap::new();
    whitelist! {
        oauth_clients,
        // Local testing
        {
            "31122c67-4801-4e70-82f0-08e12daa4f2d",
            ["https://localhost:3000"],
            OAuthClientType::Web
        },
        // Yral IOS
        {
            "e1a6a7fb-8a1d-42dc-87b4-13ff94ecbe34",
            ["com.yral.iosApp://oauth/callback", "com.yral.iosApp.staging://oauth/callback"],
            OAuthClientType::Native
        },
        // Yral Next.js
        {
            "6a0101eb-8496-4afb-ba48-425187c3a30d",
            [
                "https://pumpdump.wtf/api/oauth/callback",
                "https://pd.dev/api/oauth/callback",
                "http://localhost:5190/api/oauth/callback",
                "https://pump-dump-kit.fly.dev/api/oauth/callback"
            ],
            OAuthClientType::Web
        },
        // Yral Android
        {
            "c89b29de-8366-4e62-9b9e-c29585740acf",
            ["yral://oauth/callback"],
            OAuthClientType::Native
        },
        // Yral Previews
        {
            "5c86a459-493d-463e-965d-be6ed74f3e5f",
            [],
            OAuthClientType::Preview
        },
        // Yral & Yral Staging
        {
            "4ec00561-91bb-4e60-9743-8bed684145ba",
            [
                "https://legacy.yral.com/auth/google_redirect",
                "https://hot-or-not-web-leptos-ssr-staging.fly.dev/auth/google_redirect"
            ],
            OAuthClientType::Web
        },
        // Off-chain agent
        {
            "02c8a862-5696-4f36-b0e7-c39edd4f34ea",
            [],
            OAuthClientType::BackendService
        },
        // Yral SSR Backend
        {
            "f3a7872f-55f9-4ca7-8fec-9a5d20356248",
            [],
            OAuthClientType::BackendService
        },
        // EstateDAO
        {
            "ada497c8-f8e1-4ab8-b3b1-f2b873357f5f",
            [
                "http://localhost:3002/auth/callback",
                "https://nofeebooking.com/auth/callback",
                "https://estatefe.fly.dev/auth/callback"
            ],
            OAuthClientType::Web
        },
        // Self-service account management (auth.yral.com)
        {
            "7a2f3b8c-1d4e-4f5a-9b6c-7d8e9f0a1b2c",
            [
                "https://auth.yral.com/account/callback",
                "https://auth.dolr.ai/account/callback",
                "http://localhost:3000/account/callback"
            ],
            OAuthClientType::Web
        },
    };

    oauth_clients
}
