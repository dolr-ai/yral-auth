use std::{collections::HashMap, env, sync::Arc};

use axum::extract::FromRef;
#[cfg(feature = "apple-oauth")]
use axum::http::header::ACCEPT;
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::jwk::{self, Jwk};
use leptos::{config::LeptosOptions, prelude::expect_context};
use leptos_axum::AxumRouteListing;
use openidconnect::{
    core::CoreClient, reqwest, AuthUrl, ClientId, IssuerUrl, RedirectUrl, TokenUrl,
};

#[cfg(any(feature = "google-oauth", feature = "apple-oauth"))]
use openidconnect::core::CoreProviderMetadata;

#[cfg(feature = "google-oauth")]
use openidconnect::core::CoreJsonWebKeySet;

#[cfg(feature = "google-oauth")]
use openidconnect::ClientSecret;
use p256::pkcs8::DecodePublicKey;
#[cfg(feature = "apple-oauth")]
use p256::pkcs8::{DecodePrivateKey, EncodePublicKey};
#[cfg(feature = "apple-oauth")]
use sha2::{Digest, Sha256};

#[cfg(feature = "phone-auth")]
use crate::context::message_delivery_service::MessageDeliveryService;
use crate::{
    consts::AUTH_TOKEN_KID,
    kv::KVStoreImpl,
    oauth::{
        client_validation::ClientIdValidatorImpl, jwt::JsonWebKeySet, SupportedOAuthProviders,
    },
    oauth_provider::{OAuthProviderImpl, StdOAuthClient},
};

#[cfg(feature = "google-oauth")]
use crate::consts::GOOGLE_ISSUER_URL;

#[cfg(feature = "apple-oauth")]
use crate::consts::APPLE_ISSUER_URL;

#[cfg(feature = "google-oauth")]
use crate::oauth_provider::GoogleOAuthProvider;

#[cfg(feature = "apple-oauth")]
use crate::oauth_provider::AppleOAuthProvider;

#[derive(FromRef, Clone)]
pub struct ServerState {
    pub leptos_options: LeptosOptions,
    pub routes: Vec<AxumRouteListing>,
    pub ctx: Arc<ServerCtx>,
}

pub struct JwkPair {
    pub encoding_key: jsonwebtoken::EncodingKey,
    pub decoding_key: jsonwebtoken::DecodingKey,
}

impl JwkPair {
    fn load_encoding_key_from_env(encoding_env: &str) -> jsonwebtoken::EncodingKey {
        let jwt_pem =
            env::var(encoding_env).unwrap_or_else(|_| panic!("`{encoding_env}` is required!"));
        jsonwebtoken::EncodingKey::from_ed_pem(jwt_pem.as_bytes())
            .unwrap_or_else(|_| panic!("invalid `{encoding_env}`"))
    }

    pub fn load_from_env(encoding_env: &str, decoding_env: &str) -> Self {
        let encoding_key = Self::load_encoding_key_from_env(encoding_env);

        let jwt_pub_pem =
            env::var(decoding_env).unwrap_or_else(|_| panic!("`{decoding_env}` is required!"));
        let decoding_key = jsonwebtoken::DecodingKey::from_ed_pem(jwt_pub_pem.as_bytes())
            .unwrap_or_else(|_| panic!("invalid `{decoding_env}`"));

        Self {
            encoding_key,
            decoding_key,
        }
    }
}

pub struct JwkPairs {
    pub auth_tokens: JwkPair,
    pub client_tokens: JwkPair,
    pub well_known_jwks: JsonWebKeySet,
}

impl Default for JwkPairs {
    fn default() -> Self {
        let auth_jwt_pub_pem =
            env::var("JWT_PUB_EC_PEM").unwrap_or_else(|_| panic!("`JWT_PUB_EC_PEM` is required!"));
        let auth_jwt_ec_pub = p256::ecdsa::VerifyingKey::from_public_key_pem(&auth_jwt_pub_pem)
            .expect("Invalid `JWT_PUB_ED_PEM`");
        let auth_jwt_ec = auth_jwt_ec_pub.to_encoded_point(false);

        let auth_jwt_x = auth_jwt_ec.x().unwrap();
        let auth_jwt_x_b64 = BASE64_URL_SAFE_NO_PAD.encode(auth_jwt_x);
        let auth_jwt_y = auth_jwt_ec.y().unwrap();
        let auth_jwt_y_b64 = BASE64_URL_SAFE_NO_PAD.encode(auth_jwt_y);

        let auth_jwt_decoding_key =
            jsonwebtoken::DecodingKey::from_ec_components(&auth_jwt_x_b64, &auth_jwt_y_b64)
                .unwrap();

        let auth_jwt_decoding_jwk = Jwk {
            common: jwk::CommonParameters {
                public_key_use: Some(jwk::PublicKeyUse::Signature),
                key_algorithm: Some(jwk::KeyAlgorithm::ES256),
                key_id: Some(AUTH_TOKEN_KID.into()),
                ..Default::default()
            },
            algorithm: jwk::AlgorithmParameters::EllipticCurve(jwk::EllipticCurveKeyParameters {
                key_type: jwk::EllipticCurveKeyType::EC,
                curve: jwk::EllipticCurve::P256,
                x: auth_jwt_x_b64,
                y: auth_jwt_y_b64,
            }),
        };

        let auth_jwt_pem =
            env::var("JWT_EC_PEM").unwrap_or_else(|_| panic!("`JWT_EC_PEM` is required!"));

        Self {
            auth_tokens: JwkPair {
                encoding_key: jsonwebtoken::EncodingKey::from_ec_pem(auth_jwt_pem.as_bytes())
                    .expect("invalid `JWT_EC_PEM`"),
                decoding_key: auth_jwt_decoding_key,
            },
            client_tokens: JwkPair::load_from_env("CLIENT_JWT_ED_PEM", "CLIENT_JWT_PUB_ED_PEM"),
            well_known_jwks: JsonWebKeySet {
                keys: vec![auth_jwt_decoding_jwk],
            },
        }
    }
}

pub struct ServerCtx {
    pub oauth_http_client: reqwest::Client,
    pub oauth_providers: HashMap<SupportedOAuthProviders, OAuthProviderImpl>,
    pub cookie_key: axum_extra::extract::cookie::Key,
    pub jwk_pairs: JwkPairs,
    pub kv_store: KVStoreImpl,
    pub validator: ClientIdValidatorImpl,
    #[cfg(feature = "phone-auth")]
    pub message_delivery_service: Box<dyn MessageDeliveryService>,
}

impl ServerCtx {
    #[allow(dead_code)]
    #[cfg(any(feature = "google-oauth", feature = "apple-oauth"))]
    async fn init_oauth_client(
        client_id_env: &str,
        issuer_url: IssuerUrl,
        redirect_url: RedirectUrl,
        http_client: &reqwest::Client,
    ) -> Result<StdOAuthClient, String> {
        let client_id =
            env::var(client_id_env).unwrap_or_else(|_| panic!("`{client_id_env}` is required!"));

        let oauth_metadata = CoreProviderMetadata::discover_async(issuer_url, http_client)
            .await
            .map_err(|e| format!("Failed to discover OAuth metadata: {e}"))?;

        let client =
            CoreClient::from_provider_metadata(oauth_metadata, ClientId::new(client_id), None)
                .set_redirect_uri(redirect_url)
                .set_auth_type(openidconnect::AuthType::RequestBody);

        Ok(client)
    }

    /// Initialize Google OAuth client with JWK rotation support
    ///
    /// This creates a GoogleOAuthProvider that handles JWK rotation automatically.
    /// Google rotates their JWT signing keys regularly, and this provider respects
    /// the Cache-Control headers from Google's JWK endpoint to refresh keys appropriately.
    #[cfg(feature = "google-oauth")]
    async fn init_google_oauth_client(
        http_client: &reqwest::Client,
        oauth_providers: &mut HashMap<SupportedOAuthProviders, OAuthProviderImpl>,
    ) -> Result<(), String> {
        let google_client_secret =
            env::var("GOOGLE_CLIENT_SECRET").expect("`GOOGLE_CLIENT_SECRET` is required!");
        let client_id = env::var("GOOGLE_CLIENT_ID").expect("`GOOGLE_CLIENT_ID` is required!");

        let issuer_url = IssuerUrl::new(GOOGLE_ISSUER_URL.to_string()).unwrap();

        // Discover OAuth metadata
        let oauth_metadata = CoreProviderMetadata::discover_async(issuer_url, http_client)
            .await
            .map_err(|e| format!("Failed to discover Google OAuth metadata: {e}"))?;

        // Create OAuth client
        let google_oauth_client = CoreClient::from_provider_metadata(
            oauth_metadata.clone(),
            ClientId::new(client_id),
            None,
        )
        .set_auth_type(openidconnect::AuthType::RequestBody)
        .set_client_secret(ClientSecret::new(google_client_secret.clone()));

        // Create Google provider with JWK caching
        let google_oauth = GoogleOAuthProvider::new(
            google_oauth_client,
            oauth_metadata,
            http_client.clone(),
            google_client_secret,
        )
        .await
        .map_err(|e| format!("Failed to create Google OAuth provider: {e}"))?;

        oauth_providers.insert(SupportedOAuthProviders::Google, google_oauth.into());

        Ok(())
    }

    #[cfg(feature = "apple-oauth")]
    async fn init_apple_oauth_client(
        http_client: &reqwest::Client,
        oauth_providers: &mut HashMap<SupportedOAuthProviders, OAuthProviderImpl>,
    ) -> Result<(), String> {
        let apple_team_id = env::var("APPLE_TEAM_ID").expect("`APPLE_TEAM_ID` is required!");
        let apple_key_id = env::var("APPLE_KEY_ID").expect("`APPLE_KEY_ID` is required!");
        let apple_auth_key_pem =
            env::var("APPLE_AUTH_KEY_PEM").expect("`APPLE_AUTH_KEY_PEM` is required!");

        let apple_auth_key = jsonwebtoken::EncodingKey::from_ec_pem(apple_auth_key_pem.as_bytes())
            .expect("invalid `APPLE_AUTH_KEY_PEM`");

        let client_id = env::var("APPLE_CLIENT_ID").expect("`APPLE_CLIENT_ID` is required!");

        let iss = IssuerUrl::new(APPLE_ISSUER_URL.to_string()).unwrap();

        let well_known_url = iss.join(".well-known/openid-configuration").unwrap();

        let mut metadata = http_client
            .get(well_known_url)
            .header(ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| format!("{e}"))?
            .json::<CoreProviderMetadata>()
            .await
            .map_err(|e| format!("{e}"))?;
        let jwks = CoreJsonWebKeySet::fetch_async(metadata.jwks_uri(), http_client)
            .await
            .map_err(|e| format!("{e}"))?;

        metadata = metadata
            .set_jwks(jwks)
            .set_authorization_endpoint(
                AuthUrl::new("https://appleid.apple.com/auth/authorize".to_string()).unwrap(),
            )
            .set_token_endpoint(Some(
                TokenUrl::new("https://appleid.apple.com/auth/token".to_string()).unwrap(),
            ));

        let apple_oauth =
            CoreClient::from_provider_metadata(metadata, ClientId::new(client_id), None)
                .set_auth_type(openidconnect::AuthType::RequestBody);

        let apple_oauth =
            AppleOAuthProvider::new(apple_oauth, apple_auth_key, apple_key_id, apple_team_id);

        oauth_providers.insert(SupportedOAuthProviders::Apple, apple_oauth.into());

        Ok(())
    }

    async fn init_oauth_providers(
        http_client: &reqwest::Client,
    ) -> HashMap<SupportedOAuthProviders, OAuthProviderImpl> {
        let mut oauth_providers = HashMap::new();

        // Google OAuth
        #[cfg(feature = "google-oauth")]
        if let Err(e) = Self::init_google_oauth_client(http_client, &mut oauth_providers).await {
            log::error!("Failed to initialize Google OAuth: {e}, ignoring");
        }

        // Apple OAuth
        #[cfg(feature = "apple-oauth")]
        if let Err(e) = Self::init_apple_oauth_client(http_client, &mut oauth_providers).await {
            log::error!("Failed to initialize Apple OAuth: {e}, ignoring");
        }

        oauth_providers
    }

    fn init_cookie_key() -> axum_extra::extract::cookie::Key {
        let cookie_key_str = env::var("COOKIE_KEY").expect("`COOKIE_KEY` is required!");
        let cookie_key_raw =
            hex::decode(cookie_key_str).expect("Invalid `COOKIE_KEY` (must be length 128 hex)");
        axum_extra::extract::cookie::Key::from(&cookie_key_raw)
    }

    pub async fn init_kv_store() -> KVStoreImpl {
        #[cfg(not(feature = "redis-kv"))]
        {
            use crate::kv::redb_kv::ReDBKV;
            KVStoreImpl::ReDB(ReDBKV::new().unwrap())
        }
        #[cfg(feature = "redis-kv")]
        {
            use crate::kv::dragonfly_kv::DragonflyKV;

            log::info!("Initializing Dragonfly KV store");
            KVStoreImpl::Dragonfly(
                DragonflyKV::new()
                    .await
                    .expect("Failed to initialize RedisKV"),
            )
        }
    }

    pub async fn new() -> Self {
        let oauth_http_client = reqwest::ClientBuilder::new()
            // Following redirects opens the client up to SSRF vulnerabilities.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Client should build");

        let oauth_providers = Self::init_oauth_providers(&oauth_http_client).await;

        let cookie_key = Self::init_cookie_key();

        //dragonfly redis kv store
        let kv_store = Self::init_kv_store().await;

        #[cfg(feature = "phone-auth")]
        {
            use crate::context::message_delivery_service;

            let message_delivery_service = {
                let whatsapp_api_key = env::var("WHATSAPP_API_KEY")
                    .expect("`WHATSAPP_API_KEY` is required for phone auth!");
                Box::new(
                    message_delivery_service::WhatsAppMessageDeliveryService::new(whatsapp_api_key),
                ) as Box<dyn MessageDeliveryService>
            };

            Self {
                oauth_http_client,
                oauth_providers,
                cookie_key,
                jwk_pairs: JwkPairs::default(),
                kv_store, //dragonfly redis kv store
                validator: ClientIdValidatorImpl::Const(Default::default()),
                message_delivery_service,
            }
        }
        #[cfg(not(feature = "phone-auth"))]
        {
            Self {
                oauth_http_client,
                oauth_providers,
                cookie_key,
                jwk_pairs: JwkPairs::default(),
                kv_store,
                validator: ClientIdValidatorImpl::Const(Default::default()),
            }
        }
    }

    /// Start background JWK refresh task for OAuth providers that support it
    #[cfg(feature = "google-oauth")]
    pub fn start_jwk_refresh_task(self: &Arc<Self>) {
        // For now, we'll check Google OAuth provider and start a task that
        // calls the refresh method periodically
        if self
            .oauth_providers
            .contains_key(&SupportedOAuthProviders::Google)
        {
            let ctx = Arc::clone(self);
            let _handle = tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(5 * 60)); // 5 minutes

                loop {
                    interval.tick().await;

                    println!("JWK refresh task checking for updates...");
                    if let Some(crate::oauth_provider::OAuthProviderImpl::GoogleOAuthProvider(
                        google_provider,
                    )) = ctx.oauth_providers.get(&SupportedOAuthProviders::Google)
                    {
                        if google_provider.needs_jwk_refresh() {
                            println!("Refreshing Google OAuth JWKs...");
                            match google_provider.refresh_client_jwks().await {
                                Ok(()) => {
                                    println!("Successfully refreshed Google OAuth JWKs");
                                }
                                Err(e) => {
                                    eprintln!("Failed to refresh Google OAuth JWKs: {e}");
                                }
                            }
                        } else {
                            println!("Google OAuth JWKs are still fresh");
                        }
                    }
                }
            });
            println!("Started Google OAuth JWK refresh background task");
        } else {
            println!("No Google OAuth provider configured, skipping JWK refresh task");
        }
    }
}

pub fn expect_server_ctx() -> Arc<ServerCtx> {
    expect_context()
}
