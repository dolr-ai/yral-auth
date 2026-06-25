use std::sync::Arc;

use axum_extra::extract::{
    cookie::{Cookie, SameSite},
    PrivateCookieJar,
};
use candid::Principal;
use ic_agent::{
    identity::{Delegation, Secp256k1Identity, SignedDelegation},
    Identity,
};
use leptos::prelude::*;
use leptos_axum::extract_with_state;
use serde::{Deserialize, Serialize};
use web_time::Duration;
use yral_types::delegated_identity::DelegatedIdentityWire;

use crate::{
    consts::OFF_CHAIN_AGENT_URL,
    context::server::{expect_server_ctx, ServerCtx},
    kv::{
        dragonfly_kv::{format_to_dragonfly_key, KEY_PREFIX},
        KVStore,
    },
    utils::time::current_epoch,
};

/// Cookie name for the delete-account session (stores the user's principal text).
pub const DELETE_ACCOUNT_SESSION_COOKIE: &str = "delete-account-session";

/// Cookie max age: 10 minutes (enough time for the user to confirm deletion).
const SESSION_COOKIE_MAX_AGE: Duration = Duration::from_secs(10 * 60);

/// Delegation max age for the delete-request identity: 10 minutes.
const DELETE_DELEGATION_MAX_AGE: Duration = Duration::from_secs(10 * 60);

/// Self-service OAuth client ID (registered in the whitelist).
pub const SELF_SERVICE_CLIENT_ID: &str = "7a2f3b8c-1d4e-4f5a-9b6c-7d8e9f0a1b2c";

// ---------------------------------------------------------------------------
// Session cookie helpers (SSR only)
// ---------------------------------------------------------------------------

/// Reads the authenticated principal from the encrypted session cookie.
#[cfg(feature = "ssr")]
async fn read_session_principal() -> Result<Option<Principal>, ServerFnError> {
    let ctx = expect_server_ctx();
    let jar: PrivateCookieJar = extract_with_state(&ctx.cookie_key)
        .await
        .map_err(|e| ServerFnError::new(format!("Failed to extract cookie jar: {e:?}")))?;

    let principal_str = jar
        .get(DELETE_ACCOUNT_SESSION_COOKIE)
        .map(|c| c.value().to_string());
    match principal_str {
        Some(s) => {
            let principal = Principal::from_text(&s)
                .map_err(|_| ServerFnError::new("Invalid principal in session cookie"))?;
            Ok(Some(principal))
        }
        None => Ok(None),
    }
}

/// Stores the principal in the encrypted session cookie.
#[cfg(feature = "ssr")]
async fn set_session_principal(principal: &Principal) -> Result<(), ServerFnError> {
    use axum::http::header;

    let ctx = expect_server_ctx();
    let jar: PrivateCookieJar = extract_with_state(&ctx.cookie_key)
        .await
        .map_err(|e| ServerFnError::new(format!("Failed to extract cookie jar: {e:?}")))?;

    let cookie_life: axum_extra::extract::cookie::time::Duration =
        SESSION_COOKIE_MAX_AGE.try_into().unwrap();
    let cookie = Cookie::build((DELETE_ACCOUNT_SESSION_COOKIE, principal.to_text()))
        .same_site(SameSite::Lax)
        .secure(true)
        .path("/")
        .max_age(cookie_life)
        .http_only(true)
        .build();

    let jar = jar.add(cookie);
    let resp: ResponseOptions = expect_context();
    let resp_jar = jar.into_response();
    for cookie in resp_jar
        .headers()
        .get_all(header::SET_COOKIE)
        .into_iter()
        .cloned()
    {
        resp.append_header(header::SET_COOKIE, cookie);
    }
    Ok(())
}

/// Clears the session cookie.
#[cfg(feature = "ssr")]
async fn clear_session_principal() -> Result<(), ServerFnError> {
    use axum::http::header;

    let ctx = expect_server_ctx();
    let jar: PrivateCookieJar = extract_with_state(&ctx.cookie_key)
        .await
        .map_err(|e| ServerFnError::new(format!("Failed to extract cookie jar: {e:?}")))?;

    let jar = jar.remove(DELETE_ACCOUNT_SESSION_COOKIE);
    let resp: ResponseOptions = expect_context();
    let resp_jar = jar.into_response();
    for cookie in resp_jar
        .headers()
        .get_all(header::SET_COOKIE)
        .into_iter()
        .cloned()
    {
        resp.append_header(header::SET_COOKIE, cookie);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Delegated identity creation (SSR only)
// ---------------------------------------------------------------------------

/// Creates a short-lived `DelegatedIdentityWire` from the user's root secret key.
/// This delegated identity is sent to the off-chain agent to authenticate the
/// delete request (the agent uses `identity.sender()` to identify the user and
/// signs IC canister calls with the delegated identity).
#[cfg(feature = "ssr")]
fn create_delegated_identity(
    secret_key: &k256::SecretKey,
    max_age: Duration,
) -> DelegatedIdentityWire {
    let from_identity = Secp256k1Identity::from_private_key(secret_key.clone());

    let to_secret = k256::SecretKey::random(&mut rand::rngs::OsRng);
    let to_secret_jwk = to_secret.to_jwk();
    let to_identity = Secp256k1Identity::from_private_key(to_secret);

    let expiry = current_epoch() + max_age;
    let delegation = Delegation {
        pubkey: to_identity.public_key().unwrap(),
        expiration: expiry.as_nanos() as u64,
        targets: None,
    };

    let sig = from_identity.sign_delegation(&delegation).unwrap();
    let signed_delegation = SignedDelegation {
        delegation,
        signature: sig.signature.unwrap(),
    };

    DelegatedIdentityWire {
        from_key: sig.public_key.unwrap(),
        to_secret: to_secret_jwk,
        delegation_chain: vec![signed_delegation],
    }
}

// ---------------------------------------------------------------------------
// Server functions
// ---------------------------------------------------------------------------

/// Returns the authenticated principal from the session cookie, if any.
/// Used by the page to determine whether to show the login or confirmation UI.
#[server(endpoint = "get_delete_account_session")]
pub async fn get_delete_account_session() -> Result<Option<String>, ServerFnError> {
    #[cfg(feature = "ssr")]
    {
        let principal = read_session_principal().await?;
        Ok(principal.map(|p| p.to_text()))
    }
    #[cfg(not(feature = "ssr"))]
    {
        Ok(None)
    }
}

/// Completes the OAuth login by decoding the auth code JWT and storing
/// the principal in an encrypted session cookie.
///
/// Called from the `/account/callback` page after the OAuth flow
/// redirects back with a `code` parameter.
#[server(endpoint = "complete_account_login")]
pub async fn complete_account_login(code: String) -> Result<(), ServerFnError> {
    #[cfg(feature = "ssr")]
    {
        use crate::oauth::jwt::AuthCodeClaims;

        let ctx = expect_server_ctx();

        // Decode the auth code JWT. This JWT was generated by our own
        // `generate_code_grant_jwt` during the OAuth callback flow.
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.set_audience(&[SELF_SERVICE_CLIENT_ID]);
        validation.set_issuer(&["https://auth.yral.com", "https://auth.dolr.ai"]);

        let auth_code = jsonwebtoken::decode::<AuthCodeClaims>(
            &code,
            &ctx.jwk_pairs.auth_tokens.decoding_key,
            &validation,
        )
        .map_err(|e| ServerFnError::new(format!("Failed to decode auth code: {e}")))?;

        let principal = auth_code.claims.sub;

        // Store the principal in the session cookie
        set_session_principal(&principal).await?;

        Ok(())
    }
    #[cfg(not(feature = "ssr"))]
    {
        Ok(())
    }
}

/// Clears the session cookie (sign out).
#[server(endpoint = "sign_out")]
pub async fn sign_out() -> Result<(), ServerFnError> {
    #[cfg(feature = "ssr")]
    {
        clear_session_principal().await?;
    }
    #[cfg(not(feature = "ssr"))]
    {
        let _ = ();
    }
    Ok(())
}

/// Deletes the user's account.
///
/// Reads the principal from the session cookie, looks up the root identity
/// in KV, creates a short-lived delegated identity, and calls the off-chain
/// agent's `DELETE /api/v1/user` endpoint.
#[server(endpoint = "delete_account", input = Json, output = Json)]
pub async fn delete_account() -> Result<(), ServerFnError> {
    #[cfg(feature = "ssr")]
    {
        let ctx = expect_context::<Arc<ServerCtx>>();

        // 1. Read the principal from the session cookie
        let principal = read_session_principal()
            .await?
            .ok_or_else(|| ServerFnError::new("Not authenticated"))?;

        // 2. Look up the root identity secret key in KV
        let identity_jwk = ctx
            .kv_store
            .read(format_to_dragonfly_key(
                KEY_PREFIX,
                &principal.to_text(),
            ))
            .await
            .map_err(|e| ServerFnError::new(format!("KV error: {e}")))?
            .ok_or_else(|| ServerFnError::new("User not found"))?;

        let sk = k256::SecretKey::from_jwk_str(&identity_jwk)
            .map_err(|_| ServerFnError::new("Invalid identity in store"))?;

        // 3. Create a short-lived delegated identity
        let delegated_identity = create_delegated_identity(&sk, DELETE_DELEGATION_MAX_AGE);

        // 4. Call the off-chain agent's delete endpoint
        let client = reqwest::Client::new();
        let body = serde_json::json!({
            "delegated_identity_wire": delegated_identity
        });

        let url = OFF_CHAIN_AGENT_URL.join("api/v1/user").unwrap();

        let response = client
            .delete(url)
            .json(&body)
            .send()
            .await
            .map_err(|e| ServerFnError::new(format!("Failed to call delete API: {e}")))?;

        if response.status().is_success() {
            // 5. Clear the session cookie
            clear_session_principal().await?;
            Ok(())
        } else {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(ServerFnError::new(format!(
                "Delete user failed with status {status}: {body}"
            )))
        }
    }
    #[cfg(not(feature = "ssr"))]
    {
        Ok(())
    }
}