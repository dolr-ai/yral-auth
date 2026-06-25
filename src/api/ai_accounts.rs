use crate::{
    api::ai_accounts::server_fn::codec::Json,
    kv::dragonfly_kv::{format_to_dragonfly_key, KEY_PREFIX},
};
#[cfg(feature = "ssr")]
use crate::{context::server::ServerCtx, kv::KVStore, utils::time::current_epoch};
use candid::Principal;
use ic_agent::{
    identity::{Delegation, Secp256k1Identity, SignedDelegation},
    Identity,
};
use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use web_time::Duration;
use yral_identity::msg_builder::Message;
use yral_identity::Signature;
use yral_types::delegated_identity::DelegatedIdentityWire;

pub fn ai_account_message() -> yral_identity::msg_builder::Message {
    Message::default().method_name("yral_auth_v2_create_ai_account".into())
}

pub const MAX_AI_ACCOUNTS: u8 = 3;

#[cfg(feature = "ssr")]
fn ai_account_key(principal: &Principal, num: u8) -> String {
    format!("{}-ai-account-{}", principal.to_text(), num)
}

#[cfg(feature = "ssr")]
fn ai_account_reverse_lookup_key(ai_account_principal: &Principal) -> String {
    format!("ai-account:{}", ai_account_principal.to_text())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIAccountResponse {
    pub delegated_identity: DelegatedIdentityWire,
}

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

#[cfg(feature = "ssr")]
const AI_ACCOUNT_MAX_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);

#[server(endpoint = "create_ai_account", input=Json, output=Json)]
pub async fn create_ai_account(
    user_principal: Principal,
    signature: Signature,
) -> Result<AIAccountResponse, ServerFnError> {
    let ctx = expect_context::<std::sync::Arc<ServerCtx>>();

    let msg = ai_account_message();
    signature
        .verify_identity(user_principal, msg)
        .map_err(|_| ServerFnError::new("Invalid signature"))?;

    let main_principal = user_principal;

    let ai_account_check_key = ai_account_reverse_lookup_key(&main_principal);
    let formatted_ai_account_check_key = format_to_dragonfly_key(KEY_PREFIX, &ai_account_check_key);
    if ctx
        .kv_store
        .has_key(formatted_ai_account_check_key)
        .await
        .unwrap_or(false)
    {
        return Err(ServerFnError::new(
            "AI accounts cannot create other AI accounts",
        ));
    }

    let mut next_slot: Option<u8> = None;
    for num in 1..=MAX_AI_ACCOUNTS {
        let key = ai_account_key(&main_principal, num);
        let formatted_key = format_to_dragonfly_key(KEY_PREFIX, &key);
        match ctx.kv_store.has_key(formatted_key).await {
            Ok(exists) => {
                if !exists && next_slot.is_none() {
                    next_slot = Some(num);
                }
            }
            Err(e) => {
                return Err(ServerFnError::new(format!("Storage error: {}", e)));
            }
        }
    }

    let slot = match next_slot {
        Some(s) => s,
        None => {
            return Err(ServerFnError::new(format!(
                "Maximum of {} AI accounts already created",
                MAX_AI_ACCOUNTS
            )));
        }
    };

    let ai_secret = k256::SecretKey::random(&mut rand::rngs::OsRng);
    let ai_secret_jwk = ai_secret.to_jwk_string().to_string();

    let key = ai_account_key(&main_principal, slot);
    let formatted_key = format_to_dragonfly_key(KEY_PREFIX, &key);

    if let Err(e) = ctx.kv_store.write(formatted_key, ai_secret_jwk).await {
        return Err(ServerFnError::new(format!("Storage error: {}", e)));
    }

    let ai_identity = Secp256k1Identity::from_private_key(ai_secret.clone());
    let ai_account_principal = ai_identity.sender().unwrap();
    let reverse_key = ai_account_reverse_lookup_key(&ai_account_principal);
    let formatted_reverse_key = format_to_dragonfly_key(KEY_PREFIX, &reverse_key);

    if let Err(e) = ctx
        .kv_store
        .write(formatted_reverse_key, main_principal.to_text())
        .await
    {
        return Err(ServerFnError::new(format!("Storage error: {}", e)));
    }

    let delegated_identity = create_delegated_identity(&ai_secret, AI_ACCOUNT_MAX_AGE);

    Ok(AIAccountResponse { delegated_identity })
}

#[cfg(feature = "ssr")]
pub async fn get_ai_accounts_for_principal(
    ctx: &ServerCtx,
    main_principal: Principal,
) -> Result<Vec<AIAccountResponse>, String> {
    let mut ai_accounts = Vec::new();

    for num in 1..=MAX_AI_ACCOUNTS {
        let key = ai_account_key(&main_principal, num);
        let formatted_key = format_to_dragonfly_key(KEY_PREFIX, &key);
        match ctx.kv_store.read(formatted_key).await {
            Ok(Some(jwk_str)) => {
                if let Ok(secret_key) = k256::SecretKey::from_jwk_str(&jwk_str) {
                    let delegated_identity =
                        create_delegated_identity(&secret_key, AI_ACCOUNT_MAX_AGE);
                    ai_accounts.push(AIAccountResponse { delegated_identity });
                }
            }
            Ok(None) => continue,
            Err(e) => return Err(e.to_string()),
        }
    }

    Ok(ai_accounts)
}
