use candid::Principal;
use ic_agent::Identity;

use crate::{
    error::AuthErrorKind,
    kv::{
        dragonfly_kv::{format_to_dragonfly_key, KEY_PREFIX},
        KVStore, KVStoreImpl,
    },
    oauth::{AuthLoginHint, SupportedOAuthProviders},
    utils::identity::generate_random_identity_and_save,
};

pub fn login_hint_message() -> yral_identity::msg_builder::Message {
    use yral_identity::msg_builder::Message;

    Message::default().method_name("yral_auth_v2_login_hint".into())
}

pub fn principal_lookup_key(provider: SupportedOAuthProviders, sub_id: &str) -> String {
    format!("{provider}-login-{sub_id}")
}

pub async fn try_extract_principal_from_oauth_sub(
    provider: SupportedOAuthProviders,
    kv: &KVStoreImpl,
    sub_id: &str,
    email: Option<&str>,
) -> Result<Option<String>, AuthErrorKind> {
    let key = principal_lookup_key(provider, sub_id);
    let formatted_key = format_to_dragonfly_key(KEY_PREFIX, &key);
    let Some(principal_str) = kv
        .read(formatted_key)
        .await
        .map_err(AuthErrorKind::unexpected)?
    else {
        log::debug!("No principal found for {provider} : {email:?}");
        return Ok(None);
    };

    log::debug!("Found principal {principal_str} for {provider} : {email:?}");

    if kv
        .has_key(format_to_dragonfly_key(KEY_PREFIX, &principal_str))
        .await
        .map_err(AuthErrorKind::unexpected)?
    {
        log::debug!("Principal {principal_str} is valid for {provider} : {email:?}");
        Ok(Some(principal_str))
    } else if email
        .map(|e| e.ends_with("@gobazzinga.io"))
        .unwrap_or(false)
    {
        log::debug!("Principal {principal_str} is banned, but email {email:?} is whitelisted");
        // Allow whitelisted users to create a new account
        Ok(None)
    } else {
        // User had deleted their account,
        // don't allow creation of new account again
        log::debug!("Principal {principal_str} is banned for {provider} : {email:?}");
        // Temporarily allow banned users to create a new account
        Ok(None)
    }
}

pub async fn principal_from_login_hint_or_generate_and_save(
    provider: SupportedOAuthProviders,
    kv: &KVStoreImpl,
    sub_id: &str,
    login_hint: Option<AuthLoginHint>,
    email: Option<&str>,
) -> Result<Principal, AuthErrorKind> {
    let user_principal = if let Some(login_hint) = login_hint {
        let msg = login_hint_message();
        login_hint
            .signature
            .verify_identity(login_hint.user_principal, msg)
            .map_err(|_| AuthErrorKind::InvalidLoginHint)?;
        log::debug!(
            "Using login hint principal {} for provider {provider} for email {email:?}",
            login_hint.user_principal.to_text()
        );
        login_hint.user_principal
    } else {
        log::debug!(
            "No login hint provided, generating new principal for provider {provider} for email {email:?}"
        );
        let identity = generate_random_identity_and_save(kv)
            .await
            .map_err(|_| AuthErrorKind::unexpected("failed to generate id"))?;
        identity.sender().unwrap()
    };

    kv.write(
        format_to_dragonfly_key(KEY_PREFIX, &principal_lookup_key(provider, sub_id)),
        user_principal.to_text(),
    )
    .await
    .map_err(|_| AuthErrorKind::unexpected("failed to associated id with oauth"))?;

    Ok(user_principal)
}
