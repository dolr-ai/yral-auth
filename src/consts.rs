use std::sync::LazyLock;
use url::Url;
use web_time::Duration;

pub const GOOGLE_ISSUER_URL: &str = "https://accounts.google.com";

/// Base URL for the off-chain agent API.
/// Used for account deletion (Google Play policy compliance).
pub static OFF_CHAIN_AGENT_URL: LazyLock<Url> =
    LazyLock::new(|| Url::parse("https://offchain.yral.com").unwrap());
pub const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

pub const APPLE_ISSUER_URL: &str = "https://account.apple.com";
pub const APPLE_ISSUER_URL2: &str = "https://appleid.apple.com";

/// Delegation Expiry, 7 days
pub const ACCESS_TOKEN_MAX_AGE: Duration = Duration::from_secs(60 * 60 * 24 * 7);
/// Refresh expiry, 30 days
pub const REFRESH_TOKEN_MAX_AGE: Duration = Duration::from_secs(60 * 60 * 24 * 30);

/// Backend Delegation token expiry, 3 months
pub const BACKEND_ACCESS_TOKEN_MAX_AGE: Duration = Duration::from_secs(60 * 60 * 24 * 30 * 3);
/// Backend Refresh token expiry, 6 months
pub const BACKEND_REFRESH_TOKEN_MAX_AGE: Duration = Duration::from_secs(60 * 60 * 24 * 30 * 6);

pub const AUTH_TOKEN_KID: &str = "default";
