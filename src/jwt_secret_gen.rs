use std::{env, time::Duration};

use jsonwebtoken::Header;
use yral_auth::{oauth::jwt::ClientSecretClaims, utils::time::current_epoch};

// 1 year
const JWT_EXPIRY: Duration = Duration::from_secs(365 * 24 * 60 * 60);

fn main() {
    dotenvy::dotenv().unwrap();

    let client_id = env::var("CLIENT_ID").expect("Specify `CLIENT_ID` to generate JWT");
    let jwt_pem = env::var("CLIENT_JWT_ED_PEM").expect("`CLIENT_JWT_ED_PEM` is required!");
    let jwt_enc = jsonwebtoken::EncodingKey::from_ed_pem(jwt_pem.as_bytes())
        .expect("invalid `CLIENT_JWT_ED_PEM`");

    let jwt = jsonwebtoken::encode(
        &Header::new(jsonwebtoken::Algorithm::EdDSA),
        &ClientSecretClaims {
            aud: client_id.clone(),
            exp: (current_epoch() + JWT_EXPIRY).as_secs() as usize,
            iat: current_epoch().as_secs() as usize,
            iss: "yral-auth-v2".to_string(),
            sub: client_id,
        },
        &jwt_enc,
    )
    .expect("Failed to encode JWT");

    println!("{jwt}");
}
