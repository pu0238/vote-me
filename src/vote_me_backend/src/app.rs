use crate::{
    auth::get_auth_derivation_path,
    ecdsa_api,
    types::{Rank, TokenData, User},
    CANISTER_NAME, USERS,
};

pub async fn sign_in(username: String, salt: String, user_id: String) -> String {
    let canister_name = CANISTER_NAME.with(|n| n.borrow().clone());
    let auth_derivation_path =
        get_auth_derivation_path(canister_name.clone(), username.clone(), user_id.clone());
    let auth_key = ecdsa_api::hex_get_public_key(auth_derivation_path.clone()).await;

    let rank = match USERS.with(|users_map| users_map.borrow().len()) == 0 {
        true => Rank::Admin,
        false => Rank::User,
    };
    let user = User::new(user_id.clone(), salt, auth_key.clone(), rank.clone());
    USERS.with(|users_map| users_map.borrow_mut().insert(username.clone(), user));

    create_auth_msg(username, user_id, rank.clone(), auth_derivation_path).await
}

pub async fn log_in(username: String, user_id: String, rank: Rank) -> String {
    let canister_name = CANISTER_NAME.with(|n| n.borrow().clone());

    let auth_derivation_path =
        get_auth_derivation_path(canister_name.clone(), username.clone(), user_id.clone());

    create_auth_msg(username, user_id, rank, auth_derivation_path).await
}

async fn create_auth_msg(
    username: String,
    user_id: String,
    rank: Rank,
    auth_derivation_path: Vec<Vec<u8>>,
) -> String {
    let ten_minutes = 10 * 60 * 1_000_000_000;
    let expires_at = ic_cdk::api::time() + ten_minutes;

    let auth_message = hex::encode(
        serde_json::to_string(&TokenData {
            username,
            user_id,
            expires_at,
            rank,
        })
        .expect("Failed to deserialize tokendata?!"),
    );

    let signed_auth_message =
        ecdsa_api::hex_sign_message(auth_message.clone(), auth_derivation_path).await;

    vec![auth_message, signed_auth_message].join(".")
}
