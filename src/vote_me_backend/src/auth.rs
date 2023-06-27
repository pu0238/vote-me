use std::str::from_utf8;

use ic_cdk::api::caller as caller_api;
use ic_cdk::export::Principal;

use crate::ecdsa_api::verify;
use crate::types::TokenData;
use crate::USERS;

pub fn caller() -> Principal {
    let caller = caller_api();

    if caller == Principal::anonymous() {
        panic!("Anonymous principal not allowed to make calls.")
    }
    caller
}

pub fn get_auth_derivation_path(
    canister_name: String,
    username: String,
    user_id: String,
) -> Vec<Vec<u8>> {
    vec![
        canister_name.as_bytes().to_vec(),
        "AuthKey".as_bytes().to_vec(),
        username.as_bytes().to_vec(),
        user_id.as_bytes().to_vec(),
    ]
}

pub fn get_token_data(token: String) -> Result<TokenData, &'static str> {
    let mut token_data = token.split(".");
    let message = token_data.next();
    let signed_message = token_data.next();

    if message == None || signed_message == None {
        return Err("Token is not valid");
    }
    let message = message.expect("Message not found?");
    let auth_message = hex::decode(message).expect("Token is not valid");

    let auth_message: &str =
        from_utf8(&auth_message).expect("Error while decofding message to string");
    let token_data: TokenData =
        serde_json::from_str(auth_message).expect("Error reading json message");

    let user = USERS
        .with(|users_map| users_map.borrow().get(&token_data.username).cloned())
        .expect("User not found");

    let is_sign_valid = verify(
        signed_message.expect("Token Is not valid").to_owned(),
        message.to_owned(),
        user.auth_key,
    );
    if !is_sign_valid {
        return Err("Token is not valid");
    }

    if token_data.expires_at < ic_cdk::api::time() {
        return Err("Token is not valid");
    }

    Ok(token_data)
}
