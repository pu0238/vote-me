use crate::{types::*, NETWORK};
use ic_cdk::{api::call::call_with_payment, call, export::Principal};

/// Returns the ECDSA public key of this canister at the given derivation path.
pub async fn ecdsa_public_key(derivation_path: Vec<Vec<u8>>) -> Vec<u8> {
    // Retrieve the public key of this canister at the given derivation path
    // from the ECDSA API.
    let network = NETWORK.with(|n| n.borrow().clone());
    let res: (ECDSAPublicKeyReply,) = call(
        Principal::management_canister(),
        "ecdsa_public_key",
        (ECDSAPublicKey {
            canister_id: None,
            derivation_path,
            key_id: network.to_key_id(),
        },),
    )
    .await
    .unwrap();

    res.0.public_key
}

pub async fn ecdsa_sign(derivation_path: Vec<Vec<u8>>, message_hash: Vec<u8>) -> Vec<u8> {
    let network = NETWORK.with(|n| n.borrow().clone());
    let res: (SignWithECDSAReply,) = call_with_payment(
        Principal::management_canister(),
        "sign_with_ecdsa",
        (SignWithECDSA {
            message_hash,
            derivation_path,
            key_id: network.to_key_id(),
        },),
        10_000_000_000,
    )
    .await
    .unwrap();
    res.0.signature
}

pub async fn hex_sign_message(message: String, derivation_path: Vec<Vec<u8>>) -> String {
    let signed_msg = ecdsa_sign(derivation_path, sha256(&message).to_vec()).await;
    hex::encode(&signed_msg)
}

pub async fn hex_get_public_key(derivation_path: Vec<Vec<u8>>) -> String {
    let public_key = ecdsa_public_key(derivation_path).await;
    hex::encode(&public_key)
}

pub fn verify(signature_hex: String, message: String, public_key_hex: String) -> bool {
    let signature_bytes = hex::decode(&signature_hex).expect("failed to hex-decode signature");
    let pubkey_bytes = hex::decode(&public_key_hex).expect("failed to hex-decode public key");
    let message_bytes = message.as_bytes();

    use k256::ecdsa::signature::Verifier;
    let signature = k256::ecdsa::Signature::try_from(signature_bytes.as_slice())
        .expect("failed to deserialize signature");
    let is_signature_valid = k256::ecdsa::VerifyingKey::from_sec1_bytes(&pubkey_bytes)
        .expect("failed to deserialize sec1 encoding into public key")
        .verify(message_bytes, &signature)
        .is_ok();

    is_signature_valid
}

pub fn sha256(input: &String) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(input.as_bytes());
    hasher.finalize().into()
}
