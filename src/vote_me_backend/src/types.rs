use std::{collections::BTreeMap};

use ic_cdk::export::{
    candid::{CandidType, Deserialize},
    serde::Serialize,
    Principal,
};

#[derive(CandidType, Deserialize)]
pub struct SendRequest {
    pub destination_address: String,
    pub amount_in_satoshi: u64,
}

#[derive(CandidType, Serialize, Deserialize, Debug)]
pub struct ECDSAPublicKeyReply {
    pub public_key: Vec<u8>,
    pub chain_code: Vec<u8>,
}

#[derive(CandidType, Serialize, Deserialize, Debug, Clone)]
pub struct EcdsaKeyId {
    pub curve: EcdsaCurve,
    pub name: String,
}

#[derive(CandidType, Serialize, Deserialize, Debug, Clone)]
pub enum EcdsaCurve {
    #[serde(rename = "secp256k1")]
    Secp256k1,
}

#[derive(CandidType, Deserialize, Debug)]
pub struct SignWithECDSAReply {
    pub signature: Vec<u8>,
}

#[derive(CandidType, Serialize, Deserialize, Debug, Clone)]
pub struct ECDSAPublicKey {
    pub canister_id: Option<Principal>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: EcdsaKeyId,
}

#[derive(CandidType, Serialize, Debug)]
pub struct SignWithECDSA {
    pub message_hash: Vec<u8>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: EcdsaKeyId,
}

#[derive(CandidType, Serialize, Deserialize, Debug, Clone)]
pub enum Network {
    Mainnet,
    Testnet,
    Regtest,
}

#[derive(CandidType, Serialize, Deserialize, Debug, Clone)]
pub enum Env {
    Prod,
    Test,
}

impl Network {
    pub fn to_key_id(&self) -> EcdsaKeyId {
        EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: match self {
                Self::Regtest => "dfx_test_key",
                Self::Testnet => "test_key_1",
                Self::Mainnet => "key_1",
            }
            .to_string(),
        }
    }
}

type Username = String;
pub type UserMap = BTreeMap<Username, User>;

#[derive(CandidType, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum Rank {
    User,
    Admin,
}

#[derive(CandidType, Serialize, Deserialize, Debug, Clone)]
pub struct User {
    pub salt: String,
    pub user_id: String,
    pub auth_key: String,
    pub rank: Rank,
}

impl User {
    pub fn new(user_id: String, salt: String, auth_key: String, rank: Rank) -> Self {
        Self {
            user_id,
            salt,
            auth_key,
            rank,
        }
    }
}

type VotingName = String;
pub type VotingMap = BTreeMap<VotingName, Voting>;

#[derive(CandidType, Serialize, Deserialize, Debug, Clone)]
pub struct Voting {
    pub pro: u64,
    pub cons: u64,
    pub description: String,
    pub voted: Vec<String>,
}

impl Voting {
    pub fn new(description: String) -> Self {
        Voting {
            pro: 0,
            cons: 0,
            description,
            voted: Vec::new(),
        }
    }

    pub fn user_vote(&mut self, vote: Vote, username: Username) {
        match vote {
            Vote::Pro => {
                self.pro += 1;
                self.voted.push(username)
            }
            Vote::Cons => {
                self.cons += 1;
                self.voted.push(username)
            }
        }
    }
}

#[derive(CandidType, Serialize, Deserialize, Debug, Clone)]
pub enum Vote {
    Pro,
    Cons,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TokenData {
    pub username: String,
    pub user_id: String,
    pub expires_at: u64,
    pub rank: Rank,
}
