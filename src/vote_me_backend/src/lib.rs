mod app;
mod auth;
mod ecdsa_api;
mod types;

// use ic_cdk::println;
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, query, update};
use std::cell::RefCell;
use types::{Network, Vote, Voting};

use crate::{
    auth::{caller, get_token_data},
    types::{Rank, UserMap, VotingMap},
};

thread_local! {
    static CANISTER_NAME: RefCell<String> = RefCell::new(String::from("VoteMe"));
    static NETWORK: RefCell<Network> = RefCell::new(Network::Regtest);

    static USERS: RefCell<UserMap> = RefCell::new(UserMap::new());
    static USER_VOTINGS: RefCell<VotingMap> = RefCell::new(VotingMap::new());
}

#[init]
pub fn init(network: Network) {
    NETWORK.with(|n| *n.borrow_mut() = network.clone());
}

#[pre_upgrade]
fn pre_upgrade() {
    let network = NETWORK.with(|n| n.borrow().clone());
    ic_cdk::storage::stable_save((network,)).expect("Saving network to stable store must succeed.");
}

#[post_upgrade]
fn post_upgrade() {
    let network = ic_cdk::storage::stable_restore::<(Network,)>()
        .expect("Failed to read network from stable memory.")
        .0;

    // TODO: REMOVE
    USERS.with(|n| *n.borrow_mut() = UserMap::new());
    USER_VOTINGS.with(|n| *n.borrow_mut() = VotingMap::new());

    init(network);
}

fn is_user_registered(username: String) -> bool {
    USERS.with(|users_map| users_map.borrow().contains_key(&username))
}

#[update]
async fn sign_in(username: String, salt: String) -> String {
    let caller = caller();
    let user_id = caller.to_string();

    assert!(
        !is_user_registered(username.clone()),
        "User is already registered"
    );

    app::sign_in(username, salt, user_id).await
}

#[update]
async fn get_user_salt(username: String) -> String {
    let user = USERS
        .with(|users_map| users_map.borrow().get(&username).cloned())
        .expect("User not found");

    user.salt
}

#[update]
async fn log_in(username: String) -> String {
    let caller = caller();
    let user_id = caller.to_string();

    let user = USERS
        .with(|users_map| users_map.borrow().get(&username).cloned())
        .expect("User not found");

    assert_eq!(user.user_id, user_id, "User is not valid");

    app::log_in(username, user_id, user.rank).await
}

#[update]
fn create_vote(auth_token: String, vote_name: String, vote_description: String) {
    let token_data = get_token_data(auth_token).unwrap();

    assert_eq!(token_data.rank, Rank::Admin, "User is not an Admin");

    USER_VOTINGS.with(|votings| {
        votings
            .borrow_mut()
            .insert(vote_name, Voting::new(vote_description))
    });
}

#[query]
fn get_votings() -> VotingMap {
    USER_VOTINGS.with(|votings| votings.borrow().clone())
}

#[update]
pub fn vote_at(auth_token: String, vote_name: String, vote: Vote) -> Voting {
    let token_data = get_token_data(auth_token).unwrap();

    USER_VOTINGS
        .with(|votings| {
            let mut votings = votings.borrow_mut();
            if let Some(v) = votings.get_mut(&vote_name) {
                v.user_vote(vote, token_data.username);
                return Some(v.clone());
            }
            None
        })
        .expect("Voting not found")
}
