#![allow(unused)]

use soroban_sdk::{contracttype, Bytes, Env, Vec};
use crate::types::Credential;

/// Storage key enum for all persistent contract state.
#[contracttype]
pub enum DataKey {
    /// Stores a Credential keyed by credential_id bytes.
    Credential(Bytes),
    /// Stores the list of all registered credential IDs (Vec<Bytes>).
    CredentialList,
    /// Stores the allowed origin bytes.
    AllowedOrigin,
    /// Marks whether the contract has been initialized.
    Initialized,
}

/// Returns true if the contract has been initialized.
pub fn is_initialized(env: &Env) -> bool {
    env.storage().instance().has(&DataKey::Initialized)
}

/// Mark the contract as initialized.
pub fn set_initialized(env: &Env) {
    env.storage().instance().set(&DataKey::Initialized, &true);
}

/// Store a credential.
pub fn set_credential(env: &Env, credential_id: &Bytes, credential: &Credential) {
    env.storage().persistent().set(&DataKey::Credential(credential_id.clone()), credential);
}

/// Get a credential, returning None if not found.
pub fn get_credential(env: &Env, credential_id: &Bytes) -> Option<Credential> {
    env.storage().persistent().get(&DataKey::Credential(credential_id.clone()))
}

/// Remove a credential.
pub fn remove_credential(env: &Env, credential_id: &Bytes) {
    env.storage().persistent().remove(&DataKey::Credential(credential_id.clone()));
}

/// Get the list of all credential IDs.
pub fn get_credential_list(env: &Env) -> Vec<Bytes> {
    env.storage().persistent()
        .get(&DataKey::CredentialList)
        .unwrap_or_else(|| Vec::new(env))
}

/// Set the list of all credential IDs.
pub fn set_credential_list(env: &Env, list: &Vec<Bytes>) {
    env.storage().persistent().set(&DataKey::CredentialList, list);
}

/// Get the allowed origin.
pub fn get_allowed_origin_val(env: &Env) -> Option<Bytes> {
    env.storage().instance().get(&DataKey::AllowedOrigin)
}

/// Set the allowed origin.
pub fn set_allowed_origin(env: &Env, origin: &Bytes) {
    env.storage().instance().set(&DataKey::AllowedOrigin, origin);
}
