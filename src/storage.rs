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
    /// Stores the list of guardian addresses (Vec<Address>).
    GuardianList,
    /// Stores the recovery threshold (u32). If unset, defaults to ALL guardians.
    RecoveryThreshold,
    /// Stores the recovery timelock in seconds (u64). Default: 3 days.
    RecoveryTimelock,
    /// Stores the pending RecoveryRequest, if one is in flight.
    PendingRecovery,
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

// ---------------------------------------------------------------------------
// Social recovery storage helpers
// ---------------------------------------------------------------------------

/// Default recovery timelock: 3 days in seconds.
pub const DEFAULT_RECOVERY_TIMELOCK_SECONDS: u64 = 3 * 24 * 60 * 60;

/// Get the list of guardian addresses.
pub fn get_guardian_list(env: &Env) -> soroban_sdk::Vec<soroban_sdk::Address> {
    env.storage()
        .instance()
        .get(&DataKey::GuardianList)
        .unwrap_or_else(|| soroban_sdk::Vec::new(env))
}

/// Set the list of guardian addresses.
pub fn set_guardian_list(env: &Env, list: &soroban_sdk::Vec<soroban_sdk::Address>) {
    env.storage().instance().set(&DataKey::GuardianList, list);
}

/// Get the recovery threshold. If unset, returns None (caller must default to ALL guardians).
pub fn get_recovery_threshold(env: &Env) -> Option<u32> {
    env.storage().instance().get(&DataKey::RecoveryThreshold)
}

/// Set the recovery threshold.
pub fn set_recovery_threshold(env: &Env, threshold: u32) {
    env.storage()
        .instance()
        .set(&DataKey::RecoveryThreshold, &threshold);
}

/// Get the recovery timelock in seconds. Defaults to DEFAULT_RECOVERY_TIMELOCK_SECONDS.
pub fn get_recovery_timelock(env: &Env) -> u64 {
    env.storage()
        .instance()
        .get(&DataKey::RecoveryTimelock)
        .unwrap_or(DEFAULT_RECOVERY_TIMELOCK_SECONDS)
}

/// Set the recovery timelock in seconds.
pub fn set_recovery_timelock(env: &Env, seconds: u64) {
    env.storage()
        .instance()
        .set(&DataKey::RecoveryTimelock, &seconds);
}

/// Get the pending recovery request, if any.
pub fn get_pending_recovery(env: &Env) -> Option<crate::types::RecoveryRequest> {
    env.storage().instance().get(&DataKey::PendingRecovery)
}

/// Set the pending recovery request.
pub fn set_pending_recovery(env: &Env, request: &crate::types::RecoveryRequest) {
    env.storage()
        .instance()
        .set(&DataKey::PendingRecovery, request);
}

/// Clear the pending recovery request.
pub fn clear_pending_recovery(env: &Env) {
    env.storage().instance().remove(&DataKey::PendingRecovery);
}
