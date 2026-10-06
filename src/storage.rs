#![allow(unused)]

use soroban_sdk::{contracttype, Bytes, Env, Vec};
use crate::types::Credential;

/// Persistent storage TTL: ~1 year at 5 s/ledger.
pub const PERSISTENT_BUMP_AMOUNT: u32 = 6_307_200;
pub const PERSISTENT_BUMP_THRESHOLD: u32 = PERSISTENT_BUMP_AMOUNT / 2;

/// Instance storage TTL: ~30 days.
pub const INSTANCE_BUMP_AMOUNT: u32 = 518_400;
pub const INSTANCE_BUMP_THRESHOLD: u32 = INSTANCE_BUMP_AMOUNT / 2;

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
    env.storage().instance().extend_ttl(INSTANCE_BUMP_THRESHOLD, INSTANCE_BUMP_AMOUNT);
}

/// Store a credential.
pub fn set_credential(env: &Env, credential_id: &Bytes, credential: &Credential) {
    let key = DataKey::Credential(credential_id.clone());
    env.storage().persistent().set(&key, credential);
    env.storage().persistent().extend_ttl(&key, PERSISTENT_BUMP_THRESHOLD, PERSISTENT_BUMP_AMOUNT);
}

/// Get a credential, returning None if not found.
pub fn get_credential(env: &Env, credential_id: &Bytes) -> Option<Credential> {
    let key = DataKey::Credential(credential_id.clone());
    let result: Option<Credential> = env.storage().persistent().get(&key);
    if result.is_some() {
        env.storage().persistent().extend_ttl(&key, PERSISTENT_BUMP_THRESHOLD, PERSISTENT_BUMP_AMOUNT);
    }
    result
}

/// Remove a credential.
pub fn remove_credential(env: &Env, credential_id: &Bytes) {
    env.storage().persistent().remove(&DataKey::Credential(credential_id.clone()));
}

/// Get the list of all credential IDs.
pub fn get_credential_list(env: &Env) -> Vec<Bytes> {
    let result = env.storage().persistent()
        .get(&DataKey::CredentialList)
        .unwrap_or_else(|| Vec::new(env));
    if env.storage().persistent().has(&DataKey::CredentialList) {
        env.storage().persistent().extend_ttl(&DataKey::CredentialList, PERSISTENT_BUMP_THRESHOLD, PERSISTENT_BUMP_AMOUNT);
    }
    result
}

/// Set the list of all credential IDs.
pub fn set_credential_list(env: &Env, list: &Vec<Bytes>) {
    env.storage().persistent().set(&DataKey::CredentialList, list);
    env.storage().persistent().extend_ttl(&DataKey::CredentialList, PERSISTENT_BUMP_THRESHOLD, PERSISTENT_BUMP_AMOUNT);
}

/// Get the allowed origin.
pub fn get_allowed_origin_val(env: &Env) -> Option<Bytes> {
    let result = env.storage().instance().get(&DataKey::AllowedOrigin);
    if result.is_some() {
        env.storage().instance().extend_ttl(INSTANCE_BUMP_THRESHOLD, INSTANCE_BUMP_AMOUNT);
    }
    result
}

/// Set the allowed origin.
pub fn set_allowed_origin(env: &Env, origin: &Bytes) {
    env.storage().instance().set(&DataKey::AllowedOrigin, origin);
    env.storage().instance().extend_ttl(INSTANCE_BUMP_THRESHOLD, INSTANCE_BUMP_AMOUNT);
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
    let result = env.storage().instance().get(&DataKey::PendingRecovery);
    if result.is_some() {
        env.storage().instance().extend_ttl(INSTANCE_BUMP_THRESHOLD, INSTANCE_BUMP_AMOUNT);
    }
    result
}

/// Set the pending recovery request.
pub fn set_pending_recovery(env: &Env, request: &crate::types::RecoveryRequest) {
    env.storage()
        .instance()
        .set(&DataKey::PendingRecovery, request);
    env.storage().instance().extend_ttl(INSTANCE_BUMP_THRESHOLD, INSTANCE_BUMP_AMOUNT);
}

/// Clear the pending recovery request.
pub fn clear_pending_recovery(env: &Env) {
    env.storage().instance().remove(&DataKey::PendingRecovery);
}
