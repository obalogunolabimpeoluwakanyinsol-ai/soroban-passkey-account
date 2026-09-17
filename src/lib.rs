#![no_std]

use soroban_sdk::{
    contract, contractimpl, Bytes, BytesN, Env, Vec,
    auth::Context,
};

mod types;
mod storage;

pub use types::*;
pub use storage::*;

/// soroban-passkey-account
///
/// A Soroban custom account contract that authenticates users via WebAuthn passkeys
/// (Face ID / fingerprint / hardware key) using Soroban's native secp256r1 (P-256)
/// host function for signature verification.
///
/// # Security model
/// - Each registered credential has a stored public key and signature counter.
/// - __check_auth verifies the secp256r1 signature, checks counter strictly increases
///   (replay defense), and validates the origin from clientDataJSON.
/// - Counter=0 special case: if a credential's stored counter is 0 AND the asserted
///   counter is also 0, counter checking is disabled for that credential (compatibility
///   with platform authenticators that always report counter=0 per WebAuthn spec).
/// - The last registered signer CANNOT be removed — doing so would permanently brick
///   the account with no recovery path.
#[contract]
pub struct PasskeyAccount;

#[contractimpl]
impl PasskeyAccount {
    /// Register the first passkey and configure the origin allow-list at deploy time.
    ///
    /// # Panics
    /// Panics (via AccountError::AlreadyInitialized) if called more than once.
    pub fn initialize(
        env: Env,
        credential_id: Bytes,
        public_key: BytesN<65>,
        allowed_origin: Bytes,
    ) {
        if is_initialized(&env) {
            panic!("contract already initialized");
        }

        // Store the allowed origin
        set_allowed_origin(&env, &allowed_origin);

        // Store the first credential with counter=0
        let credential = Credential {
            public_key,
            counter: 0,
        };
        set_credential(&env, &credential_id, &credential);

        // Update the credential list
        let mut list: Vec<Bytes> = Vec::new(&env);
        list.push_back(credential_id);
        set_credential_list(&env, &list);

        // Mark as initialized
        set_initialized(&env);
    }

    /// Add a new passkey signer. Requires a valid signature from an existing signer
    /// (enforced via __check_auth — this function is only callable through auth).
    pub fn add_signer(
        env: Env,
        credential_id: Bytes,
        public_key: BytesN<65>,
    ) {
        // Auth is enforced by __check_auth via Soroban's account abstraction.
        // The caller must supply a valid WebAuthn assertion from an existing signer.
        env.current_contract_address().require_auth();

        let credential = Credential {
            public_key,
            counter: 0,
        };
        set_credential(&env, &credential_id, &credential);

        let mut list = get_credential_list(&env);
        list.push_back(credential_id);
        set_credential_list(&env, &list);
    }

    /// Remove a passkey signer. Requires a valid signature from an existing signer.
    /// Blocked if this is the last remaining signer (would permanently brick the account).
    pub fn remove_signer(env: Env, credential_id: Bytes) {
        env.current_contract_address().require_auth();

        let list = get_credential_list(&env);
        if list.len() <= 1 {
            panic!("cannot remove last signer: account would be unrecoverable");
        }

        remove_credential(&env, &credential_id);

        // Rebuild the credential list without the removed credential_id
        let mut new_list: Vec<Bytes> = Vec::new(&env);
        for id in list.iter() {
            if id != credential_id {
                new_list.push_back(id);
            }
        }
        set_credential_list(&env, &new_list);
    }

    /// List all registered credential IDs.
    pub fn list_credentials(env: Env) -> Vec<Bytes> {
        get_credential_list(&env)
    }

    /// Get the current stored counter for a credential.
    /// Returns 0 if the credential is not found.
    pub fn get_counter(env: Env, credential_id: Bytes) -> u32 {
        get_credential(&env, &credential_id)
            .map(|c| c.counter)
            .unwrap_or(0)
    }

    /// Get the configured allowed origin.
    pub fn get_allowed_origin(env: Env) -> Bytes {
        get_allowed_origin_val(&env).expect("not initialized")
    }
}

/// Soroban custom account interface implementation.
#[contractimpl]
impl soroban_sdk::auth::CustomAccountInterface for PasskeyAccount {
    type Signature = WebAuthnAssertion;
    type Error = AccountError;

    fn __check_auth(
        env: Env,
        signature_payload: BytesN<32>,
        signature_args: WebAuthnAssertion,
        auth_contexts: Vec<Context>,
    ) -> Result<(), AccountError> {
        // Implemented in chunks 3-5
        let _ = (signature_payload, signature_args, auth_contexts);
        Err(AccountError::InvalidSignature)
    }
}
