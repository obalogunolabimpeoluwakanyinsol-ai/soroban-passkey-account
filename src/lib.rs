#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, contracterror, Bytes, BytesN, Env, Vec, Val};

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
    pub fn initialize(
        env: Env,
        credential_id: Bytes,
        public_key: BytesN<65>,
        allowed_origin: Bytes,
    ) {
        todo!("implement in chunk 2")
    }

    /// Add a new passkey signer. Requires a valid signature from an existing signer
    /// (enforced via __check_auth — this function is only callable through auth).
    pub fn add_signer(
        env: Env,
        credential_id: Bytes,
        public_key: BytesN<65>,
    ) {
        todo!("implement in chunk 6")
    }

    /// Remove a passkey signer. Requires a valid signature from an existing signer.
    /// Blocked if this is the last remaining signer.
    pub fn remove_signer(env: Env, credential_id: Bytes) {
        todo!("implement in chunk 6")
    }

    /// List all registered credential IDs.
    pub fn list_credentials(env: Env) -> Vec<Bytes> {
        todo!("implement in chunk 2")
    }

    /// Get the current stored counter for a credential.
    pub fn get_counter(env: Env, credential_id: Bytes) -> u32 {
        todo!("implement in chunk 2")
    }

    /// Get the configured allowed origin.
    pub fn get_allowed_origin(env: Env) -> Bytes {
        todo!("implement in chunk 2")
    }
}

/// Soroban custom account interface implementation.
pub struct PasskeyAccountInterface;

#[contractimpl]
impl soroban_sdk::auth::CustomAccountInterface for PasskeyAccount {
    type Signature = WebAuthnAssertion;
    type Error = AccountError;

    fn __check_auth(
        env: Env,
        signature_payload: BytesN<32>,
        signature_args: WebAuthnAssertion,
        auth_contexts: Vec<soroban_sdk::auth::Context>,
    ) -> Result<(), AccountError> {
        todo!("implement in chunks 3-5")
    }
}
