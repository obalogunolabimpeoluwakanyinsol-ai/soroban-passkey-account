#![allow(unused)]

use soroban_sdk::{contracttype, contracterror, Bytes, BytesN};

/// A registered passkey credential.
#[contracttype]
#[derive(Clone)]
pub struct Credential {
    /// Uncompressed secp256r1 (P-256) public key, 65 bytes (0x04 || X || Y).
    pub public_key: BytesN<65>,
    /// Last seen WebAuthn signature counter. 0 means counter checking is disabled
    /// for this credential (platform authenticator compatibility mode).
    pub counter: u32,
}

/// The WebAuthn assertion passed into __check_auth via signature_args.
/// This mirrors the structure of a WebAuthn AuthenticatorAssertionResponse.
#[contracttype]
#[derive(Clone)]
pub struct WebAuthnAssertion {
    /// The credential ID identifying which registered key to verify against.
    pub credential_id: Bytes,
    /// authenticatorData bytes from the WebAuthn assertion.
    pub authenticator_data: Bytes,
    /// clientDataJSON bytes from the WebAuthn assertion.
    pub client_data_json: Bytes,
    /// The secp256r1 (P-256) signature over SHA-256(authenticatorData || SHA-256(clientDataJSON)).
    /// DER-encoded, as produced by WebAuthn authenticators.
    pub signature: BytesN<64>,
}

/// Contract errors.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum AccountError {
    /// Contract has already been initialized.
    AlreadyInitialized = 1,
    /// The referenced credential_id is not registered.
    CredentialNotFound = 2,
    /// The signature counter was not strictly greater than the stored counter.
    /// This indicates a replayed or cloned assertion.
    CounterNotIncreased = 3,
    /// The origin in clientDataJSON does not match the allow-listed origin.
    OriginMismatch = 4,
    /// The secp256r1 signature verification failed.
    InvalidSignature = 5,
    /// Attempt to remove the last remaining signer, which would brick the account.
    CannotRemoveLastSigner = 6,
    /// clientDataJSON is malformed or missing required fields.
    MalformedClientData = 7,
    /// authenticatorData is malformed (too short).
    MalformedAuthenticatorData = 8,
    /// The caller is not a registered guardian.
    NotAGuardian = 9,
    /// A recovery is already pending. Cancel or execute the existing one first.
    RecoveryAlreadyPending = 10,
    /// No recovery is currently pending.
    NoRecoveryPending = 11,
    /// This guardian has already approved the pending recovery.
    AlreadyApproved = 12,
    /// Threshold has not been met.
    ThresholdNotMet = 13,
    /// The recovery timelock has not yet elapsed.
    TimelockNotElapsed = 14,
    /// The recovery threshold value is invalid (must be >= 1 and <= guardian count).
    InvalidThreshold = 15,
}

/// A pending social recovery request.
/// Stores who proposed it, what credential to add, when it was proposed,
/// and which guardians have approved it.
#[contracttype]
#[derive(Clone)]
pub struct RecoveryRequest {
    /// The guardian who initiated the recovery.
    pub proposer: soroban_sdk::Address,
    /// The credential ID to be added as a new signer upon successful recovery.
    pub new_credential_id: soroban_sdk::Bytes,
    /// The public key associated with the new credential.
    pub new_public_key: BytesN<65>,
    /// Ledger timestamp (Unix seconds) when initiate_recovery was called.
    pub initiated_at: u64,
    /// List of guardian addresses that have approved this recovery.
    pub approvals: soroban_sdk::Vec<soroban_sdk::Address>,
}
