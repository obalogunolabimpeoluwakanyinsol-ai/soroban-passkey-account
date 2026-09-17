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
}
