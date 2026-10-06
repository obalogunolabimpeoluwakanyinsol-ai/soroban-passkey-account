#![no_std]

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contractimpl,
    crypto::Hash,
    Bytes, BytesN, Env, Vec,
};

pub(crate) mod storage;
mod types;

pub use storage::*;
pub use types::*;

#[contract]
pub struct PasskeyAccount;

#[contractimpl]
impl PasskeyAccount {
    /// Register the first passkey and configure the origin allow-list at deploy time.
    ///
    /// Called automatically at deploy time with constructor arguments supplied in
    /// the deploy transaction.  There is no separate initialization step, so there
    /// is no front-running window: no other transaction can interpose between
    /// deployment and the first-signer registration.
    pub fn __constructor(
        env: Env,
        credential_id: Bytes,
        public_key: BytesN<65>,
        allowed_origin: Bytes,
    ) {
        set_allowed_origin(&env, &allowed_origin);
        let credential = Credential {
            public_key,
            counter: 0,
        };
        set_credential(&env, &credential_id, &credential);
        let mut list: Vec<Bytes> = Vec::new(&env);
        list.push_back(credential_id);
        set_credential_list(&env, &list);
        set_initialized(&env);
    }

    /// Add a new passkey signer. Requires auth from an existing signer.
    pub fn add_signer(
        env: Env,
        credential_id: Bytes,
        public_key: BytesN<65>,
    ) -> Result<(), AccountError> {
        env.current_contract_address().require_auth();
        // Reject duplicate: if this credential_id is already registered, return a typed error.
        if crate::storage::get_credential(&env, &credential_id).is_some() {
            return Err(AccountError::CredentialExists);
        }
        let credential = Credential {
            public_key,
            counter: 0,
        };
        set_credential(&env, &credential_id, &credential);
        let mut list = get_credential_list(&env);
        list.push_back(credential_id);
        set_credential_list(&env, &list);
        Ok(())
    }

    /// Remove a passkey signer. Requires auth. Blocked if last signer.
    pub fn remove_signer(env: Env, credential_id: Bytes) {
        env.current_contract_address().require_auth();
        let list = get_credential_list(&env);
        if list.len() <= 1 {
            panic!("cannot remove last signer: account would be unrecoverable");
        }
        remove_credential(&env, &credential_id);
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

    /// Get the current stored counter for a credential (0 if not found).
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

#[contractimpl]
impl CustomAccountInterface for PasskeyAccount {
    type Signature = WebAuthnAssertion;
    type Error = AccountError;

    /// Verify a WebAuthn passkey assertion.
    ///
    /// Flow:
    /// 1. Look up the credential by credential_id.
    /// 2. Build the signed message: SHA-256(authenticatorData || SHA-256(clientDataJSON)).
    /// 3. Verify the secp256r1 signature using the Soroban host function.
    /// 4. Check the signature counter (replay defense).
    /// 5. Validate the origin from clientDataJSON.
    ///
    /// # Counter=0 handling
    /// Per the WebAuthn spec, some platform authenticators always report counter=0.
    /// If stored counter is 0 AND asserted counter is 0, counter checking is disabled.
    /// Once a credential has ever reported non-zero, strict incrementing is enforced.
    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        signature_args: WebAuthnAssertion,
        _auth_contexts: Vec<Context>,
    ) -> Result<(), AccountError> {
        // Step 0: validate clientDataJSON fields BEFORE any crypto.
        // (a) type must be exactly "webauthn.get"
        extract_type_from_client_data_json(&signature_args.client_data_json)?;
        // (b) challenge must be the base64url encoding of signature_payload (32 bytes)
        let payload_bytes: [u8; 32] = signature_payload.into();
        verify_challenge_in_client_data_json(&signature_args.client_data_json, &payload_bytes)?;

        // Step 1: look up the credential
        let mut credential = get_credential(&env, &signature_args.credential_id)
            .ok_or(AccountError::CredentialNotFound)?;

        // Step 2: build the signed message
        // WebAuthn authenticator signs: authenticatorData || SHA-256(clientDataJSON)
        // We hash the concatenation to produce the 32-byte input for secp256r1_verify.
        let client_data_hash: Hash<32> = env.crypto().sha256(&signature_args.client_data_json);

        let mut msg = signature_args.authenticator_data.clone();
        let hash_arr: [u8; 32] = client_data_hash.into();
        msg.extend_from_array(&hash_arr);

        let msg_hash: Hash<32> = env.crypto().sha256(&msg);

        // Step 3: verify the secp256r1 signature using Soroban's native host function.
        // Hardened, gas-cheap, audited primitive — we do NOT hand-roll ECDSA.
        env.crypto()
            .secp256r1_verify(&credential.public_key, &msg_hash, &signature_args.signature);
        // secp256r1_verify panics on failure — reaching this line means the signature is valid.

        // Step 4: counter replay defense
        let asserted_counter =
            parse_counter_from_authenticator_data(&signature_args.authenticator_data)?;
        let stored_counter = credential.counter;

        if stored_counter == 0 && asserted_counter == 0 {
            // Counter=0 compatibility mode — see WebAuthn spec §6.1 and ARCHITECTURE.md
        } else if asserted_counter > stored_counter {
            credential.counter = asserted_counter;
            set_credential(&env, &signature_args.credential_id, &credential);
        } else {
            return Err(AccountError::CounterNotIncreased);
        }

        // Step 5: origin validation
        let allowed_origin = get_allowed_origin_val(&env).ok_or(AccountError::OriginMismatch)?;
        let origin_from_client_data =
            extract_origin_from_client_data_json(&env, &signature_args.client_data_json)?;
        if origin_from_client_data != allowed_origin {
            return Err(AccountError::OriginMismatch);
        }

        Ok(())
    }
}

/// Extract the signature counter (bytes 33-36) from WebAuthn authenticatorData.
/// Layout: [0..32] rpIdHash | [32] flags | [33..37] signCount (big-endian u32)
pub(crate) fn parse_counter_from_authenticator_data(
    auth_data: &Bytes,
) -> Result<u32, AccountError> {
    if auth_data.len() < 37 {
        return Err(AccountError::MalformedAuthenticatorData);
    }
    let b0 = auth_data
        .get(33)
        .ok_or(AccountError::MalformedAuthenticatorData)? as u32;
    let b1 = auth_data
        .get(34)
        .ok_or(AccountError::MalformedAuthenticatorData)? as u32;
    let b2 = auth_data
        .get(35)
        .ok_or(AccountError::MalformedAuthenticatorData)? as u32;
    let b3 = auth_data
        .get(36)
        .ok_or(AccountError::MalformedAuthenticatorData)? as u32;
    Ok((b0 << 24) | (b1 << 16) | (b2 << 8) | b3)
}

/// Extract the "origin" field from WebAuthn clientDataJSON (no_std byte scanning).
/// Scans for the pattern `"origin":"` and reads until the closing `"`.
pub(crate) fn extract_origin_from_client_data_json(
    env: &Env,
    client_data_json: &Bytes,
) -> Result<Bytes, AccountError> {
    let needle = b"\"origin\":\"";
    let json_len = client_data_json.len() as usize;
    let mut origin_start: Option<usize> = None;

    'outer: for i in 0..json_len {
        if i + needle.len() > json_len {
            break;
        }
        let mut matched = true;
        for (j, &nb) in needle.iter().enumerate() {
            let byte = client_data_json
                .get((i + j) as u32)
                .ok_or(AccountError::MalformedClientData)?;
            if byte != nb {
                matched = false;
                break;
            }
        }
        if matched {
            origin_start = Some(i + needle.len());
            break 'outer;
        }
    }

    let start = origin_start.ok_or(AccountError::MalformedClientData)?;
    let mut end = start;
    loop {
        if end >= json_len {
            return Err(AccountError::MalformedClientData);
        }
        let byte = client_data_json
            .get(end as u32)
            .ok_or(AccountError::MalformedClientData)?;
        if byte == b'"' {
            break;
        }
        end += 1;
    }

    let mut origin = Bytes::new(env);
    for i in start..end {
        let byte = client_data_json
            .get(i as u32)
            .ok_or(AccountError::MalformedClientData)?;
        origin.push_back(byte);
    }

    Ok(origin)
}

/// Verify that the "type" field in clientDataJSON equals "webauthn.get".
/// Scans for `"type":"webauthn.get"` exactly; rejects "webauthn.create" and
/// any other value.
pub(crate) fn extract_type_from_client_data_json(
    client_data_json: &Bytes,
) -> Result<(), AccountError> {
    let needle = b"\"type\":\"webauthn.get\"";
    let json_len = client_data_json.len() as usize;
    if json_len < needle.len() {
        return Err(AccountError::InvalidType);
    }
    for i in 0..=(json_len - needle.len()) {
        let mut matched = true;
        for (j, &nb) in needle.iter().enumerate() {
            let byte = client_data_json
                .get((i + j) as u32)
                .ok_or(AccountError::InvalidType)?;
            if byte != nb {
                matched = false;
                break;
            }
        }
        if matched {
            return Ok(());
        }
    }
    Err(AccountError::InvalidType)
}

/// Verify that the base64url-decoded "challenge" field in clientDataJSON
/// equals `expected` (32 bytes, no padding assumed).
///
/// WebAuthn encodes the challenge as base64url without padding.
/// We extract the raw base64url string, decode it, and compare byte-by-byte
/// to `expected`.
pub(crate) fn verify_challenge_in_client_data_json(
    client_data_json: &Bytes,
    expected: &[u8; 32],
) -> Result<(), AccountError> {
    // Find `"challenge":"` and read until the next `"`
    let needle = b"\"challenge\":\"";
    let json_len = client_data_json.len() as usize;
    let mut challenge_start: Option<usize> = None;

    'outer: for i in 0..json_len {
        if i + needle.len() > json_len {
            break;
        }
        let mut matched = true;
        for (j, &nb) in needle.iter().enumerate() {
            let byte = client_data_json
                .get((i + j) as u32)
                .ok_or(AccountError::MalformedClientData)?;
            if byte != nb {
                matched = false;
                break;
            }
        }
        if matched {
            challenge_start = Some(i + needle.len());
            break 'outer;
        }
    }

    let start = challenge_start.ok_or(AccountError::MalformedClientData)?;
    let mut end = start;
    loop {
        if end >= json_len {
            return Err(AccountError::MalformedClientData);
        }
        let byte = client_data_json
            .get(end as u32)
            .ok_or(AccountError::MalformedClientData)?;
        if byte == b'"' {
            break;
        }
        end += 1;
    }
    // end - start is the length of the base64url string
    let b64_len = end - start;
    // base64url of 32 bytes = ceil(32/3)*4 = 44 chars with padding, or 43 without.
    // We accept both 43 (no padding) and 44 (with one `=`).
    if !(43..=44).contains(&b64_len) {
        return Err(AccountError::ChallengeMismatch);
    }

    // Read the base64url characters into a fixed buffer
    let mut b64_buf = [0u8; 44];
    for (i, slot) in b64_buf[..b64_len].iter_mut().enumerate() {
        *slot = client_data_json
            .get((start + i) as u32)
            .ok_or(AccountError::MalformedClientData)?;
    }

    // Decode base64url (URL alphabet: A-Z a-z 0-9 - _) without padding
    // 32 bytes → 43 base64url chars (256 bits = 43 * 6 bits, last char encodes 4 bits)
    let mut decoded = [0u8; 32];
    base64url_decode_32(&b64_buf[..b64_len], &mut decoded)
        .map_err(|_| AccountError::ChallengeMismatch)?;

    if &decoded != expected {
        return Err(AccountError::ChallengeMismatch);
    }
    Ok(())
}

/// Decode a base64url string (no padding or one `=`) into exactly 32 bytes.
/// Returns Err(()) on any invalid character or wrong length.
fn base64url_decode_32(input: &[u8], out: &mut [u8; 32]) -> Result<(), ()> {
    // We expect 43 or 44 bytes of base64url input to yield 32 decoded bytes.
    // 43 chars × 6 bits = 258 bits → 32 bytes + 2 leftover bits (must be 0)
    let stripped = if input.last() == Some(&b'=') {
        &input[..input.len() - 1]
    } else {
        input
    };
    if stripped.len() != 43 {
        return Err(());
    }

    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out_idx: usize = 0;

    for &c in stripped.iter() {
        let val: u32 = match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'-' => 62,
            b'_' => 63,
            _ => return Err(()),
        };
        acc = (acc << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            if out_idx >= 32 {
                return Err(());
            }
            out[out_idx] = ((acc >> bits) & 0xFF) as u8;
            out_idx += 1;
        }
    }
    // The 2 leftover bits must be zero (padding bits)
    if bits > 0 && (acc & ((1u32 << bits) - 1)) != 0 {
        return Err(());
    }
    if out_idx != 32 {
        return Err(());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Social recovery implementation
// ---------------------------------------------------------------------------
//
// IMPORTANT: Guardians CANNOT sign transactions or act as wallet signers.
// Their only power is proposing and approving recovery operations. This is
// enforced by design: the contract's signing authority is exclusively through
// __check_auth (which only accepts WebAuthn passkey assertions), and the
// guardian functions use guardian.require_auth() — a separate authority that
// Soroban tracks independently. Guardians are never added to the credential
// list or the CredentialList storage, so they have zero signing capability.
//
// Design decision (flagged per spec): a second initiate_recovery while one is
// pending FAILS with RecoveryAlreadyPending rather than replacing the first.
// Rationale: silent replacement would let an attacker reset the timelock by
// repeatedly calling initiate_recovery. The real owner must cancel first.

use soroban_sdk::Address;

#[contractimpl]
impl PasskeyAccount {
    // -----------------------------------------------------------------------
    // Guardian management — auth required from an existing passkey signer
    // -----------------------------------------------------------------------

    /// Add a guardian address. Guardians can propose and approve recovery operations
    /// when all passkeys are lost. They CANNOT sign transactions or act as wallet
    /// signers under any circumstance — their only power is proposing/approving recovery.
    ///
    /// Adding a guardian requires existing passkey signer auth — same security bar as
    /// add_signer. A guardian cannot be added by another guardian or by recovery itself.
    pub fn add_guardian(env: Env, guardian: Address) {
        env.current_contract_address().require_auth();
        let mut list = get_guardian_list(&env);
        // Deduplicate — adding an existing guardian is a no-op
        for existing in list.iter() {
            if existing == guardian {
                return;
            }
        }
        list.push_back(guardian);
        set_guardian_list(&env, &list);
    }

    /// Remove a guardian address. Requires auth from an existing passkey signer.
    ///
    /// Removing a guardian invalidates any pending recovery immediately, because
    /// the approval set may no longer be valid. The owner must initiate a fresh
    /// recovery after re-establishing the guardian set.
    pub fn remove_guardian(env: Env, guardian: Address) {
        env.current_contract_address().require_auth();
        let list = get_guardian_list(&env);
        let mut new_list: soroban_sdk::Vec<Address> = soroban_sdk::Vec::new(&env);
        for existing in list.iter() {
            if existing != guardian {
                new_list.push_back(existing);
            }
        }
        set_guardian_list(&env, &new_list);
        // Invalidate any pending recovery: the guardian set has changed and the
        // existing approvals may no longer be meaningful.
        clear_pending_recovery(&env);
    }

    /// List all registered guardian addresses.
    pub fn list_guardians(env: Env) -> soroban_sdk::Vec<Address> {
        get_guardian_list(&env)
    }

    /// Set the number of guardian approvals required to execute a recovery.
    /// Must be >= 1 and <= current number of guardians. Invalid values are rejected.
    ///
    /// If never set, execute_recovery defaults to requiring ALL guardians (safest default).
    /// Requires auth from an existing passkey signer.
    pub fn set_recovery_threshold(env: Env, threshold: u32) -> Result<(), AccountError> {
        env.current_contract_address().require_auth();
        let guardian_count = get_guardian_list(&env).len();
        if threshold < 1 || threshold > guardian_count {
            return Err(AccountError::InvalidThreshold);
        }
        set_recovery_threshold(&env, threshold);
        Ok(())
    }

    /// Set the timelock duration (in seconds) that must elapse between initiate_recovery
    /// and execute_recovery. Defaults to 3 days (259200 seconds) if never set.
    /// A guardian CANNOT bypass the timelock under any condition.
    /// Requires auth from an existing passkey signer.
    pub fn set_recovery_timelock(env: Env, seconds: u64) {
        env.current_contract_address().require_auth();
        set_recovery_timelock(&env, seconds);
    }

    // -----------------------------------------------------------------------
    // Recovery flow — guardian operations (NO signing power outside recovery)
    // -----------------------------------------------------------------------

    /// Initiate a recovery request. The proposer must be a registered guardian.
    /// The proposer's initiate call counts as their own approval.
    ///
    /// Only one recovery may be pending at a time. If a recovery is already pending,
    /// this call fails with RecoveryAlreadyPending — the existing owner must cancel
    /// it first via cancel_recovery (requires passkey signer auth).
    pub fn initiate_recovery(
        env: Env,
        proposer: Address,
        new_credential_id: Bytes,
        new_public_key: BytesN<65>,
    ) -> Result<(), AccountError> {
        // Auth required from the proposer (a guardian address, NOT a passkey signer)
        proposer.require_auth();

        // Verify proposer is a registered guardian
        let guardians = get_guardian_list(&env);
        let mut is_guardian = false;
        for g in guardians.iter() {
            if g == proposer {
                is_guardian = true;
                break;
            }
        }
        if !is_guardian {
            return Err(AccountError::NotAGuardian);
        }

        // Reject if a recovery is already pending (no silent replacement)
        if get_pending_recovery(&env).is_some() {
            return Err(AccountError::RecoveryAlreadyPending);
        }

        // Proposer's initiation counts as their own approval
        let mut initial_approvals: soroban_sdk::Vec<Address> = soroban_sdk::Vec::new(&env);
        initial_approvals.push_back(proposer.clone());

        let request = RecoveryRequest {
            proposer,
            new_credential_id,
            new_public_key,
            initiated_at: env.ledger().timestamp(),
            approvals: initial_approvals,
        };
        set_pending_recovery(&env, &request);
        Ok(())
    }

    /// Add an approval to the pending recovery. Callable by any registered guardian.
    /// Rejects non-guardians, duplicate approvals, and calls when no recovery is pending.
    pub fn approve_recovery(env: Env, approver: Address) -> Result<(), AccountError> {
        // Auth required from the approving guardian
        approver.require_auth();

        // Must be a registered guardian
        let guardians = get_guardian_list(&env);
        let mut is_guardian = false;
        for g in guardians.iter() {
            if g == approver {
                is_guardian = true;
                break;
            }
        }
        if !is_guardian {
            return Err(AccountError::NotAGuardian);
        }

        let mut request = get_pending_recovery(&env).ok_or(AccountError::NoRecoveryPending)?;

        // Reject duplicate approvals — cannot double-count
        for already in request.approvals.iter() {
            if already == approver {
                return Err(AccountError::AlreadyApproved);
            }
        }

        request.approvals.push_back(approver);
        set_pending_recovery(&env, &request);
        Ok(())
    }

    /// Execute a pending recovery once ALL conditions are met:
    ///   (a) approvals from CURRENT guardians >= threshold (re-checked at execution time)
    ///   (b) the timelock has elapsed since initiate_recovery
    ///
    /// Callable by anyone — there is no auth requirement. Conditions are verified
    /// atomically at execution time. A guardian removed mid-recovery will not have
    /// their prior approval counted (re-validated against current guardian set).
    pub fn execute_recovery(env: Env) -> Result<(), AccountError> {
        let request = get_pending_recovery(&env).ok_or(AccountError::NoRecoveryPending)?;

        // Re-check timelock at execution time — cannot be bypassed
        let timelock = get_recovery_timelock(&env);
        let now = env.ledger().timestamp();
        if now < request.initiated_at.saturating_add(timelock) {
            return Err(AccountError::TimelockNotElapsed);
        }

        // Re-validate approvals against the CURRENT guardian set at execution time.
        // Approvals from guardians who were removed mid-recovery do NOT count.
        let current_guardians = get_guardian_list(&env);
        let mut valid_approval_count: u32 = 0;
        for approval in request.approvals.iter() {
            for guardian in current_guardians.iter() {
                if guardian == approval {
                    valid_approval_count += 1;
                    break;
                }
            }
        }

        // Effective threshold: if never set, require ALL current guardians (safest default).
        // Also enforce a hard floor of 1: even if threshold was set when there were more
        // guardians, we never allow 0-approval execution (e.g. all guardians removed).
        let configured = get_recovery_threshold(&env).unwrap_or(current_guardians.len());
        let threshold = if configured < 1 { 1u32 } else { configured };

        if valid_approval_count < 1 {
            return Err(AccountError::ThresholdNotMet);
        }
        if valid_approval_count < threshold {
            return Err(AccountError::ThresholdNotMet);
        }

        // Add the recovered credential as a new signer
        let credential = Credential {
            public_key: request.new_public_key,
            counter: 0,
        };
        set_credential(&env, &request.new_credential_id, &credential);
        let mut cred_list = get_credential_list(&env);
        cred_list.push_back(request.new_credential_id);
        set_credential_list(&env, &cred_list);

        // Clear recovery state
        clear_pending_recovery(&env);
        Ok(())
    }

    /// Cancel a pending recovery. Auth required from an existing passkey signer (NOT a guardian).
    /// This lets the real owner abort a malicious or mistaken recovery attempt
    /// while they still have access to at least one passkey.
    pub fn cancel_recovery(env: Env) -> Result<(), AccountError> {
        env.current_contract_address().require_auth();
        get_pending_recovery(&env).ok_or(AccountError::NoRecoveryPending)?;
        clear_pending_recovery(&env);
        Ok(())
    }

    /// Get the current pending recovery request, if any.
    pub fn get_pending_recovery_state(env: Env) -> Option<RecoveryRequest> {
        get_pending_recovery(&env)
    }
}

mod test;
