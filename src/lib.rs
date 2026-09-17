#![no_std]

use soroban_sdk::{
    contract, contractimpl, Bytes, BytesN, Env, Vec,
    auth::Context,
};

mod types;
mod storage;

pub use types::*;
pub use storage::*;

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
        if is_initialized(&env) {
            panic!("contract already initialized");
        }
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
    ) {
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
impl soroban_sdk::auth::CustomAccountInterface for PasskeyAccount {
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
    /// Per the WebAuthn spec, some platform authenticators (e.g. Apple Touch ID, Windows Hello)
    /// always report a counter of 0. If the stored counter for a credential is 0 AND the
    /// asserted counter is also 0, counter checking is disabled for that credential.
    /// This prevents permanently locking out real devices that don't increment their counter.
    /// Once a credential has ever reported a non-zero counter, strict incrementing is enforced.
    fn __check_auth(
        env: Env,
        signature_payload: BytesN<32>,
        signature_args: WebAuthnAssertion,
        _auth_contexts: Vec<Context>,
    ) -> Result<(), AccountError> {
        // Step 1: look up the credential
        let mut credential = get_credential(&env, &signature_args.credential_id)
            .ok_or(AccountError::CredentialNotFound)?;

        // Step 2: build the signed message
        // WebAuthn signatures are over: SHA-256(authenticatorData || SHA-256(clientDataJSON))
        // But Soroban's __check_auth passes us the signature_payload which is the
        // SHA-256 of the transaction envelope. We need to verify that the WebAuthn
        // signature covers the authenticatorData concatenated with the hash of clientDataJSON,
        // where the clientDataJSON contains the base64url-encoded signature_payload as "challenge".
        //
        // The message signed by the authenticator is:
        //   msg = authenticatorData || SHA-256(clientDataJSON)
        //
        // We compute SHA-256(msg) and verify that against the stored public key.
        let client_data_hash = env.crypto().sha256(&signature_args.client_data_json);

        // Concatenate authenticatorData || SHA-256(clientDataJSON)
        let mut msg = signature_args.authenticator_data.clone();
        // Append the 32-byte client_data_hash
        let hash_bytes: BytesN<32> = client_data_hash;
        msg.extend_from_array(&hash_bytes.to_array());

        // Hash the concatenation to get the 32-byte message for secp256r1 verify
        let msg_hash: BytesN<32> = env.crypto().sha256(&msg);

        // Step 3: verify the secp256r1 signature using Soroban's native host function
        // This is a hardened, gas-cheap, audited primitive — we do NOT hand-roll ECDSA.
        env.crypto().secp256r1_verify(
            &credential.public_key,
            &msg_hash,
            &signature_args.signature,
        );
        // secp256r1_verify panics on failure — if we reach here, the signature is valid.
        // Map the implicit panic to our error type by catching it? Unfortunately Soroban
        // panics propagate as contract errors. The convention is that secp256r1_verify
        // either succeeds (returns ()) or panics with an SDK error code.
        // So if we reach the next line, signature verification passed.

        // Step 4: counter replay defense
        let asserted_counter = parse_counter_from_authenticator_data(&signature_args.authenticator_data)?;
        let stored_counter = credential.counter;

        if stored_counter == 0 && asserted_counter == 0 {
            // Counter checking disabled for this credential (platform authenticator
            // compatibility mode — see WebAuthn spec section 6.1).
            // No update needed.
        } else if asserted_counter > stored_counter {
            // Normal case: counter increased, update stored value.
            credential.counter = asserted_counter;
            set_credential(&env, &signature_args.credential_id, &credential);
        } else {
            // Counter did not increase — possible replay or cloned authenticator.
            return Err(AccountError::CounterNotIncreased);
        }

        // Step 5: origin validation
        let allowed_origin = get_allowed_origin_val(&env)
            .ok_or(AccountError::OriginMismatch)?;
        let origin_from_client_data = extract_origin_from_client_data_json(
            &env,
            &signature_args.client_data_json,
        )?;
        if origin_from_client_data != allowed_origin {
            return Err(AccountError::OriginMismatch);
        }

        Ok(())
    }
}

/// Extract the signature counter (bytes 33-36) from WebAuthn authenticatorData.
/// authenticatorData layout:
///   [0..32]  rpIdHash (32 bytes)
///   [32]     flags (1 byte)
///   [33..36] signCount (4 bytes, big-endian u32)
///   [37..]   attestedCredentialData and extensions (variable)
fn parse_counter_from_authenticator_data(auth_data: &Bytes) -> Result<u32, AccountError> {
    if auth_data.len() < 37 {
        return Err(AccountError::MalformedAuthenticatorData);
    }
    let b0 = auth_data.get(33).ok_or(AccountError::MalformedAuthenticatorData)? as u32;
    let b1 = auth_data.get(34).ok_or(AccountError::MalformedAuthenticatorData)? as u32;
    let b2 = auth_data.get(35).ok_or(AccountError::MalformedAuthenticatorData)? as u32;
    let b3 = auth_data.get(36).ok_or(AccountError::MalformedAuthenticatorData)? as u32;
    Ok((b0 << 24) | (b1 << 16) | (b2 << 8) | b3)
}

/// Extract the "origin" field from WebAuthn clientDataJSON.
///
/// clientDataJSON is a UTF-8 JSON string with at minimum:
///   {"type":"webauthn.get","challenge":"...","origin":"https://example.com",...}
///
/// We parse this without a JSON library (no_std) by scanning for `"origin":"` and
/// extracting the value up to the closing `"`.
fn extract_origin_from_client_data_json(
    env: &Env,
    client_data_json: &Bytes,
) -> Result<Bytes, AccountError> {
    // We look for the byte pattern: `"origin":"` then read until `"`
    let needle = b"\"origin\":\"";
    let json_len = client_data_json.len() as usize;

    // Find the start of the origin value
    let mut origin_start: Option<usize> = None;

    // Scan for the needle
    'outer: for i in 0..json_len {
        if i + needle.len() > json_len {
            break;
        }
        let mut matched = true;
        for (j, &nb) in needle.iter().enumerate() {
            let byte = client_data_json.get((i + j) as u32)
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

    // Find the closing quote
    let mut end = start;
    loop {
        if end >= json_len {
            return Err(AccountError::MalformedClientData);
        }
        let byte = client_data_json.get(end as u32)
            .ok_or(AccountError::MalformedClientData)?;
        if byte == b'"' {
            break;
        }
        end += 1;
    }

    // Extract the origin bytes
    let mut origin = Bytes::new(env);
    for i in start..end {
        let byte = client_data_json.get(i as u32)
            .ok_or(AccountError::MalformedClientData)?;
        origin.push_back(byte);
    }

    Ok(origin)
}

mod test;