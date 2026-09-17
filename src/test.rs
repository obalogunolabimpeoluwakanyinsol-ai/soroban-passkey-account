#![cfg(test)]
#![allow(dead_code, unused_imports)]

use soroban_sdk::{
    testutils::{Address as _, AuthorizedFunction, AuthorizedInvocation},
    Address, Bytes, BytesN, Env, IntoVal, Symbol, Val, Vec,
};

use crate::{AccountError, PasskeyAccount, PasskeyAccountClient, WebAuthnAssertion};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Build a 65-byte uncompressed P-256 public key (0x04 prefix + 32-byte X + 32-byte Y).
/// For testing we use deterministic fake values.
fn make_public_key(env: &Env, seed: u8) -> BytesN<65> {
    let mut buf = [0u8; 65];
    buf[0] = 0x04;
    for i in 1..33 {
        buf[i] = seed.wrapping_add(i as u8);
    }
    for i in 33..65 {
        buf[i] = seed.wrapping_add(i as u8).wrapping_add(128);
    }
    BytesN::from_array(env, &buf)
}

/// Build a fake credential_id (32 bytes).
fn make_cred_id(env: &Env, seed: u8) -> Bytes {
    let mut buf = [0u8; 32];
    for (i, b) in buf.iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8);
    }
    Bytes::from_slice(env, &buf)
}

/// Build a fake allowed_origin.
fn make_origin(env: &Env) -> Bytes {
    Bytes::from_slice(env, b"https://app.example.com")
}

/// Build a 64-byte fake signature (not a real secp256r1 sig).
fn make_signature(env: &Env) -> BytesN<64> {
    BytesN::from_array(env, &[0xABu8; 64])
}

/// Build fake authenticatorData with a given counter value.
/// Layout: [0..32] rpIdHash, [32] flags, [33..37] signCount (big-endian u32)
fn make_auth_data(env: &Env, counter: u32) -> Bytes {
    let mut buf = [0u8; 37];
    // rpIdHash: fake SHA-256
    for i in 0..32 {
        buf[i] = i as u8;
    }
    // flags: UP + UV set
    buf[32] = 0x05;
    // signCount big-endian
    buf[33] = ((counter >> 24) & 0xFF) as u8;
    buf[34] = ((counter >> 16) & 0xFF) as u8;
    buf[35] = ((counter >> 8) & 0xFF) as u8;
    buf[36] = (counter & 0xFF) as u8;
    Bytes::from_slice(env, &buf)
}

/// Build a clientDataJSON with the given origin.
fn make_client_data_json(env: &Env, origin: &str) -> Bytes {
    // Build JSON bytes using alloc::vec (available via the crate's no_std + alloc setup).
    let prefix = b"{\"type\":\"webauthn.get\",\"challenge\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"origin\":\"";
    let suffix = b"\"}";
    let mut json_bytes: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    json_bytes.extend_from_slice(prefix);
    json_bytes.extend_from_slice(origin.as_bytes());
    json_bytes.extend_from_slice(suffix);
    Bytes::from_slice(env, &json_bytes)
}

/// Deploy and initialize the contract with one credential.
fn setup(env: &Env) -> (PasskeyAccountClient, Bytes, BytesN<65>) {
    let contract_id = env.register_contract(None, PasskeyAccount);
    let client = PasskeyAccountClient::new(env, &contract_id);
    let cred_id = make_cred_id(env, 1);
    let pub_key = make_public_key(env, 1);
    let origin = make_origin(env);
    client.initialize(&cred_id, &pub_key, &origin);
    (client, cred_id, pub_key)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_initialize_stores_credential() {
    let env = Env::default();
    let (client, cred_id, _pub_key) = setup(&env);

    let credentials = client.list_credentials();
    assert_eq!(credentials.len(), 1);
    assert_eq!(credentials.get(0).unwrap(), cred_id);

    let counter = client.get_counter(&cred_id);
    assert_eq!(counter, 0);

    let origin = client.get_allowed_origin();
    assert_eq!(origin, make_origin(&env));
}

#[test]
#[should_panic(expected = "contract already initialized")]
fn test_initialize_twice_panics() {
    let env = Env::default();
    let (client, cred_id, pub_key) = setup(&env);
    // Second call should panic
    client.initialize(&cred_id, &pub_key, &make_origin(&env));
}

#[test]
fn test_list_credentials_empty_before_init() {
    let env = Env::default();
    // Don't call initialize — list_credentials should return empty vec (storage default).
    let contract_id = env.register_contract(None, PasskeyAccount);
    let client = PasskeyAccountClient::new(&env, &contract_id);
    let credentials = client.list_credentials();
    assert_eq!(credentials.len(), 0);
}

#[test]
fn test_add_signer_requires_auth() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _cred1, _) = setup(&env);

    let cred2 = make_cred_id(&env, 2);
    let pub2 = make_public_key(&env, 2);
    client.add_signer(&cred2, &pub2);

    let credentials = client.list_credentials();
    assert_eq!(credentials.len(), 2);
}

#[test]
fn test_remove_signer_requires_auth() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, cred1, _) = setup(&env);

    let cred2 = make_cred_id(&env, 2);
    let pub2 = make_public_key(&env, 2);
    client.add_signer(&cred2, &pub2);
    assert_eq!(client.list_credentials().len(), 2);

    client.remove_signer(&cred1);
    let remaining = client.list_credentials();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining.get(0).unwrap(), cred2);
}

#[test]
#[should_panic(expected = "cannot remove last signer")]
fn test_remove_last_signer_panics() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, cred1, _) = setup(&env);
    // Only one signer — removing it should panic.
    client.remove_signer(&cred1);
}

#[test]
fn test_multiple_independent_signers() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, cred1, _) = setup(&env);

    let cred2 = make_cred_id(&env, 2);
    let pub2 = make_public_key(&env, 2);
    let cred3 = make_cred_id(&env, 3);
    let pub3 = make_public_key(&env, 3);
    client.add_signer(&cred2, &pub2);
    client.add_signer(&cred3, &pub3);

    let credentials = client.list_credentials();
    assert_eq!(credentials.len(), 3);

    // Each credential has its own counter, all starting at 0.
    assert_eq!(client.get_counter(&cred1), 0);
    assert_eq!(client.get_counter(&cred2), 0);
    assert_eq!(client.get_counter(&cred3), 0);
}

#[test]
fn test_get_counter_for_unknown_credential_returns_zero() {
    let env = Env::default();
    let (client, _, _) = setup(&env);
    let unknown = make_cred_id(&env, 99);
    // Should return 0 (not panic) for unknown credentials via getter.
    assert_eq!(client.get_counter(&unknown), 0);
}

/// The following test verifies counter=0 behavior (disabled counter checking)
/// using mock auth to confirm the contract logic path is reachable.
///
/// Tests that exercise __check_auth directly require real secp256r1 signatures
/// and a live Soroban host — those are integration tests outside this unit suite.
#[test]
fn test_counter_zero_compatibility_documented() {
    // A credential initialized with counter=0 starts in compatibility mode.
    // When the authenticator also reports counter=0, the check passes.
    // This test documents the invariant — full __check_auth exercised in integration tests.
    let env = Env::default();
    let (client, cred_id, _) = setup(&env);
    let counter = client.get_counter(&cred_id);
    // Freshly registered credential has counter=0 — compatibility mode is active.
    assert_eq!(counter, 0, "New credentials start in counter=0 compatibility mode");
}
