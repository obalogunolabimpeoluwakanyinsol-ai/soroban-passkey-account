# soroban-passkey-account

A Soroban custom account contract that lets users authenticate with a **WebAuthn passkey** (Face ID, fingerprint, or hardware security key) instead of holding a seed phrase.

Built for the Stellar network using Soroban's native secp256r1 (P-256) host function for signature verification.

---

## ⚠️ Critical limitation — read before building on this

**If a user loses every registered passkey for their account, the account is permanently unrecoverable.** There is no seed phrase, no guardian recovery, and no override. The account's funds and state are inaccessible forever.

This is an inherent consequence of removing the seed phrase. Social recovery (v2 roadmap) will address this, but it does not exist in v1. If you build a product on top of this contract, you must communicate this limitation prominently to your users.

---

## What is a passkey?

A passkey is a cryptographic credential stored in your device's secure hardware (Secure Enclave on Apple, TPM on Windows, hardware security key). When you authenticate, your device signs a challenge using a private key that **never leaves the device** — not even to you. There is no seed phrase to write down, no password to forget, and no phishing risk for the signing key itself.

WebAuthn is the W3C standard that defines how passkeys work in browsers and native apps. This contract implements the on-chain side of WebAuthn authentication for Soroban.

---

## How it works

```
Browser / App                    Soroban Contract
─────────────────────────────────────────────────────
1. User taps Face ID / fingerprint
2. Device signs:
   authenticatorData || SHA-256(clientDataJSON)
   with the P-256 private key stored in secure hardware
3. App encodes the assertion into signature_args
4. App submits a Soroban transaction calling
   any authorized function
5.                    ──────────────────────────▶
                       __check_auth is called
                       - Look up credential by ID
                       - SHA-256(authenticatorData || SHA-256(clientDataJSON))
                       - secp256r1_verify(pubkey, hash, sig)  ← host function
                       - Check counter > stored counter (replay defense)
                       - Extract "origin" from clientDataJSON
                       - Validate origin against allow-list
                       ◀──────────────────────────
6. Transaction executes (or is rejected)
```

The secp256r1 verification uses Soroban's native host function — not hand-rolled ECDSA. This is audited, gas-cheap, and the correct primitive for this use case.

---

## Contract interface

```rust
// Deploy-time setup
fn initialize(credential_id: Bytes, public_key: BytesN<65>, allowed_origin: Bytes)

// Signer management (both require auth from an existing signer)
fn add_signer(credential_id: Bytes, public_key: BytesN<65>)
fn remove_signer(credential_id: Bytes)  // blocked if last signer

// Getters
fn list_credentials() -> Vec<Bytes>
fn get_counter(credential_id: Bytes) -> u32
fn get_allowed_origin() -> Bytes
```

`__check_auth` is called automatically by the Soroban runtime — your app does not call it directly.

### signature_args format

`__check_auth` expects a `WebAuthnAssertion` struct:

```rust
pub struct WebAuthnAssertion {
    pub credential_id: Bytes,         // which passkey to verify against
    pub authenticator_data: Bytes,    // raw authenticatorData from the WebAuthn response
    pub client_data_json: Bytes,      // raw clientDataJSON from the WebAuthn response
    pub signature: BytesN<64>,        // raw P-256 signature (r || s, 32 bytes each)
}
```

A companion JS SDK for generating this from a browser WebAuthn ceremony is a planned future project (see issues).

---

## Counter=0 compatibility

Some platform authenticators (Apple Touch ID on some devices, Windows Hello, certain hardware keys) always report a signature counter of 0. A strict "counter must always increase" rule would permanently lock out these devices.

**This contract's rule:** if a credential's stored counter is 0 AND the asserted counter in the authenticatorData is also 0, counter checking is disabled for that credential. This matches the WebAuthn spec's own guidance (§6.1). Once a credential has ever reported a non-zero counter, strict incrementing is enforced.

---

## Security properties

| Property | Implementation |
|---|---|
| Signature verification | Soroban native `secp256r1_verify` host function |
| Replay defense | Signature counter checked per credential, stored atomically |
| Origin phishing prevention | `origin` field in clientDataJSON validated against allow-list |
| Multi-device backup | Multiple credentials per account, independent counters |
| Last-signer protection | `remove_signer` blocked when only one credential remains |

---

## Building

```bash
# Install Rust and the wasm32 target
rustup target add wasm32-unknown-unknown

# Build the contract
cargo build --target wasm32-unknown-unknown --release

# Run tests
cargo test
```

---

## License

MIT — see [LICENSE](LICENSE).
