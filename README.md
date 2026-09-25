# soroban-passkey-account

A Soroban custom account contract that lets users authenticate with a **WebAuthn passkey** (Face ID, fingerprint, or hardware security key) instead of holding a seed phrase.

Built for the Stellar network using Soroban's native secp256r1 (P-256) host function for signature verification.

---

## Why this matters

Seed phrases are the single biggest UX and security failure point in crypto wallets — they're confusing to create, easy to lose, and dangerous to store. This contract replaces them with Face ID, fingerprint, or a hardware key: authentication people already know how to use, backed by hardware that never exposes the private key.

That's not just a developer convenience. Poor onboarding UX (seed phrases) is a major reason mainstream users avoid crypto applications. A working passkey account model is a building block other Soroban teams can adopt directly, so its benefit compounds across the ecosystem. And with guardian-based social recovery (now implemented), the model is viable for real production products: if a user loses a device, recovery is possible without reintroducing a seed phrase.

---

## What is a passkey?

A passkey is a cryptographic credential stored in your device's secure hardware (Secure Enclave on Apple, TPM on Windows, hardware security key). When you authenticate, your device signs a challenge using a private key that **never leaves the device** — not even to you. There is no seed phrase to write down, no password to forget, and no phishing risk for the signing key itself.

WebAuthn is the W3C standard that defines how passkeys work in browsers and native apps. This contract implements the on-chain side of WebAuthn authentication for Soroban.

---

## Recovery via social guardians

If a user loses every registered passkey, the account can be recovered using a guardian network — trusted contacts (or services) you designate in advance. Guardians cannot sign transactions; their only power is proposing and approving recovery. See [How recovery works](#how-recovery-works) below.

The trust model shifts from "no recovery at all" to "recovery is possible, but guardians are a trust assumption." Choosing bad guardians (or too few) is now the user's risk. This is an explicit tradeoff: it's better than permanent loss, but it requires thoughtful setup.

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

## How recovery works

```
Setup (done in advance while passkeys are available):
  Owner calls add_guardian(addr) for each trusted contact
  Owner calls set_recovery_threshold(n)  ← how many must approve
  Owner calls set_recovery_timelock(s)   ← default: 3 days

Recovery flow (when passkeys are lost):
  Guardian 1                  Guardian 2                  Contract
  ─────────────────────────────────────────────────────────────────
  initiate_recovery(g1, new_cred, new_pubkey)
  ───────────────────────────────────────────▶
                              Pending recovery recorded
                              Timelock clock starts
                              g1's initiation = 1st approval

  approve_recovery(g2)
  ─────────────────────────────────────────────────────▶
                                                         2 approvals ≥ threshold
  ← wait timelock duration →

  execute_recovery() [callable by anyone]
  ──────────────────────────────────────────────────────▶
                                                         Re-check: approvals ≥ threshold
                                                         Re-check: timelock elapsed
                                                         New credential added as signer
                                                         Pending recovery cleared

  Owner can cancel_recovery() at any time if they still have a passkey
  ──────────────────────────────────────────────────────▶
                                                         Recovery cleared immediately
```

**Security guarantees:**
- The timelock cannot be bypassed by any guardian under any condition
- `execute_recovery` re-checks both timelock and approval count at execution time
- Approvals from guardians removed mid-recovery are discarded at execution time
- If threshold is never set, execute_recovery defaults to requiring ALL guardians
- Guardians have zero signing power — they cannot initiate normal transactions

---

## Contract interface

```rust
// Deploy-time setup
fn initialize(credential_id: Bytes, public_key: BytesN<65>, allowed_origin: Bytes)

// Signer management (auth from existing passkey signer required)
fn add_signer(credential_id: Bytes, public_key: BytesN<65>)
fn remove_signer(credential_id: Bytes)   // blocked if last signer

// Guardian management (auth from existing passkey signer required)
fn add_guardian(guardian: Address)
fn remove_guardian(guardian: Address)
fn list_guardians() -> Vec<Address>
fn set_recovery_threshold(threshold: u32)  // ≥ 1 and ≤ guardian count
fn set_recovery_timelock(seconds: u64)     // default: 259200 (3 days)

// Recovery flow (guardian auth required for initiate/approve; anyone for execute)
fn initiate_recovery(proposer: Address, new_credential_id: Bytes, new_public_key: BytesN<65>) -> Result<(), AccountError>
fn approve_recovery(approver: Address) -> Result<(), AccountError>
fn execute_recovery() -> Result<(), AccountError>
fn cancel_recovery() -> Result<(), AccountError>   // passkey signer auth required

// Getters
fn list_credentials() -> Vec<Bytes>
fn get_counter(credential_id: Bytes) -> u32
fn get_allowed_origin() -> Bytes
fn get_pending_recovery_state() -> Option<RecoveryRequest>
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
| Recovery | Guardian network with mandatory timelock and threshold |
| Guardian isolation | Guardians cannot sign transactions; zero signing power |

---

## Building

```bash
# Install Rust and the wasm32 target
rustup target add wasm32v1-none

# Build the contract
cargo build --target wasm32v1-none --release

# Run tests (note: requires soroban-env-host testutils which has an upstream
# dep conflict with Rust stable — tracked at https://github.com/stellar/rs-soroban-env/issues
# The wasm build above is the primary correctness gate)
cargo test
```

---

## Roadmap

**Shipped:**
- WebAuthn passkey authentication (secp256r1 via Soroban host function)
- Multi-device passkey support (multiple credentials per account)
- Counter-based replay defense with counter=0 compatibility mode
- Origin validation against allow-list
- Guardian-based social recovery with timelock

**Planned:**
- Companion JavaScript SDK for browser WebAuthn ceremony encoding (see issue #3)
- Session keys / per-transaction spending limits for high-frequency UX (see issue #2)

---

## License

MIT — see [LICENSE](LICENSE).
