# Architecture

## Overview

`soroban-passkey-account` implements Soroban's custom account interface (`CustomAccountInterface`) to replace the standard Ed25519 signature check with WebAuthn passkey verification. It also implements guardian-based social recovery with a mandatory timelock for accounts where all passkeys are lost.

## WebAuthn ceremony → `signature_args` → `__check_auth`

```
┌─────────────────────────────────────────────────────────────────────┐
│  Browser / Mobile App                                               │
│                                                                     │
│  1. App calls navigator.credentials.get({ challenge: txHash })     │
│     where txHash = SHA-256(Soroban transaction envelope)            │
│                                                                     │
│  2. OS prompts user: Face ID / fingerprint / PIN                    │
│                                                                     │
│  3. Secure hardware signs:                                          │
│     message = authenticatorData || SHA-256(clientDataJSON)          │
│     where clientDataJSON.challenge = base64url(txHash)              │
│                                                                     │
│  4. App receives:                                                   │
│     - authenticatorData  (>=37 bytes, contains rpIdHash + counter)  │
│     - clientDataJSON     (UTF-8 JSON with type, challenge, origin)  │
│     - signature          (P-256 raw 64-byte r||s)                   │
│                                                                     │
│  5. App encodes WebAuthnAssertion { credential_id, authenticator_   │
│     data, client_data_json, signature } and submits the Soroban tx  │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               ▼  Soroban runtime calls __check_auth
┌─────────────────────────────────────────────────────────────────────┐
│  __check_auth(signature_payload: BytesN<32>,                        │
│               signature_args: WebAuthnAssertion,                    │
│               auth_contexts: Vec<Context>)                          │
│                                                                     │
│  Step 1: Look up credential                                         │
│    stored = storage.get(credential_id)                              │
│    → CredentialNotFound if missing                                  │
│                                                                     │
│  Step 2: Build signed message                                       │
│    client_data_hash = SHA-256(clientDataJSON)      <- host fn       │
│    msg = authenticatorData || client_data_hash                      │
│    msg_hash = SHA-256(msg)                         <- host fn       │
│                                                                     │
│  Step 3: Verify signature                                           │
│    env.crypto().secp256r1_verify(                                   │
│      pubkey, msg_hash, signature                                    │
│    )                                               <- host fn       │
│    (panics on failure — Soroban maps to contract error)             │
│                                                                     │
│  Step 4: Counter replay defense                                     │
│    asserted = authenticatorData[33..37] (big-endian u32)            │
│    if stored == 0 && asserted == 0:                                 │
│      skip (counter=0 compatibility mode)                            │
│    elif asserted > stored:                                          │
│      update stored counter                                          │
│    else:                                                            │
│      return Err(CounterNotIncreased)  <- replay detected            │
│                                                                     │
│  Step 5: Origin validation                                          │
│    origin = extract "origin" field from clientDataJSON              │
│    if origin != allowed_origin:                                     │
│      return Err(OriginMismatch)       <- phishing detected          │
│                                                                     │
│  return Ok(())  <- auth approved, transaction executes              │
└─────────────────────────────────────────────────────────────────────┘
```

## Social recovery flow

```
Setup (owner, while passkeys are available):
┌────────────────────────────────────────────────────┐
│ add_guardian(addr)          ← passkey signer auth  │
│ set_recovery_threshold(n)   ← passkey signer auth  │
│ set_recovery_timelock(s)    ← passkey signer auth  │
└────────────────────────────────────────────────────┘

Recovery (when all passkeys are lost):
┌───────────────────────────────────────────────────────────────────┐
│                                                                   │
│  Guardian 1                                                       │
│  initiate_recovery(g1, new_cred_id, new_pubkey)                  │
│  ─────────────────────────────────────────────▶                  │
│                               Pending recovery stored             │
│                               initiated_at = ledger.timestamp()  │
│                               approvals = [g1]  (auto-approved)  │
│                                                                   │
│  Guardian 2                                                       │
│  approve_recovery(g2)                                             │
│  ─────────────────────────────────────────────▶                  │
│                               approvals = [g1, g2]               │
│                                                                   │
│  ← timelock duration elapses (default 3 days) →                  │
│                                                                   │
│  Anyone calls execute_recovery()                                  │
│  ─────────────────────────────────────────────▶                  │
│                               Re-verify at execution time:        │
│                               - timelock elapsed?         Y       │
│                               - valid approvals ≥ threshold? Y   │
│                               (re-check against CURRENT guardians)│
│                               Add new_cred as signer              │
│                               Clear pending recovery              │
│                                                                   │
│  OR: Owner calls cancel_recovery() with passkey signer auth       │
│  ─────────────────────────────────────────────▶                  │
│                               Pending recovery cleared            │
│                               New initiate can start fresh        │
└───────────────────────────────────────────────────────────────────┘
```

## secp256r1_verify host function

Soroban exposes `env.crypto().secp256r1_verify(pubkey, hash, sig)` as a native host function. This is:

- **Audited** — implemented in the Soroban host, not in contract code
- **Gas-cheap** — native host calls cost far less than equivalent Wasm computation
- **Correct** — no hand-rolled ECDSA; we do not implement this ourselves

The public key is an uncompressed P-256 point: `0x04 || X (32 bytes) || Y (32 bytes)` = 65 bytes total.

The signature is raw 64 bytes: `r (32 bytes) || s (32 bytes)`. WebAuthn authenticators produce DER-encoded signatures — the companion JS SDK (future project) is responsible for converting DER to raw before encoding into `signature_args`.

## Storage layout

All state uses Soroban persistent storage (survives ledger archival when TTL is maintained):

| Key | Type | Description |
|---|---|---|
| `DataKey::Credential(id)` | `Credential { public_key, counter }` | Per-credential state |
| `DataKey::CredentialList` | `Vec<Bytes>` | Ordered list of registered credential IDs |
| `DataKey::AllowedOrigin` | `Bytes` | The configured origin allow-list |
| `DataKey::Initialized` | `bool` | Initialization guard |
| `DataKey::GuardianList` | `Vec<Address>` | Registered guardian addresses |
| `DataKey::RecoveryThreshold` | `u32` | Approval threshold (default: ALL guardians) |
| `DataKey::RecoveryTimelock` | `u64` | Timelock in seconds (default: 259200 / 3 days) |
| `DataKey::PendingRecovery` | `RecoveryRequest` | In-flight recovery state, if any |

**Critical invariant:** Guardian addresses and passkey credentials are stored in completely separate storage keys and separate types (`Address` vs `Bytes`). Guardians are never added to `CredentialList`. This is the structural separation that prevents guardians from acquiring signing power.

## Counter=0 compatibility

Per WebAuthn spec §6.1, authenticators are permitted to always report a counter of 0. The rule:

- `stored=0 AND asserted=0` → counter checking disabled (compatibility mode)
- `asserted > stored` → update stored counter (normal operation)
- `asserted == stored` with `stored > 0` → reject (replay or counter reset)
- `asserted < stored` → reject (replay or cloned authenticator)

## Remove-last-signer protection

`remove_signer` checks `list.len() <= 1` before removing. If only one signer remains, it panics. This is a hard guard — there is no override. Social recovery (now implemented) is the path back in if all passkeys are lost.

## Guardian security model

Guardians CANNOT sign transactions or act as wallet signers. Their authorization mechanism is entirely separate from the contract's signing authority:

- **Signing authority** (`__check_auth`): accepts only WebAuthn assertions. Guardians cannot produce these.
- **Guardian operations** (`initiate_recovery`, `approve_recovery`): use `guardian.require_auth()`, which the Soroban runtime treats as an independent authority for that specific address. This auth does NOT grant access to any contract function that calls `env.current_contract_address().require_auth()`.

In other words: a guardian satisfying `guardian.require_auth()` for the recovery functions does NOT satisfy the `env.current_contract_address().require_auth()` check required by `add_signer`, `add_guardian`, `cancel_recovery`, etc. These are structurally distinct authorization checks with no overlap.

## Module structure

```
src/
├── lib.rs        Contract entry point, __check_auth implementation, social recovery
├── types.rs      Credential, WebAuthnAssertion, RecoveryRequest, AccountError types
├── storage.rs    Storage key enum and typed read/write helpers (incl. recovery state)
└── test.rs       Unit tests (existing passkey + new recovery tests)
```
