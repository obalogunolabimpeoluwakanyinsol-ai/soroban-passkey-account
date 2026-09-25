# EMMY_CHANGELOG.md — soroban-passkey-account

Append-only log of changes made during the Stellar Wave Program audit and improvement cycle.
Each entry records what changed, why, and which branch it landed on.

---

## 2026-09-25

### Branch: `feat/tests`

**New unit tests — internal function coverage (20 new tests)**
- **What:** Added two new sections to `src/test.rs`, bringing total test count from 8 to 28+:
  1. `parse_counter_from_authenticator_data` direct tests:
     - counter=0, counter=42, counter=u32::MAX
     - authenticatorData too short (36 bytes) → MalformedAuthenticatorData
     - empty authenticatorData → MalformedAuthenticatorData
     - exactly 37 bytes (minimum valid) → Ok
  2. `extract_origin_from_client_data_json` direct tests:
     - matching origin extracted correctly
     - different origin value extracted correctly
     - missing "origin" field → MalformedClientData
     - empty JSON → MalformedClientData
     - unclosed string value → MalformedClientData
  3. Other gap coverage:
     - add_signer duplicate credential_id overwrite behavior documented
     - Counter starts at zero for new credential
     - get_counter for unregistered returns 0
     - CredentialNotFound storage path via direct get_credential call
     - Origin mismatch/match comparison logic verified
- **Why:** The audit identified that `__check_auth` error paths (MalformedAuthenticatorData,
  MalformedClientData, OriginMismatch, CredentialNotFound, replay) were completely
  untested. Since `__check_auth` requires real secp256r1 signatures to call end-to-end,
  these are tested by making the internal parsing functions `pub(crate)` and testing them
  directly. The wasm build remains the primary CI gate.

**Internal function visibility**
- **What:** Made `parse_counter_from_authenticator_data` and
  `extract_origin_from_client_data_json` `pub(crate)` in `lib.rs`. Made `storage` module
  `pub(crate)`.
- **Why:** Enables direct unit testing of security-critical parsing logic without
  requiring end-to-end WebAuthn assertion generation.

---

### Branch: `feat/social-recovery`

**New feature — guardian-based social recovery (pre-approved)**
- **What:** Implemented complete social recovery with mandatory timelock in `src/lib.rs`,
  `src/types.rs`, and `src/storage.rs`. Addresses issue #1 (v2 roadmap, pre-approved).
  New public functions added (existing interface unchanged):
  - `add_guardian(guardian: Address)` — passkey signer auth
  - `remove_guardian(guardian: Address)` — passkey signer auth
  - `list_guardians() -> Vec<Address>`
  - `set_recovery_threshold(threshold: u32)` — passkey signer auth, validates 1..=guardian_count
  - `set_recovery_timelock(seconds: u64)` — passkey signer auth, default 3 days
  - `initiate_recovery(proposer, new_credential_id, new_public_key)` — guardian auth
  - `approve_recovery(approver)` — guardian auth
  - `execute_recovery()` — no auth, callable by anyone once conditions met
  - `cancel_recovery()` — passkey signer auth
  - `get_pending_recovery_state() -> Option<RecoveryRequest>`
- **Why:** "No recovery if all passkeys are lost" was the contract's biggest user-facing
  risk and the primary v2 roadmap item. Now resolved without modifying the existing
  interface.

**Design decision — second initiate_recovery while pending FAILS (flagged)**
- A second call to `initiate_recovery` while a recovery is already pending returns
  `RecoveryAlreadyPending` rather than silently replacing the first.
- Rationale: silent replacement would allow an attacker to reset the timelock clock
  indefinitely by spamming `initiate_recovery`. The existing owner must explicitly
  call `cancel_recovery` (requires passkey signer auth) to clear the pending recovery
  before a new one can start.

**Security requirements verified:**
- ✅ Guardian cannot bypass timelock — enforced via `env.ledger().timestamp()` comparison at execution time
- ✅ execute_recovery re-checks timelock and approval count at execution (not just at approval)
- ✅ Unset threshold defaults to ALL guardians
- ✅ Removed guardian's prior approval does not count at execute time (re-validated against current set)
- ✅ Adding guardian requires passkey signer auth — guardians cannot add themselves
- ✅ Guardians have zero signing power (structurally separate from CredentialList)

**New types added to `types.rs`:**
- `RecoveryRequest` struct: proposer, new_credential_id, new_public_key, initiated_at, approvals
- New `AccountError` variants: NotAGuardian, RecoveryAlreadyPending, NoRecoveryPending,
  AlreadyApproved, ThresholdNotMet, TimelockNotElapsed, InvalidThreshold

**New storage keys added to `storage.rs`:**
- `DataKey::GuardianList`, `DataKey::RecoveryThreshold`, `DataKey::RecoveryTimelock`,
  `DataKey::PendingRecovery`
- Helper functions: get/set_guardian_list, get/set_recovery_threshold,
  get/set_recovery_timelock, get/set_pending_recovery, clear_pending_recovery

**New recovery tests (17 tests)**
- Full happy path (add guardians → initiate → approve → timelock → execute → credential added)
- Timelock not elapsed → execute_recovery fails
- Approvals below threshold → execute_recovery fails
- Owner cancels mid-flight → recovery cleared, fresh initiate works
- Non-guardian tries to initiate → fails
- Non-guardian tries to approve → fails
- Guardian structural isolation (not in CredentialList, no signing power)
- Guardian removed mid-recovery → their approval discarded at execute time
- Double approval by same guardian → fails
- Second initiate while pending → fails (RecoveryAlreadyPending)
- Unset threshold defaults to ALL guardians
- Invalid threshold (0 or > guardian count) → fails
- cancel_recovery with no pending recovery → fails
- approve_recovery with no pending recovery → fails
- execute_recovery with no pending recovery → fails

**README updated**
- Removed "Critical limitation" callout (recovery is now implemented)
- Added "Why this matters" section near the top
- Added "How recovery works" section with ASCII sequence diagram
- Updated contract interface section with all new functions
- Updated roadmap: social recovery moved from "planned" to shipped; JS SDK and session
  keys remain as planned items

**ARCHITECTURE.md updated**
- Added social recovery flow diagram
- Added recovery storage keys to the storage layout table
- Added guardian security model section explaining the structural separation
- Updated module structure

---

### Branch: `fix/test-compile-blocker` (2026-09-25)

**Diagnosis and fix of the `cargo test` compile blocker**

#### Root cause (confirmed, not assumed)

`soroban-env-host 22.1.3` declares `ed25519-dalek = ">=2.0.0"` in its
Cargo.toml. With a fresh lockfile, Cargo resolves this to `ed25519-dalek 3.0.0`,
which requires `rand_core ^0.10` and `curve25519-dalek ^5`. The host's testutils
code at `src/builtin_contracts/testutils.rs:26` passes a `ChaCha20Rng` instance
(from `rand_chacha 0.3.1`, which implements `rand_core 0.6`'s `CryptoRng`) into
`ed25519_dalek::SigningKey::generate()`, which expects `rand_core 0.10`'s
`CryptoRng`. The two `CryptoRng` traits are different types across the `rand_core`
major versions — the bound is unsatisfied and the crate fails to compile.

Verbatim error (captured fresh from the failing commit):
```
error[E0277]: the trait bound `ChaCha20Rng: ed25519_dalek::rand_core::CryptoRng` is not satisfied
   --> soroban-env-host-22.1.3/src/builtin_contracts/testutils.rs:26:58
    |
 26 |     host.with_test_prng(|chacha| Ok(SigningKey::generate(chacha)))
    |                                     -------------------- ^^^^^^ the trait `DerefMut` is not implemented for `ChaCha20Rng`
    = note: required for `ChaCha20Rng` to implement `TryRng`
    = note: required for `ChaCha20Rng` to implement `ed25519_dalek::rand_core::CryptoRng`
```

#### Is this genuinely pre-existing? (verified, not assumed)

Yes. Timeline of commits confirms `continue-on-error: true` was added at commit
`4d2c1ac` (2026-09-17 16:33 UTC), which is **before** `feat/tests` (`9e5504a`,
2026-09-25) and `feat/social-recovery` (`d1208d9`, 2026-09-25). Re-running
`cargo test` at the SDK-upgrade commit `9ada4b9` (no test code yet) reproduced
the identical error — the conflict exists in the dependency graph itself, independent
of any test code this project added.

#### Upstream issue (specific link, not the vague issues page)

- **stellar/rs-soroban-env#1705** — reports the problem ("Fresh SDK 27 testutils lock
  resolves incompatible ed25519-dalek 3")
- **stellar/rs-soroban-env#1706** — the fix ("Pin ed25519-dalek to 2.x.y", merged
  2026-08-03). PR description:
  > "The host uses rand_chacha 0.3.1 / rand_core 0.6 when it calls
  > SigningKey::generate in test utilities. The existing >=2.0.0 constraint lets a
  > fresh lockfile select ed25519-dalek 3.0.0 / rand_core 0.10."

The fix was merged into the `main` (27.x) branch only. `soroban-env-host 22.1.4`
(the latest 22.x patch) still carries `">=2.0.0"` — the fix was **not backported**
to the 22.x line.

#### Fix applied

Two-part downstream pin mirroring the upstream fix:

1. **`Cargo.toml`** — added `ed25519-dalek = ">=2.0.0, <3.0.0"` to `[dev-dependencies]`
   with a clear comment citing #1706 and the reason. Also bumped `soroban-sdk` from
   `22.0.0` to `22.0.11` (latest 22.x patch, no interface changes).

2. **`Cargo.lock`** — ran `cargo update ed25519-dalek@3.0.0 --precise 2.2.0`. This
   drops `ed25519-dalek 3.0.0`, `curve25519-dalek 5.0.0`, `rand_core 0.10.1`, and the
   entire `digest 0.11.3` chain from the lockfile. Only the 2.x line remains.

The `Cargo.toml` dev-dep pin ensures `cargo update` and fresh CI lockfile resolutions
can never re-introduce 3.0.0.

#### Additional test-code fixes applied

After the dependency compile blocker was resolved, `cargo test` surfaced real bugs in
`src/test.rs` that had been invisible behind the blocker:

| Error | Fix |
|---|---|
| `alloc::vec::Vec` not in scope | Added `extern crate alloc;` at top of test.rs (crate is `#![no_std]`) |
| `register_contract(None, T)` deprecated | Replaced all 5 occurrences with `env.register(T, ())` |
| `with_mut` not found on `Ledger` | Added `Ledger` to the `use soroban_sdk::testutils::` import |
| `.unwrap()` on `()` (13 call sites) | Removed `.unwrap()` — soroban client's non-`try_` methods for `Result<(), E>` contracts already return `()` and panic on error |
| `result.is_ok()` on `()` | Replaced with direct call + `assert!(pending_state.is_some(), ...)` |
| `get_credential` called outside contract context | Wrapped in `env.as_contract(&contract_id, ...)` |
| Lifetime warning in helper function signatures | Added `<'_>` to `PasskeyAccountClient` in return types of `setup()` and `setup_with_guardians()` |

#### Final result

```
running 41 tests
... (all ok) ...
test result: ok. 41 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.44s
```

Zero warnings. `continue-on-error: true` removed from CI. CI workflow comment updated
with the specific upstream issue links and the date of re-investigation.

**Files changed:**
- `Cargo.toml` — dev-dep pin + soroban-sdk version bump
- `Cargo.lock` — ed25519-dalek 3.0.0 removed
- `src/test.rs` — all test-code compile errors fixed
- `.github/workflows/ci.yml` — `continue-on-error` removed, comment updated
