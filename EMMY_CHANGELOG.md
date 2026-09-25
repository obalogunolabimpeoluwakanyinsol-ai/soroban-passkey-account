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
