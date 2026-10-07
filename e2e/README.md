# e2e — End-to-end tests for soroban-passkey-account

This directory contains everything needed to exercise the `PasskeyAccount` Soroban
contract end-to-end: credential registration in a real browser, Node.js scripts
that build, sign, and submit transactions, negative-case tests, and a 10x happy-path
stress test.

## Prerequisites

- Node.js ≥ 18
- A Chromium-based browser (Chrome, Edge) or Firefox 90+ for WebAuthn
- A funded Stellar testnet account (fee-payer; XLM only, no trust lines needed)
- The contract deployed on testnet (constructor ran with your credential's data)

## Quick start

```sh
cd e2e
npm install
```

## Files

| File | Purpose |
|------|---------|
| `server.js`   | Tiny static HTTP server — serves `e2e/` at `http://localhost:8080` |
| `index.html`  | WebAuthn credential registration page |
| `sign.js`     | Happy-path: `add_guardian` via real or mock WebAuthn sign |
| `negative.js` | Negative cases: wrong challenge, wrong origin, wrong type, bad sig, replay |
| `happy10.js`  | Happy path × 10 with pass/fail reporting |
| `package.json`| npm metadata and run scripts |

---

## Step 1 — Register a credential (browser)

Start the server:

```sh
node e2e/server.js
```

Open `http://localhost:8080` in your browser and click **Create Credential**.
Your platform authenticator (Touch ID / Windows Hello / FIDO2 key) will run.

The page prints:

- **`credential_id_hex`** — pass as `credential_id` to `__constructor`
- **`public_key_hex`** — pass as `public_key` (65-byte uncompressed P-256) to `__constructor`
- **`origin`** — will be `http://localhost:8080`

Click **Copy JSON** to copy the full JSON blob; save it as `e2e/cred.json`.

For automated/mock-sign mode, add the private key to `cred.json`:

```json
{
  "credential_id_hex": "...",
  "public_key_hex": "...",
  "origin": "http://localhost:8080",
  "private_key_hex": "<32-byte P-256 private key scalar, 64 hex chars>"
}
```

**Never commit `cred.json`** — it is listed in `.gitignore`.

---

## Step 2 — Deploy the contract

Using the Stellar CLI:

```sh
stellar contract deploy \
  --wasm target/wasm32-unknown-unknown/release/soroban_passkey_account.wasm \
  --source <YOUR_SECRET_KEY> \
  --network testnet \
  -- \
  --credential-id $(node -e "const c=require('./e2e/cred.json'); process.stdout.write(c.credential_id_hex)") \
  --public-key $(node -e "const c=require('./e2e/cred.json'); process.stdout.write(c.public_key_hex)") \
  --allowed-origin "http://localhost:8080"
```

Note the contract ID printed on success (starts with `C`).

---

## Step 3 — Happy-path: add a guardian (real WebAuthn)

```sh
export FEEPAYER_SECRET=S...          # your funded fee-payer account secret
export CONTRACT_ID=C...              # from Step 2

node e2e/sign.js \
  --cred e2e/cred.json \
  --contract $CONTRACT_ID \
  --guardian G... \                  # any Stellar address to add as guardian
  --network testnet
```

When prompted, the script will print a URL like:

```
http://localhost:8080/?sign=<challenge_hex>#<challenge_b64url>
```

Open the URL in your browser (server must be running from Step 1).
The `index.html` page will automatically detect the `?sign=` parameter, call
`navigator.credentials.get()` with the challenge, and display the assertion JSON.

Copy the JSON and paste it into the terminal, then press Enter twice.

The script will:
1. Convert the DER signature to raw 64-byte r∥s (low-S normalised)
2. Assemble the `WebAuthnAssertion` ScVal (keys alphabetically sorted)
3. Re-simulate and submit the authorised transaction
4. Poll until finalised
5. Call `list_guardians` and print the result

### Mock-sign mode (no browser needed)

Requires `private_key_hex` in `cred.json`:

```sh
node e2e/sign.js \
  --cred e2e/cred.json \
  --contract $CONTRACT_ID \
  --guardian G... \
  --network testnet \
  --mock-sign
```

---

## Step 4 — Negative tests

```sh
export FEEPAYER_SECRET=S...
export CONTRACT_ID=C...

node e2e/negative.js \
  --cred e2e/cred.json \
  --contract $CONTRACT_ID \
  --guardian G... \
  --network testnet
```

Expected output:

```
[1] Wrong-payload challenge...
  ✓ PASS: Wrong-payload challenge → ChallengeMismatch (16)
[2] Wrong origin...
  ✓ PASS: Wrong origin → OriginMismatch (4)
[3] Wrong type (webauthn.create)...
  ✓ PASS: Wrong type → InvalidType (17)
[4] Bit-flipped signature...
  ✓ PASS: Bit-flipped signature → rejected (...)
[5] Replay (old signature against new simulation)...
  ✓ PASS: Replay → rejected (...)

=== Negative tests: 5 passed, 0 failed ===
```

### What each case tests

| # | Case | Expected error |
|---|------|----------------|
| 1 | `challenge` in clientDataJSON is SHA-256 of the wrong bytes | `ChallengeMismatch` (16) |
| 2 | `origin` in clientDataJSON is `http://evil.example.com` | `OriginMismatch` (4) |
| 3 | `type` in clientDataJSON is `webauthn.create` | `InvalidType` (17) |
| 4 | Single bit flipped in the raw 64-byte signature | host panic / `InvalidSignature` (5) |
| 5 | Old assertion replayed against a fresh simulation (different nonce) | `ChallengeMismatch` (16) |

---

## Step 5 — Happy path × 10

```sh
export FEEPAYER_SECRET=S...
export CONTRACT_ID=C...

node e2e/happy10.js \
  --cred e2e/cred.json \
  --contract $CONTRACT_ID \
  --network testnet
```

Runs 10 sequential `add_guardian` calls, each with a freshly generated random
Stellar keypair as the guardian.  Reports success count at the end.

Expected output:

```
  [1/10] Adding guardian GAAAAAAA... ✓  (abc123def456...)
  [2/10] Adding guardian GBBBBBBB... ✓  (...)
  ...
  [10/10] Adding guardian GKKKKKKKK... ✓  (...)

──────────────────────────────────────────────────
Result: 10/10 iterations succeeded
──────────────────────────────────────────────────

✓ All 10 happy-path iterations completed successfully.
```

---

## Signature format notes

### Why DER → raw 64

WebAuthn authenticators produce ECDSA signatures in ASN.1 DER encoding:

```
30 <len>
  02 <rLen> <r>        -- INTEGER, may have leading 0x00 padding
  02 <sLen> <s>        -- INTEGER, may have leading 0x00 padding
```

The Soroban `secp256r1_verify` host function expects **raw 64 bytes**:
32-byte big-endian `r` followed by 32-byte big-endian `s`.

Additionally, `s` must be **low-S** (`s ≤ n/2` where `n` is the P-256 curve order).
If `s > n/2`, replace it with `n - s`.  Most modern authenticators already produce
low-S, but the conversion normalises it regardless.

The conversion is implemented in `index.html` (browser) and `sign.js` / `negative.js` /
`happy10.js` (Node.js) — see `derToRaw64()` in each file.

### WebAuthnAssertion ScVal layout

The contract struct:

```rust
pub struct WebAuthnAssertion {
    pub authenticator_data: Bytes,
    pub client_data_json: Bytes,
    pub credential_id: Bytes,
    pub signature: BytesN<64>,
}
```

Soroban encodes contract structs as `SCV_MAP` with string keys sorted
**lexicographically**.  Alphabetical order for the four fields is:

1. `authenticator_data`
2. `client_data_json`
3. `credential_id`
4. `signature`

The `buildWebAuthnAssertionScVal()` function in each Node.js script
constructs the map in this exact order.

### The challenge

`__check_auth` receives the `signature_payload` as a `Hash<32>` — the
32-byte SHA-256 of the `SorobanAuthorization` XDR preimage.  The contract
verifies that `clientDataJSON.challenge == base64url(signature_payload)`.

The Node scripts compute this via:

```js
const preimage = xdr.HashIdPreimage.envelopeTypeSorobanAuthorization({
  networkId, nonce, signatureExpirationLedger, invocation
});
const challenge32 = sha256(preimage.toXDR());
// Then: clientDataJSON.challenge = base64url(challenge32)
```

---

## Security notes

- `cred.json` and any file containing `private_key_hex` must **never** be committed.
  The repo's `.gitignore` should include `e2e/cred.json` and `e2e/*.key`.
- `FEEPAYER_SECRET` should be a throwaway testnet key funded with a small amount of XLM.
  Do not reuse a production key.
- The mock-sign mode is for automated CI only.  Real usage requires a hardware or
  platform authenticator via the browser page.

---

## npm scripts

```sh
npm run serve      # Start static server on http://localhost:8080
npm run sign:mock  # Happy-path sign with mock key
npm run negative   # Negative test cases
npm run happy10    # Happy path × 10
npm test           # negative + happy10
```
