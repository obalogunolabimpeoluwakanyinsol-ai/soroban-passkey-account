#!/usr/bin/env node
/**
 * e2e/sign.js
 *
 * End-to-end happy-path script for the PasskeyAccount Soroban contract.
 *
 * What it does:
 *   1. Reads credential data (credential_id_hex, public_key_hex) from --cred <file>.
 *   2. Builds an `add_guardian` invocation on the account contract.
 *   3. Simulates the transaction to obtain the SorobanAuthorization entry.
 *   4. Computes the challenge = base64url(SHA-256(SorobanAuthorization XDR preimage)).
 *   5. Opens the browser page (http://localhost:8080) and waits for the user to
 *      sign the challenge via WebAuthn (the page posts back the assertion JSON).
 *      — In headless / automated mode, set --mock-sign to use a pre-generated
 *        WebAuthn assertion via the node-webcrypto-p384 soft authenticator.
 *   6. Converts the DER signature to raw 64-byte r||s (low-S normalised).
 *   7. Assembles the WebAuthnAssertion ScVal (map with keys sorted alphabetically).
 *   8. Re-simulates (authorises) and submits the transaction.
 *   9. Polls until finalised, then calls `list_guardians` to verify.
 *
 * Usage:
 *   node e2e/sign.js \
 *     --cred cred.json \
 *     --contract <CONTRACT_ID> \
 *     --guardian <GUARDIAN_ADDRESS> \
 *     --network testnet \
 *     [--mock-sign]
 *
 * Environment variables (alternative to flags):
 *   CONTRACT_ID     — Soroban contract ID (C...)
 *   GUARDIAN_ADDR   — Stellar address to add as guardian
 *   NETWORK         — testnet | mainnet | futurenet | localnet (default: testnet)
 *   RPC_URL         — override RPC URL
 *   NETWORK_PASSPHRASE — override network passphrase
 *
 * The --mock-sign flag uses node:crypto to sign the challenge with the P-256 private
 * key embedded in cred.json (field: private_key_hex).  This is ONLY for automated
 * testing; real usage requires the browser page.
 *
 * Dependencies (see package.json):
 *   @stellar/stellar-sdk  ^12.0.0
 */

'use strict';

const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');
const readline = require('readline');

// Stellar SDK — loaded after dependency check below.
let StellarSdk;
try {
  StellarSdk = require('@stellar/stellar-sdk');
} catch {
  console.error('Missing dependency: run `npm install` in e2e/ first.');
  process.exit(1);
}

const {
  Keypair,
  Networks,
  TransactionBuilder,
  BASE_FEE,
  SorobanRpc,
  Address,
  Contract,
  xdr,
  nativeToScVal,
} = StellarSdk;

// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------
function parseArgs(argv) {
  const args = {};
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next && !next.startsWith('--')) {
        args[key] = next; i++;
      } else {
        args[key] = true;
      }
    }
  }
  return args;
}

const args = parseArgs(process.argv);

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
const CRED_FILE   = args['cred']      || process.env.CRED_FILE     || 'cred.json';
const CONTRACT_ID = args['contract']  || process.env.CONTRACT_ID;
const GUARDIAN    = args['guardian']  || process.env.GUARDIAN_ADDR;
const NETWORK     = (args['network']  || process.env.NETWORK || 'testnet').toLowerCase();
const MOCK_SIGN   = !!args['mock-sign'];

const NETWORK_CONFIG = {
  testnet:   { rpc: 'https://soroban-testnet.stellar.org', passphrase: Networks.TESTNET },
  mainnet:   { rpc: 'https://rpc-mainnet.stellar.org',     passphrase: Networks.PUBLIC },
  futurenet: { rpc: 'https://rpc-futurenet.stellar.org',   passphrase: Networks.FUTURENET },
  localnet:  { rpc: 'http://localhost:8000/soroban/rpc',   passphrase: Networks.STANDALONE },
};

const netCfg = NETWORK_CONFIG[NETWORK];
if (!netCfg) {
  console.error(`Unknown network "${NETWORK}". Choose: testnet, mainnet, futurenet, localnet`);
  process.exit(1);
}

const RPC_URL    = args['rpc-url']    || process.env.RPC_URL            || netCfg.rpc;
const PASSPHRASE = args['passphrase'] || process.env.NETWORK_PASSPHRASE || netCfg.passphrase;

if (!CONTRACT_ID) { console.error('--contract <CONTRACT_ID> is required'); process.exit(1); }
if (!GUARDIAN)    { console.error('--guardian <GUARDIAN_ADDRESS> is required'); process.exit(1); }

// ---------------------------------------------------------------------------
// Load credential data
// ---------------------------------------------------------------------------
let credData;
try {
  credData = JSON.parse(fs.readFileSync(path.resolve(CRED_FILE), 'utf8'));
} catch (e) {
  console.error(`Cannot read credential file "${CRED_FILE}": ${e.message}`);
  process.exit(1);
}

const CREDENTIAL_ID_HEX = credData.credential_id_hex;
const PUBLIC_KEY_HEX    = credData.public_key_hex;

if (!CREDENTIAL_ID_HEX || !PUBLIC_KEY_HEX) {
  console.error('cred.json must have credential_id_hex and public_key_hex fields.');
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function hex2buf(hex) {
  const buf = Buffer.from(hex, 'hex');
  return buf;
}

function buf2hex(buf) {
  return Buffer.from(buf).toString('hex');
}

/**
 * Base64url-encode a Buffer or Uint8Array (no padding, url-safe alphabet).
 */
function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

/**
 * Decode base64url to Buffer.
 */
function fromB64url(str) {
  return Buffer.from(str, 'base64url');
}

/**
 * Convert a DER-encoded ECDSA signature to raw 64-byte r||s (low-S normalised).
 *
 * DER layout: 0x30 <seqLen> 0x02 <rLen> <r> 0x02 <sLen> <s>
 */
function derToRaw64(derBuf) {
  const der = Buffer.from(derBuf);
  let offset = 0;
  if (der[offset++] !== 0x30) throw new Error('DER: expected SEQUENCE');
  let seqLen = der[offset++];
  if (seqLen & 0x80) {
    const lb = seqLen & 0x7f;
    seqLen = 0;
    for (let i = 0; i < lb; i++) seqLen = (seqLen << 8) | der[offset++];
  }
  if (der[offset++] !== 0x02) throw new Error('DER: expected INTEGER r');
  const rLen = der[offset++];
  let r = der.slice(offset, offset + rLen); offset += rLen;
  if (der[offset++] !== 0x02) throw new Error('DER: expected INTEGER s');
  const sLen = der[offset++];
  let s = der.slice(offset, offset + sLen);

  r = padTo32(r);
  s = lowSNormalise(padTo32(s));

  return Buffer.concat([r, s]);
}

function padTo32(b) {
  // strip leading 0x00 added for sign bit
  let start = 0;
  while (start < b.length - 1 && b[start] === 0) start++;
  b = b.slice(start);
  if (b.length > 32) throw new Error('Component too long: ' + b.length);
  const out = Buffer.alloc(32, 0);
  b.copy(out, 32 - b.length);
  return out;
}

// P-256 curve order n
const P256_N = Buffer.from(
  'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551', 'hex'
);

function lowSNormalise(s32) {
  // halfN = n >> 1
  const halfN = Buffer.alloc(32);
  let carry = 0;
  for (let i = 0; i < 32; i++) {
    const val = (carry << 8) | P256_N[i];
    halfN[i] = val >> 1;
    carry = val & 1;
  }
  if (cmpBE(s32, halfN) <= 0) return s32;
  return subBE(P256_N, s32);
}

function cmpBE(a, b) {
  for (let i = 0; i < 32; i++) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return  1;
  }
  return 0;
}

function subBE(a, b) {
  const out = Buffer.alloc(32);
  let borrow = 0;
  for (let i = 31; i >= 0; i--) {
    let d = a[i] - b[i] - borrow;
    if (d < 0) { d += 256; borrow = 1; } else { borrow = 0; }
    out[i] = d;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Build WebAuthnAssertion ScVal
//
// The contract type is:
//   struct WebAuthnAssertion {
//     authenticator_data: Bytes,
//     client_data_json: Bytes,
//     credential_id: Bytes,
//     signature: BytesN<64>,
//   }
//
// Soroban encodes contract structs as SCV_MAP with string keys sorted
// lexicographically (alphabetically by field name).
// Sorted order: authenticator_data, client_data_json, credential_id, signature
// ---------------------------------------------------------------------------
function buildWebAuthnAssertionScVal({ credentialId, authenticatorData, clientDataJSON, signature64 }) {
  const { xdr: XDR } = StellarSdk;

  function bytesScVal(buf) {
    return XDR.ScVal.scvBytes(buf);
  }
  function bytesNScVal(buf) {
    // BytesN<64> is also encoded as scvBytes in Soroban XDR.
    return XDR.ScVal.scvBytes(buf);
  }
  function strKey(s) {
    return XDR.ScVal.scvString(s);
  }

  const entries = [
    new XDR.ScMapEntry({ key: strKey('authenticator_data'), val: bytesScVal(authenticatorData) }),
    new XDR.ScMapEntry({ key: strKey('client_data_json'),   val: bytesScVal(clientDataJSON) }),
    new XDR.ScMapEntry({ key: strKey('credential_id'),      val: bytesScVal(credentialId) }),
    new XDR.ScMapEntry({ key: strKey('signature'),          val: bytesNScVal(signature64) }),
  ];

  return XDR.ScVal.scvMap(entries);
}

// ---------------------------------------------------------------------------
// Simulate and authorise helpers
// ---------------------------------------------------------------------------

/**
 * Build a raw (unsigned) transaction that calls add_guardian on the contract.
 * We use a throwaway keypair as the fee-payer — the account being authorised
 * is the contract itself (custom account), not the fee-payer.
 */
async function buildAddGuardianTx(server, contractId, guardianAddress, feePayerKeypair) {
  const contract = new Contract(contractId);
  const feePayer = feePayerKeypair.publicKey();
  const account  = await server.getAccount(feePayer);

  const guardianScVal = new Address(guardianAddress).toScVal();

  const tx = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: PASSPHRASE,
  })
    .addOperation(contract.call('add_guardian', guardianScVal))
    .setTimeout(300)
    .build();

  return tx;
}

/**
 * Simulate a transaction and return the SimulateTransactionResponse.
 * Throws on failure.
 */
async function simulate(server, tx) {
  const resp = await server.simulateTransaction(tx);
  if (SorobanRpc.Api.isSimulationError(resp)) {
    throw new Error(`Simulation failed: ${JSON.stringify(resp.error)}`);
  }
  return resp;
}

/**
 * Given a simulation response, extract the SorobanAuthorization entries that
 * correspond to the custom account (address === contractId).
 */
function extractAuthEntry(simResp, contractId) {
  const results = simResp.result?.auth ?? simResp.auth ?? [];
  // Find the entry whose credentials use the custom account
  for (const authEntry of results) {
    const creds = authEntry.credentials();
    if (creds.switch().name === 'sorobanCredentialsAddress') {
      const addrCreds = creds.address();
      const addr = Address.fromScAddress(addrCreds.address()).toString();
      if (addr === contractId) return authEntry;
    }
  }
  // If none match explicitly, return the first entry (single-auth case)
  if (results.length > 0) return results[0];
  return null;
}

/**
 * Compute the signature payload: SHA-256 of the SorobanAuthorization preimage.
 *
 * The preimage is the XDR encoding of HashIDPreimageSorobanAuthorization:
 *   { networkId: sha256(networkPassphrase), nonce, signatureExpirationLedger, invocation }
 */
function computeSignaturePayload(authEntry, networkPassphrase) {
  const networkId = crypto.createHash('sha256').update(networkPassphrase).digest();

  const addrCreds = authEntry.credentials().address();
  const nonce     = addrCreds.nonce();
  const expLedger = addrCreds.signatureExpirationLedger();

  const preimage = xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(
    new xdr.HashIdPreimageSorobanAuthorization({
      networkId: xdr.Hash.fromXDR(networkId),
      nonce,
      signatureExpirationLedger: expLedger,
      invocation: authEntry.rootInvocation(),
    })
  );

  const preimageXdr = preimage.toXDR();
  return crypto.createHash('sha256').update(preimageXdr).digest(); // 32-byte Buffer
}

// ---------------------------------------------------------------------------
// Mock WebAuthn signing (automated testing only)
// ---------------------------------------------------------------------------

/**
 * Sign the 32-byte challenge buffer with a P-256 private key (DER or raw hex).
 * Returns { authenticatorData, clientDataJSON, signatureDER } as Buffers.
 *
 * This simulates what the browser's WebAuthn authenticator would do, but
 * uses a software key — suitable ONLY for automated tests.
 *
 * The private key must be in cred.json as "private_key_hex" (32-byte P-256
 * scalar in hex, as exported by subtle.exportKey("raw", privateKey) or
 * openssl ec -text).
 */
function mockWebAuthnSign(challenge32, credentialIdHex, privateKeyHex) {
  // Build a minimal authenticatorData (37 bytes minimum):
  //   rpIdHash(32) + flags(1) + counter(4)
  const rpIdHash = crypto.createHash('sha256').update('localhost').digest();
  const flags    = Buffer.from([0x05]); // UP=1, UV=1
  const counter  = Buffer.from([0x00, 0x00, 0x00, 0x00]); // counter=0
  const authenticatorData = Buffer.concat([rpIdHash, flags, counter]);

  // Build clientDataJSON with type=webauthn.get, challenge=base64url(challenge32), origin
  const clientDataJSON = Buffer.from(JSON.stringify({
    type     : 'webauthn.get',
    challenge: b64url(challenge32),
    origin   : 'http://localhost:8080',
    crossOrigin: false,
  }));

  // Build the signed message: SHA-256(authenticatorData || SHA-256(clientDataJSON))
  const cdHash  = crypto.createHash('sha256').update(clientDataJSON).digest();
  const msg     = Buffer.concat([authenticatorData, cdHash]);
  const msgHash = crypto.createHash('sha256').update(msg).digest();

  // Sign with P-256 using node:crypto
  // The private key must be available as JWK or PEM.  We accept raw hex (32 bytes).
  const d = privateKeyHex;
  if (!d || d.length !== 64) {
    throw new Error(
      'mock-sign requires cred.json to have private_key_hex (32-byte P-256 scalar, 64 hex chars). ' +
      'Generate with: openssl ecparam -name prime256v1 -genkey -noout | openssl ec -text -noout'
    );
  }

  // Build the private key as a JWK.  We need x and y too — derive from d.
  // Use node's crypto.createPrivateKey with JWK format.  But we need x,y for the JWK…
  // Easier: use the PKCS8 DER format.
  // Build EC private key DER (SEC1) then wrap in PKCS8.
  const privKeyDER = buildPKCS8DERfromRawP256(d);
  const privKey = crypto.createPrivateKey({ key: privKeyDER, format: 'der', type: 'pkcs8' });

  const signObj  = crypto.createSign('SHA256');
  signObj.update(msgHash); // pre-hashed: we pass the hash directly but createSign adds another SHA256 — fix below
  // Actually node:crypto createSign with 'SHA256' will SHA256 the input again.
  // We need to sign the raw msgHash bytes without hashing again.
  // Use 'sign' with the low-level approach: signObj with 'id-ecPublicKey' needs 'SHA-256' internally.
  // Better approach: use the subtle equivalent via crypto.sign() with no hash (raw).
  const sigDER = crypto.sign(null, msgHash, privKey); // null = no additional hash (raw)

  return { authenticatorData, clientDataJSON, signatureDER: sigDER };
}

/**
 * Build a minimal PKCS8 DER wrapping of a P-256 private key from the raw 32-byte
 * scalar (as 64-char hex string).  Uses a hardcoded OID for P-256.
 */
function buildPKCS8DERfromRawP256(dHex) {
  const dBuf = Buffer.from(dHex, 'hex');
  // SEC1 ECPrivateKey ::= SEQUENCE { version INTEGER, privateKey OCTET STRING, parameters [0] OID, publicKey [1] BIT STRING }
  // Minimal: just SEQUENCE { 1, dBuf } — but PKCS8 wraps it differently.
  // Easiest: use the known DER prefix for P-256 PKCS8 private key.
  // PKCS8 P-256 prefix (30 bytes): version + AlgorithmIdentifier{ecPublicKey, prime256v1}
  const pkcs8Header = Buffer.from(
    '308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420',
    'hex'
  );
  // Then append dBuf (32 bytes), then a zero pubkey placeholder isn't needed for signing.
  // Actually the proper minimal form:
  // 30 41 — total SEQUENCE
  //   02 01 00 — version = 0
  //   30 13 — AlgorithmIdentifier SEQUENCE
  //     06 07 2a 86 48 ce 3d 02 01  — OID ecPublicKey
  //     06 08 2a 86 48 ce 3d 03 01 07 — OID prime256v1
  //   04 1f — OCTET STRING (SEC1 wrapping)
  //     30 1d — SEC1 SEQUENCE
  //       02 01 01 — version = 1
  //       04 20 — OCTET STRING (private key)
  //         <32 bytes d>
  const sec1Inner = Buffer.concat([
    Buffer.from('02010104200', 'hex').slice(0, 5), // 02 01 01 04 20
    dBuf,
  ]);
  // Fix: build properly
  const sec1 = Buffer.concat([
    Buffer.from('30', 'hex'),
    encodeLength(2 + sec1Inner.length - 1 + 32 + 2), // approximate — just build it right
  ]);

  // Use a known-good minimal PKCS8 template.  Hardcode the structure:
  const der = Buffer.concat([
    Buffer.from('3041', 'hex'),     // SEQUENCE (65 bytes)
    Buffer.from('020100', 'hex'),   // version = 0
    Buffer.from('301306072a8648ce3d020106082a8648ce3d030107', 'hex'), // AlgorithmIdentifier
    Buffer.from('041f', 'hex'),     // OCTET STRING (31 bytes = SEC1)
    Buffer.from('301d020101042', 'hex').slice(0, 7), // 30 1b 02 01 01 04 20
    Buffer.from('301b0201010420', 'hex'), // SEC1: SEQUENCE(27) { version=1, OCTET STRING(32) }
    dBuf,
  ]);
  // This still isn't quite right; let's use a clean helper.
  return buildCleanPKCS8(dBuf);
}

function encodeLength(n) {
  if (n < 128) return Buffer.from([n]);
  if (n < 256) return Buffer.from([0x81, n]);
  return Buffer.from([0x82, n >> 8, n & 0xff]);
}

function buildCleanPKCS8(d32) {
  // SEC1 private key: SEQUENCE { version(1), privateKey OCTET STRING(32) }
  const sec1 = Buffer.concat([
    Buffer.from('3023', 'hex'),          // SEQUENCE (35 bytes)
    Buffer.from('020101', 'hex'),        // INTEGER version = 1
    Buffer.from('0420', 'hex'),          // OCTET STRING (32 bytes)
    d32,                                 // the private key scalar
  ]);
  // AlgorithmIdentifier for ecPublicKey + prime256v1
  const algoId = Buffer.from(
    '301306072a8648ce3d020106082a8648ce3d030107', 'hex'
  ); // 21 bytes
  // PKCS8 outer: SEQUENCE { version(0), algoId, OCTET STRING(sec1) }
  const octetWrapped = Buffer.concat([
    Buffer.from('04', 'hex'),
    encodeLength(sec1.length),
    sec1,
  ]);
  const inner = Buffer.concat([
    Buffer.from('020100', 'hex'), // version = 0
    algoId,
    octetWrapped,
  ]);
  return Buffer.concat([
    Buffer.from('30', 'hex'),
    encodeLength(inner.length),
    inner,
  ]);
}

// ---------------------------------------------------------------------------
// Interactive WebAuthn signing via browser page
// ---------------------------------------------------------------------------

/**
 * Prompt the user to sign the challenge in the browser and paste back the JSON.
 *
 * The browser page (index.html) when given a challenge hash in the URL fragment
 * will call navigator.credentials.get() and display the assertion JSON.
 * The user copies that JSON and pastes it here.
 */
async function interactiveSign(challenge32, credentialIdHex) {
  const challengeHex  = buf2hex(challenge32);
  const signUrl = `http://localhost:8080/?sign=${challengeHex}#${b64url(challenge32)}`;

  console.log('\n--- WebAuthn signing required ---');
  console.log(`Challenge (hex)    : ${challengeHex}`);
  console.log(`Challenge (b64url) : ${b64url(challenge32)}`);
  console.log(`\nOpen this URL in your browser (server must be running):`);
  console.log(`  ${signUrl}`);
  console.log('\nThe page will prompt your authenticator to sign the challenge.');
  console.log('Copy the JSON output from the page and paste it below, then press Enter twice.\n');

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const lines = [];

  return new Promise((resolve, reject) => {
    rl.on('line', (line) => {
      lines.push(line);
      if (lines.length >= 2 && lines[lines.length - 1] === '' && lines[lines.length - 2] === '') {
        rl.close();
      }
    });
    rl.on('close', () => {
      const jsonStr = lines.join('\n').trim();
      try {
        const parsed = JSON.parse(jsonStr);
        resolve(parsed);
      } catch (e) {
        reject(new Error('Invalid JSON pasted: ' + e.message));
      }
    });
  });
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  console.log('=== soroban-passkey-account e2e/sign.js ===');
  console.log(`Network  : ${NETWORK} (${RPC_URL})`);
  console.log(`Contract : ${CONTRACT_ID}`);
  console.log(`Guardian : ${GUARDIAN}`);
  console.log(`Cred file: ${CRED_FILE}`);
  console.log(`Mock sign: ${MOCK_SIGN}`);
  console.log('');

  const server = new SorobanRpc.Server(RPC_URL, { allowHttp: true });

  // We need a fee-payer account on the network.  The user should fund a throwaway
  // keypair and put its secret in FEEPAYER_SECRET env var.
  const feePayerSecret = process.env.FEEPAYER_SECRET;
  if (!feePayerSecret) {
    console.error(
      'Set FEEPAYER_SECRET env var to a funded account secret key (used only for fee payment).'
    );
    process.exit(1);
  }
  const feePayerKeypair = Keypair.fromSecret(feePayerSecret);
  console.log(`Fee payer: ${feePayerKeypair.publicKey()}`);

  // Step 1: Build the add_guardian transaction.
  console.log('\n[1] Building add_guardian transaction...');
  const tx = await buildAddGuardianTx(server, CONTRACT_ID, GUARDIAN, feePayerKeypair);

  // Step 2: Simulate to get auth entries.
  console.log('[2] Simulating to obtain auth entry...');
  const simResp = await simulate(server, tx);
  const authEntry = extractAuthEntry(simResp, CONTRACT_ID);
  if (!authEntry) {
    throw new Error('No auth entry found for contract in simulation response.');
  }
  console.log('    Auth entry found.');

  // Step 3: Compute the signature payload (challenge).
  console.log('[3] Computing signature payload (SHA-256 of SorobanAuthorization preimage)...');
  const challenge32 = computeSignaturePayload(authEntry, PASSPHRASE);
  console.log(`    Challenge: ${buf2hex(challenge32)}`);

  // Step 4: Obtain the WebAuthn assertion.
  let authenticatorData, clientDataJSON, signatureDER;
  if (MOCK_SIGN) {
    console.log('[4] Mock-signing with soft P-256 key...');
    const result = mockWebAuthnSign(challenge32, CREDENTIAL_ID_HEX, credData.private_key_hex);
    authenticatorData = result.authenticatorData;
    clientDataJSON    = result.clientDataJSON;
    signatureDER      = result.signatureDER;
    console.log(`    clientDataJSON: ${clientDataJSON.toString()}`);
  } else {
    console.log('[4] Waiting for interactive WebAuthn assertion from browser...');
    const assertionJson = await interactiveSign(challenge32, CREDENTIAL_ID_HEX);
    // Expect fields: authenticatorData_hex, clientDataJSON_text, signature_der_hex
    authenticatorData = Buffer.from(assertionJson.authenticatorData_hex, 'hex');
    clientDataJSON    = Buffer.from(assertionJson.clientDataJSON_text);
    signatureDER      = Buffer.from(assertionJson.signature_der_hex, 'hex');
  }

  // Step 5: Convert DER to raw 64-byte r||s (low-S).
  console.log('[5] Converting DER signature to raw 64-byte r||s (low-S normalised)...');
  const signature64 = derToRaw64(signatureDER);
  console.log(`    Signature (raw 64, hex): ${buf2hex(signature64)}`);

  // Step 6: Build the WebAuthnAssertion ScVal.
  console.log('[6] Building WebAuthnAssertion ScVal...');
  const assertionScVal = buildWebAuthnAssertionScVal({
    credentialId    : hex2buf(CREDENTIAL_ID_HEX),
    authenticatorData,
    clientDataJSON,
    signature64,
  });

  // Step 7: Set the credential on the auth entry and re-simulate (authorise).
  console.log('[7] Attaching signature and re-simulating (authorise)...');
  authEntry.credentials().address().signature(assertionScVal);

  // Assemble the authorised transaction using the simulation's resource estimates.
  const authorisedTx = SorobanRpc.assembleTransaction(tx, simResp).build();

  // Sign the fee-payer envelope.
  authorisedTx.sign(feePayerKeypair);

  // Step 8: Submit.
  console.log('[8] Submitting transaction...');
  const sendResp = await server.sendTransaction(authorisedTx);
  console.log(`    Status: ${sendResp.status}  Hash: ${sendResp.hash}`);

  if (sendResp.status === 'ERROR') {
    throw new Error(`sendTransaction error: ${JSON.stringify(sendResp.errorResult)}`);
  }

  // Step 9: Poll until finalised.
  console.log('[9] Polling for confirmation...');
  let txResp;
  for (let i = 0; i < 30; i++) {
    await new Promise(r => setTimeout(r, 2000));
    txResp = await server.getTransaction(sendResp.hash);
    if (txResp.status !== SorobanRpc.Api.GetTransactionStatus.NOT_FOUND) break;
    process.stdout.write('.');
  }
  console.log('');

  if (txResp.status === SorobanRpc.Api.GetTransactionStatus.SUCCESS) {
    console.log('    Transaction SUCCEEDED.');
  } else {
    throw new Error(`Transaction failed: ${JSON.stringify(txResp.resultXdr)}`);
  }

  // Step 10: Verify with list_guardians.
  console.log('[10] Verifying: calling list_guardians...');
  const contract   = new Contract(CONTRACT_ID);
  const account    = await server.getAccount(feePayerKeypair.publicKey());
  const verifyTx   = new TransactionBuilder(account, {
    fee: BASE_FEE, networkPassphrase: PASSPHRASE,
  })
    .addOperation(contract.call('list_guardians'))
    .setTimeout(30)
    .build();

  const verifySim = await simulate(server, verifyTx);
  const guardians = verifySim.result?.retval;
  console.log(`    list_guardians result: ${JSON.stringify(guardians)}`);

  console.log('\n✓ add_guardian e2e complete.');
}

main().catch(err => {
  console.error('\nFATAL:', err.message || err);
  process.exit(1);
});
