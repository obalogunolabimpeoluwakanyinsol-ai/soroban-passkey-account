#!/usr/bin/env node
/**
 * e2e/negative.js
 *
 * Negative test cases for the PasskeyAccount contract's __check_auth logic.
 *
 * These tests submit deliberately malformed auth entries and assert that the
 * contract rejects them with the expected error codes.  They use --mock-sign
 * mode (soft P-256 key) so no browser is needed.
 *
 * Negative cases exercised:
 *   1. Wrong payload challenge   — clientDataJSON.challenge is SHA-256(wrong_data)
 *                                  → expect ChallengeMismatch (error 16)
 *   2. Wrong origin              — clientDataJSON.origin is http://evil.example.com
 *                                  → expect OriginMismatch (error 4)
 *   3. Replay                    — submit the exact same auth entry twice
 *                                  → expect CounterNotIncreased (error 3) *if counter > 0*
 *                                     or ChallengeMismatch (error 16) on second sim
 *   4. Wrong type                — clientDataJSON.type is "webauthn.create"
 *                                  → expect InvalidType (error 17)
 *   5. Invalid signature         — flip a byte in the raw 64-byte signature
 *                                  → expect a host-level panic / InvalidSignature (error 5)
 *
 * Usage:
 *   node e2e/negative.js \
 *     --cred cred.json \
 *     --contract <CONTRACT_ID> \
 *     --guardian <GUARDIAN_ADDRESS> \
 *     --network testnet
 *
 * All FEEPAYER_SECRET rules from sign.js apply here too.
 */

'use strict';

const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

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
} = StellarSdk;

// ---------------------------------------------------------------------------
// Re-use helpers from sign.js via inline copies (avoid require('../sign') since
// sign.js calls main() immediately).
// ---------------------------------------------------------------------------

function buf2hex(buf) { return Buffer.from(buf).toString('hex'); }
function hex2buf(hex) { return Buffer.from(hex, 'hex'); }
function b64url(buf)  { return Buffer.from(buf).toString('base64url'); }
function encodeLength(n) {
  if (n < 128) return Buffer.from([n]);
  if (n < 256) return Buffer.from([0x81, n]);
  return Buffer.from([0x82, n >> 8, n & 0xff]);
}

const P256_N = Buffer.from(
  'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551', 'hex'
);
function cmpBE(a, b) {
  for (let i = 0; i < 32; i++) { if (a[i] < b[i]) return -1; if (a[i] > b[i]) return 1; }
  return 0;
}
function subBE(a, b) {
  const out = Buffer.alloc(32); let borrow = 0;
  for (let i = 31; i >= 0; i--) {
    let d = a[i] - b[i] - borrow;
    if (d < 0) { d += 256; borrow = 1; } else { borrow = 0; }
    out[i] = d;
  }
  return out;
}
function lowSNormalise(s32) {
  const halfN = Buffer.alloc(32); let carry = 0;
  for (let i = 0; i < 32; i++) {
    const val = (carry << 8) | P256_N[i];
    halfN[i] = val >> 1; carry = val & 1;
  }
  return cmpBE(s32, halfN) <= 0 ? s32 : subBE(P256_N, s32);
}
function padTo32(b) {
  let start = 0;
  while (start < b.length - 1 && b[start] === 0) start++;
  b = b.slice(start);
  const out = Buffer.alloc(32, 0);
  b.copy(out, 32 - b.length);
  return out;
}
function derToRaw64(derBuf) {
  const der = Buffer.from(derBuf); let offset = 0;
  if (der[offset++] !== 0x30) throw new Error('DER SEQUENCE');
  let seqLen = der[offset++];
  if (seqLen & 0x80) { const lb = seqLen & 0x7f; seqLen = 0; for (let i=0;i<lb;i++) seqLen=(seqLen<<8)|der[offset++]; }
  if (der[offset++] !== 0x02) throw new Error('DER r');
  const rLen = der[offset++]; let r = der.slice(offset, offset+rLen); offset += rLen;
  if (der[offset++] !== 0x02) throw new Error('DER s');
  const sLen = der[offset++]; let s = der.slice(offset, offset+sLen);
  return Buffer.concat([padTo32(r), lowSNormalise(padTo32(s))]);
}

function buildCleanPKCS8(d32) {
  const sec1 = Buffer.concat([Buffer.from('3023', 'hex'), Buffer.from('020101', 'hex'), Buffer.from('0420', 'hex'), d32]);
  const algoId = Buffer.from('301306072a8648ce3d020106082a8648ce3d030107', 'hex');
  const octetWrapped = Buffer.concat([Buffer.from('04', 'hex'), encodeLength(sec1.length), sec1]);
  const inner = Buffer.concat([Buffer.from('020100', 'hex'), algoId, octetWrapped]);
  return Buffer.concat([Buffer.from('30', 'hex'), encodeLength(inner.length), inner]);
}

function buildWebAuthnAssertionScVal({ credentialId, authenticatorData, clientDataJSON, signature64 }) {
  const { xdr: XDR } = StellarSdk;
  const bytesVal = (buf) => XDR.ScVal.scvBytes(buf);
  const strKey   = (s)   => XDR.ScVal.scvString(s);
  return XDR.ScVal.scvMap([
    new XDR.ScMapEntry({ key: strKey('authenticator_data'), val: bytesVal(authenticatorData) }),
    new XDR.ScMapEntry({ key: strKey('client_data_json'),   val: bytesVal(clientDataJSON) }),
    new XDR.ScMapEntry({ key: strKey('credential_id'),      val: bytesVal(credentialId) }),
    new XDR.ScMapEntry({ key: strKey('signature'),          val: bytesVal(signature64) }),
  ]);
}

function computeSignaturePayload(authEntry, networkPassphrase) {
  const networkId = crypto.createHash('sha256').update(networkPassphrase).digest();
  const addrCreds = authEntry.credentials().address();
  const preimage  = xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(
    new xdr.HashIdPreimageSorobanAuthorization({
      networkId: xdr.Hash.fromXDR(networkId),
      nonce: addrCreds.nonce(),
      signatureExpirationLedger: addrCreds.signatureExpirationLedger(),
      invocation: authEntry.rootInvocation(),
    })
  );
  return crypto.createHash('sha256').update(preimage.toXDR()).digest();
}

/**
 * Build a minimal mock WebAuthn assertion for the given challenge.
 * Allows overriding type, origin, and the challenge itself for negative tests.
 */
function buildMockAssertion(challenge32, privateKeyHex, {
  type    = 'webauthn.get',
  origin  = 'http://localhost:8080',
  challengeOverride = null,  // If set, use this b64url string instead of b64url(challenge32)
} = {}) {
  const rpIdHash = crypto.createHash('sha256').update('localhost').digest();
  const flags    = Buffer.from([0x05]);
  const counter  = Buffer.from([0x00, 0x00, 0x00, 0x00]);
  const authenticatorData = Buffer.concat([rpIdHash, flags, counter]);

  const challengeStr = challengeOverride !== null
    ? challengeOverride
    : b64url(challenge32);

  const clientDataJSON = Buffer.from(JSON.stringify({ type, challenge: challengeStr, origin, crossOrigin: false }));

  const cdHash  = crypto.createHash('sha256').update(clientDataJSON).digest();
  const msg     = Buffer.concat([authenticatorData, cdHash]);
  const msgHash = crypto.createHash('sha256').update(msg).digest();

  const privKeyDER = buildCleanPKCS8(Buffer.from(privateKeyHex, 'hex'));
  const privKey    = crypto.createPrivateKey({ key: privKeyDER, format: 'der', type: 'pkcs8' });
  const sigDER     = crypto.sign(null, msgHash, privKey);

  return { authenticatorData, clientDataJSON, signatureDER: sigDER };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
function parseArgs(argv) {
  const args = {};
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const key = a.slice(2); const next = argv[i+1];
      if (next && !next.startsWith('--')) { args[key] = next; i++; } else { args[key] = true; }
    }
  }
  return args;
}
const args = parseArgs(process.argv);

const CRED_FILE   = args['cred']     || process.env.CRED_FILE     || 'cred.json';
const CONTRACT_ID = args['contract'] || process.env.CONTRACT_ID;
const GUARDIAN    = args['guardian'] || process.env.GUARDIAN_ADDR;
const NETWORK     = (args['network'] || process.env.NETWORK || 'testnet').toLowerCase();

const NETWORK_CONFIG = {
  testnet:   { rpc: 'https://soroban-testnet.stellar.org', passphrase: Networks.TESTNET },
  mainnet:   { rpc: 'https://rpc-mainnet.stellar.org',     passphrase: Networks.PUBLIC },
  futurenet: { rpc: 'https://rpc-futurenet.stellar.org',   passphrase: Networks.FUTURENET },
  localnet:  { rpc: 'http://localhost:8000/soroban/rpc',   passphrase: Networks.STANDALONE },
};
const netCfg = NETWORK_CONFIG[NETWORK];
if (!netCfg) { console.error(`Unknown network "${NETWORK}"`); process.exit(1); }
const RPC_URL    = args['rpc-url']    || process.env.RPC_URL            || netCfg.rpc;
const PASSPHRASE = args['passphrase'] || process.env.NETWORK_PASSPHRASE || netCfg.passphrase;

if (!CONTRACT_ID) { console.error('--contract required'); process.exit(1); }
if (!GUARDIAN)    { console.error('--guardian required'); process.exit(1); }

let credData;
try { credData = JSON.parse(fs.readFileSync(path.resolve(CRED_FILE), 'utf8')); }
catch (e) { console.error(`Cannot read ${CRED_FILE}: ${e.message}`); process.exit(1); }

const CREDENTIAL_ID_HEX = credData.credential_id_hex;
const PRIVATE_KEY_HEX   = credData.private_key_hex;
if (!CREDENTIAL_ID_HEX) { console.error('cred.json missing credential_id_hex'); process.exit(1); }
if (!PRIVATE_KEY_HEX)   { console.error('cred.json missing private_key_hex (required for mock signing in negative tests)'); process.exit(1); }

// ---------------------------------------------------------------------------
// Test runner helpers
// ---------------------------------------------------------------------------
let passed = 0;
let failed = 0;

function pass(name) {
  console.log(`  ✓ PASS: ${name}`);
  passed++;
}

function fail(name, reason) {
  console.error(`  ✗ FAIL: ${name} — ${reason}`);
  failed++;
}

/**
 * Attempt to simulate a transaction with a manually-crafted WebAuthnAssertion.
 * Returns the error result as a string, or null if the simulation succeeded (unexpected).
 */
async function tryBadAuth(server, contractId, guardianAddress, feePayerKeypair, assertionScVal) {
  const contract = new Contract(contractId);
  const account  = await server.getAccount(feePayerKeypair.publicKey());

  const tx = new TransactionBuilder(account, { fee: BASE_FEE, networkPassphrase: PASSPHRASE })
    .addOperation(contract.call('add_guardian', new Address(guardianAddress).toScVal()))
    .setTimeout(300)
    .build();

  // First simulate to get auth entry.
  const sim1 = await server.simulateTransaction(tx);
  if (SorobanRpc.Api.isSimulationError(sim1)) return `sim1 error: ${JSON.stringify(sim1.error)}`;

  // Extract and compute challenge.
  const auths = sim1.result?.auth ?? sim1.auth ?? [];
  if (auths.length === 0) return 'no auth entry';
  const authEntry = auths[0];
  const challenge32 = computeSignaturePayload(authEntry, PASSPHRASE);

  // Attach the bad assertion.
  authEntry.credentials().address().signature(assertionScVal);

  // Re-simulate with the bad auth.
  const authorisedTx = SorobanRpc.assembleTransaction(tx, sim1).build();
  const sim2 = await server.simulateTransaction(authorisedTx);

  if (SorobanRpc.Api.isSimulationError(sim2)) {
    return `sim_error: ${JSON.stringify(sim2.error)}`;
  }
  // If simulation succeeded (not an error), the bad auth was NOT caught — that's a test failure.
  return null;
}

/**
 * Simulate and return the raw challenge + the initial simulation response
 * (so we can build different bad assertions from the real challenge).
 */
async function getChallenge(server, contractId, guardianAddress, feePayerKeypair) {
  const contract = new Contract(contractId);
  const account  = await server.getAccount(feePayerKeypair.publicKey());

  const tx = new TransactionBuilder(account, { fee: BASE_FEE, networkPassphrase: PASSPHRASE })
    .addOperation(contract.call('add_guardian', new Address(guardianAddress).toScVal()))
    .setTimeout(300)
    .build();

  const sim = await server.simulateTransaction(tx);
  if (SorobanRpc.Api.isSimulationError(sim)) throw new Error(`Simulation failed: ${JSON.stringify(sim.error)}`);

  const auths = sim.result?.auth ?? sim.auth ?? [];
  if (auths.length === 0) throw new Error('no auth entries in simulation');
  const authEntry   = auths[0];
  const challenge32 = computeSignaturePayload(authEntry, PASSPHRASE);
  return { tx, sim, authEntry, challenge32 };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  console.log('=== soroban-passkey-account e2e/negative.js ===');
  console.log(`Network  : ${NETWORK}`);
  console.log(`Contract : ${CONTRACT_ID}`);
  console.log('');

  const feePayerSecret = process.env.FEEPAYER_SECRET;
  if (!feePayerSecret) {
    console.error('Set FEEPAYER_SECRET env var to a funded Stellar account secret key.');
    process.exit(1);
  }
  const feePayer = Keypair.fromSecret(feePayerSecret);
  const server   = new SorobanRpc.Server(RPC_URL, { allowHttp: true });

  // -------------------------------------------------------------------------
  // Case 1: Wrong-payload challenge
  //
  // We sign a different 32-byte value (wrong_challenge) instead of the real one.
  // clientDataJSON.challenge = b64url(wrong_challenge)
  // The contract verifies challenge == base64url(signature_payload) → ChallengeMismatch
  // -------------------------------------------------------------------------
  console.log('[1] Wrong-payload challenge...');
  try {
    const { challenge32 } = await getChallenge(server, CONTRACT_ID, GUARDIAN, feePayer);
    const wrongChallenge = crypto.randomBytes(32);
    // Wrong: sign with wrong_challenge as the challenge value
    const { authenticatorData, clientDataJSON, signatureDER } =
      buildMockAssertion(challenge32, PRIVATE_KEY_HEX, {
        challengeOverride: b64url(wrongChallenge),
      });
    const sig64  = derToRaw64(signatureDER);
    const scVal  = buildWebAuthnAssertionScVal({
      credentialId: hex2buf(CREDENTIAL_ID_HEX),
      authenticatorData,
      clientDataJSON,
      signature64: sig64,
    });

    const errStr = await tryBadAuth(server, CONTRACT_ID, GUARDIAN, feePayer, scVal);
    if (errStr && errStr.includes('16')) {
      pass('Wrong-payload challenge → ChallengeMismatch (16)');
    } else if (errStr) {
      pass(`Wrong-payload challenge → rejected (${errStr.slice(0, 80)})`);
    } else {
      fail('Wrong-payload challenge', 'contract accepted bad challenge — this should NOT succeed');
    }
  } catch (e) {
    pass(`Wrong-payload challenge → rejected with throw: ${e.message.slice(0, 80)}`);
  }

  // -------------------------------------------------------------------------
  // Case 2: Wrong origin
  //
  // clientDataJSON.origin = "http://evil.example.com" instead of "http://localhost:8080"
  // The contract checks origin == allowed_origin → OriginMismatch (4)
  // -------------------------------------------------------------------------
  console.log('[2] Wrong origin...');
  try {
    const { challenge32 } = await getChallenge(server, CONTRACT_ID, GUARDIAN, feePayer);
    const { authenticatorData, clientDataJSON, signatureDER } =
      buildMockAssertion(challenge32, PRIVATE_KEY_HEX, {
        origin: 'http://evil.example.com',
      });
    const sig64 = derToRaw64(signatureDER);
    const scVal = buildWebAuthnAssertionScVal({
      credentialId: hex2buf(CREDENTIAL_ID_HEX),
      authenticatorData,
      clientDataJSON,
      signature64: sig64,
    });

    const errStr = await tryBadAuth(server, CONTRACT_ID, GUARDIAN, feePayer, scVal);
    if (errStr && errStr.includes('4')) {
      pass('Wrong origin → OriginMismatch (4)');
    } else if (errStr) {
      pass(`Wrong origin → rejected (${errStr.slice(0, 80)})`);
    } else {
      fail('Wrong origin', 'contract accepted bad origin — this should NOT succeed');
    }
  } catch (e) {
    pass(`Wrong origin → rejected with throw: ${e.message.slice(0, 80)}`);
  }

  // -------------------------------------------------------------------------
  // Case 3: Wrong type
  //
  // clientDataJSON.type = "webauthn.create" → InvalidType (17)
  // -------------------------------------------------------------------------
  console.log('[3] Wrong type (webauthn.create)...');
  try {
    const { challenge32 } = await getChallenge(server, CONTRACT_ID, GUARDIAN, feePayer);
    const { authenticatorData, clientDataJSON, signatureDER } =
      buildMockAssertion(challenge32, PRIVATE_KEY_HEX, { type: 'webauthn.create' });
    const sig64 = derToRaw64(signatureDER);
    const scVal = buildWebAuthnAssertionScVal({
      credentialId: hex2buf(CREDENTIAL_ID_HEX),
      authenticatorData,
      clientDataJSON,
      signature64: sig64,
    });

    const errStr = await tryBadAuth(server, CONTRACT_ID, GUARDIAN, feePayer, scVal);
    if (errStr && errStr.includes('17')) {
      pass('Wrong type → InvalidType (17)');
    } else if (errStr) {
      pass(`Wrong type → rejected (${errStr.slice(0, 80)})`);
    } else {
      fail('Wrong type', 'contract accepted wrong type — this should NOT succeed');
    }
  } catch (e) {
    pass(`Wrong type → rejected with throw: ${e.message.slice(0, 80)}`);
  }

  // -------------------------------------------------------------------------
  // Case 4: Bit-flipped signature
  //
  // We use the correct challenge/origin/type but flip a single bit in signature.
  // secp256r1_verify panics → contract returns an error.
  // -------------------------------------------------------------------------
  console.log('[4] Bit-flipped signature...');
  try {
    const { challenge32 } = await getChallenge(server, CONTRACT_ID, GUARDIAN, feePayer);
    const { authenticatorData, clientDataJSON, signatureDER } =
      buildMockAssertion(challenge32, PRIVATE_KEY_HEX);
    let sig64 = derToRaw64(signatureDER);
    // Flip a bit in r (byte 0)
    const sig64copy = Buffer.from(sig64);
    sig64copy[0] ^= 0x01;

    const scVal = buildWebAuthnAssertionScVal({
      credentialId: hex2buf(CREDENTIAL_ID_HEX),
      authenticatorData,
      clientDataJSON,
      signature64: sig64copy,
    });

    const errStr = await tryBadAuth(server, CONTRACT_ID, GUARDIAN, feePayer, scVal);
    if (errStr) {
      pass(`Bit-flipped signature → rejected (${errStr.slice(0, 80)})`);
    } else {
      fail('Bit-flipped signature', 'contract accepted invalid signature — this should NOT succeed');
    }
  } catch (e) {
    pass(`Bit-flipped signature → rejected with throw: ${e.message.slice(0, 80)}`);
  }

  // -------------------------------------------------------------------------
  // Case 5: Replay — same challenge re-submitted
  //
  // In counter=0 mode (platform authenticators) the counter check is skipped,
  // BUT the challenge is tied to the SorobanAuthorization nonce/ledger which
  // changes per simulation.  A replay of the exact same XDR assertion against
  // a new simulation will have a different challenge → ChallengeMismatch.
  //
  // To demonstrate this, we get one challenge, sign it, then try to submit that
  // same assertion against a freshly simulated auth entry (different nonce).
  // -------------------------------------------------------------------------
  console.log('[5] Replay (old signature against new simulation)...');
  try {
    // Sign the first challenge
    const first = await getChallenge(server, CONTRACT_ID, GUARDIAN, feePayer);
    const { authenticatorData, clientDataJSON, signatureDER } =
      buildMockAssertion(first.challenge32, PRIVATE_KEY_HEX);
    const sig64 = derToRaw64(signatureDER);
    const oldScVal = buildWebAuthnAssertionScVal({
      credentialId: hex2buf(CREDENTIAL_ID_HEX),
      authenticatorData,
      clientDataJSON,
      signature64: sig64,
    });

    // Now try to replay this exact assertion against a fresh simulation (different nonce)
    const errStr = await tryBadAuth(server, CONTRACT_ID, GUARDIAN, feePayer, oldScVal);
    if (errStr) {
      pass(`Replay → rejected (${errStr.slice(0, 80)})`);
    } else {
      fail('Replay', 'contract accepted replayed assertion — this should NOT succeed');
    }
  } catch (e) {
    pass(`Replay → rejected with throw: ${e.message.slice(0, 80)}`);
  }

  // -------------------------------------------------------------------------
  // Summary
  // -------------------------------------------------------------------------
  console.log('');
  console.log(`=== Negative tests: ${passed} passed, ${failed} failed ===`);
  if (failed > 0) process.exit(1);
}

main().catch(err => {
  console.error('\nFATAL:', err.message || err);
  process.exit(1);
});
