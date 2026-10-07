#!/usr/bin/env node
/**
 * e2e/happy10.js
 *
 * Happy-path stress test: run the full add_guardian → verify flow 10 times
 * in succession, each time with a different randomly-generated guardian address,
 * and report how many succeeded.
 *
 * Each iteration:
 *   1. Generate a random Stellar keypair as the guardian.
 *   2. Simulate add_guardian to obtain the SorobanAuthorization entry.
 *   3. Compute the challenge (SHA-256 of the auth preimage).
 *   4. Mock-sign with the soft P-256 key from cred.json.
 *   5. Build WebAuthnAssertion ScVal, assemble, submit.
 *   6. Poll for confirmation.
 *   7. Call list_guardians and verify the address is present.
 *
 * Each iteration's guardian is unique, so there are no deduplication skips.
 * All 10 submissions share the same fee-payer account (sequential nonces).
 *
 * Usage:
 *   node e2e/happy10.js \
 *     --cred cred.json \
 *     --contract <CONTRACT_ID> \
 *     --network testnet
 *
 * Environment:
 *   FEEPAYER_SECRET   — funded fee-payer secret key
 *   CONTRACT_ID       — contract address
 *   NETWORK           — testnet (default)
 *   RPC_URL           — override
 *   NETWORK_PASSPHRASE — override
 *
 * Exit code: 0 if all 10 succeed, 1 otherwise.
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
// Inline helpers (same as sign.js / negative.js — kept self-contained)
// ---------------------------------------------------------------------------
function buf2hex(buf) { return Buffer.from(buf).toString('hex'); }
function hex2buf(hex) { return Buffer.from(hex, 'hex'); }
function b64url(buf)  { return Buffer.from(buf).toString('base64url'); }

function encodeLength(n) {
  if (n < 128) return Buffer.from([n]);
  if (n < 256) return Buffer.from([0x81, n]);
  return Buffer.from([0x82, n >> 8, n & 0xff]);
}

const P256_N = Buffer.from('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551', 'hex');

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
  const rLen = der[offset++]; const r = der.slice(offset, offset+rLen); offset += rLen;
  if (der[offset++] !== 0x02) throw new Error('DER s');
  const sLen = der[offset++]; const s = der.slice(offset, offset+sLen);
  return Buffer.concat([padTo32(r), lowSNormalise(padTo32(s))]);
}

function buildCleanPKCS8(d32) {
  const sec1 = Buffer.concat([Buffer.from('3023', 'hex'), Buffer.from('020101', 'hex'), Buffer.from('0420', 'hex'), d32]);
  const algoId = Buffer.from('301306072a8648ce3d020106082a8648ce3d030107', 'hex');
  const wrapped = Buffer.concat([Buffer.from('04', 'hex'), encodeLength(sec1.length), sec1]);
  const inner = Buffer.concat([Buffer.from('020100', 'hex'), algoId, wrapped]);
  return Buffer.concat([Buffer.from('30', 'hex'), encodeLength(inner.length), inner]);
}

function buildWebAuthnAssertionScVal({ credentialId, authenticatorData, clientDataJSON, signature64 }) {
  const { xdr: XDR } = StellarSdk;
  const bv  = (buf) => XDR.ScVal.scvBytes(buf);
  const sk  = (s)   => XDR.ScVal.scvString(s);
  return XDR.ScVal.scvMap([
    new XDR.ScMapEntry({ key: sk('authenticator_data'), val: bv(authenticatorData) }),
    new XDR.ScMapEntry({ key: sk('client_data_json'),   val: bv(clientDataJSON) }),
    new XDR.ScMapEntry({ key: sk('credential_id'),      val: bv(credentialId) }),
    new XDR.ScMapEntry({ key: sk('signature'),          val: bv(signature64) }),
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

function mockSign(challenge32, privateKeyHex) {
  const rpIdHash = crypto.createHash('sha256').update('localhost').digest();
  const flags    = Buffer.from([0x05]);
  const counter  = Buffer.from([0x00, 0x00, 0x00, 0x00]);
  const authenticatorData = Buffer.concat([rpIdHash, flags, counter]);
  const clientDataJSON = Buffer.from(JSON.stringify({
    type: 'webauthn.get',
    challenge: b64url(challenge32),
    origin: 'http://localhost:8080',
    crossOrigin: false,
  }));
  const cdHash  = crypto.createHash('sha256').update(clientDataJSON).digest();
  const msg     = Buffer.concat([authenticatorData, cdHash]);
  const msgHash = crypto.createHash('sha256').update(msg).digest();
  const privKey = crypto.createPrivateKey({
    key: buildCleanPKCS8(Buffer.from(privateKeyHex, 'hex')),
    format: 'der', type: 'pkcs8',
  });
  const sigDER = crypto.sign(null, msgHash, privKey);
  return { authenticatorData, clientDataJSON, signatureDER: sigDER };
}

async function simulate(server, tx) {
  const resp = await server.simulateTransaction(tx);
  if (SorobanRpc.Api.isSimulationError(resp)) throw new Error(`Sim failed: ${JSON.stringify(resp.error)}`);
  return resp;
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
const NETWORK     = (args['network'] || process.env.NETWORK || 'testnet').toLowerCase();
const ITERATIONS  = parseInt(args['iterations'] || '10', 10);

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

let credData;
try { credData = JSON.parse(fs.readFileSync(path.resolve(CRED_FILE), 'utf8')); }
catch (e) { console.error(`Cannot read ${CRED_FILE}: ${e.message}`); process.exit(1); }

const CREDENTIAL_ID_HEX = credData.credential_id_hex;
const PRIVATE_KEY_HEX   = credData.private_key_hex;
if (!CREDENTIAL_ID_HEX) { console.error('cred.json missing credential_id_hex'); process.exit(1); }
if (!PRIVATE_KEY_HEX)   { console.error('cred.json missing private_key_hex (required for mock signing)'); process.exit(1); }

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function runIteration(server, feePayerKeypair, guardianAddress, index) {
  const contract = new Contract(CONTRACT_ID);
  const account  = await server.getAccount(feePayerKeypair.publicKey());

  const tx = new TransactionBuilder(account, { fee: BASE_FEE, networkPassphrase: PASSPHRASE })
    .addOperation(contract.call('add_guardian', new Address(guardianAddress).toScVal()))
    .setTimeout(300)
    .build();

  const sim = await simulate(server, tx);
  const auths = sim.result?.auth ?? sim.auth ?? [];
  if (auths.length === 0) throw new Error('no auth entries');
  const authEntry = auths[0];

  const challenge32 = computeSignaturePayload(authEntry, PASSPHRASE);
  const { authenticatorData, clientDataJSON, signatureDER } = mockSign(challenge32, PRIVATE_KEY_HEX);
  const sig64 = derToRaw64(signatureDER);

  const scVal = buildWebAuthnAssertionScVal({
    credentialId: hex2buf(CREDENTIAL_ID_HEX),
    authenticatorData,
    clientDataJSON,
    signature64: sig64,
  });
  authEntry.credentials().address().signature(scVal);

  const authorisedTx = SorobanRpc.assembleTransaction(tx, sim).build();
  authorisedTx.sign(feePayerKeypair);

  const sendResp = await server.sendTransaction(authorisedTx);
  if (sendResp.status === 'ERROR') throw new Error(`send error: ${JSON.stringify(sendResp.errorResult)}`);

  // Poll for confirmation
  let txResp;
  for (let i = 0; i < 30; i++) {
    await new Promise(r => setTimeout(r, 2000));
    txResp = await server.getTransaction(sendResp.hash);
    if (txResp.status !== SorobanRpc.Api.GetTransactionStatus.NOT_FOUND) break;
  }
  if (txResp.status !== SorobanRpc.Api.GetTransactionStatus.SUCCESS) {
    throw new Error(`tx failed: ${txResp.status}`);
  }

  // Verify list_guardians contains the new guardian
  const verifyAccount = await server.getAccount(feePayerKeypair.publicKey());
  const verifyTx = new TransactionBuilder(verifyAccount, { fee: BASE_FEE, networkPassphrase: PASSPHRASE })
    .addOperation(contract.call('list_guardians'))
    .setTimeout(30)
    .build();
  const verifySim = await simulate(server, verifyTx);
  // The retval is a Vec<Address>; we check it contains our guardian.
  const retvalXdr = verifySim.result?.retval;
  const retvalStr = JSON.stringify(retvalXdr);
  // Address shows up in the XDR string
  if (!retvalStr.includes(guardianAddress)) {
    throw new Error(`Guardian ${guardianAddress} not found in list_guardians result`);
  }

  return sendResp.hash;
}

async function main() {
  console.log('=== soroban-passkey-account e2e/happy10.js ===');
  console.log(`Network   : ${NETWORK}`);
  console.log(`Contract  : ${CONTRACT_ID}`);
  console.log(`Iterations: ${ITERATIONS}`);
  console.log('');

  const feePayerSecret = process.env.FEEPAYER_SECRET;
  if (!feePayerSecret) {
    console.error('Set FEEPAYER_SECRET env var to a funded Stellar account secret key.');
    process.exit(1);
  }
  const feePayer = Keypair.fromSecret(feePayerSecret);
  const server   = new SorobanRpc.Server(RPC_URL, { allowHttp: true });

  let successCount = 0;
  const results = [];

  for (let i = 1; i <= ITERATIONS; i++) {
    // Generate a unique random guardian address for this iteration.
    const guardianKp      = Keypair.random();
    const guardianAddress = guardianKp.publicKey();
    process.stdout.write(`  [${i}/${ITERATIONS}] Adding guardian ${guardianAddress.slice(0, 8)}... `);

    try {
      const txHash = await runIteration(server, feePayer, guardianAddress, i);
      console.log(`✓  (${txHash.slice(0, 12)}...)`);
      successCount++;
      results.push({ iteration: i, guardian: guardianAddress, status: 'success', txHash });
    } catch (err) {
      console.log(`✗  ${err.message.slice(0, 80)}`);
      results.push({ iteration: i, guardian: guardianAddress, status: 'fail', error: err.message });
    }
  }

  console.log('');
  console.log('─'.repeat(50));
  console.log(`Result: ${successCount}/${ITERATIONS} iterations succeeded`);
  console.log('─'.repeat(50));

  if (successCount < ITERATIONS) {
    console.log('\nFailed iterations:');
    for (const r of results.filter(r => r.status === 'fail')) {
      console.log(`  [${r.iteration}] ${r.guardian.slice(0, 8)}... — ${r.error}`);
    }
    process.exit(1);
  } else {
    console.log('\n✓ All 10 happy-path iterations completed successfully.');
  }
}

main().catch(err => {
  console.error('\nFATAL:', err.message || err);
  process.exit(1);
});
