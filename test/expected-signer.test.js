// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const qsign = require('..');
const { makeChain, client, SEED } = require('./chain');

const ROOT = path.join(__dirname, '..');
const qstamp = require('@quantovainc/qstamp');
const doc = Buffer.from('contract body');

function proven(t) {
  const had = Object.prototype.hasOwnProperty.call(qstamp, 'isProven');
  const before = qstamp.isProven;
  qstamp.isProven = (r) => !!r && r.status === 'unproven' && r.trust === 'custom-endpoints' && r.checks.every((c) => c.ok || c.name === 'proof');
  t.after(() => {
    if (had) qstamp.isProven = before;
    else delete qstamp.isProven;
  });
}

test('a signature by any other key never verifies, and verify refuses to run without the expected signer', async () => {
  const alice = qsign.generateKey();
  const mallory = qsign.generateKey();
  const aliceRevoke = qsign.keyStatement({ key: alice, action: 'revoke', note: 'device retired' });
  const forged = await qsign.sign({ key: mallory, bytes: doc, signer: 'Alice Holdings', signedAt: '2025-01-01T00:00:00.000Z' });
  await assert.rejects(qsign.verify(forged, { network: 'testnet', bytes: doc, revocations: [aliceRevoke], requireAnchor: false }), (e) => e.code === 'QSIGN_INVALID_INPUT' && /expected signer/.test(e.message));
  const pinned = await qsign.verify(forged, { network: 'testnet', bytes: doc, publicKey: qsign.publicKey(alice), revocations: [aliceRevoke], requireAnchor: false });
  assert.strictEqual(pinned.status, 'invalid');
  assert.strictEqual(pinned.signerTrusted, false);
});

test('an unanchored signature or a missing revocation list never verifies valid by default', async () => {
  const alice = qsign.generateKey();
  const own = await qsign.sign({ key: alice, bytes: doc });
  const keyId = qsign.keyId(alice);
  const defaults = await qsign.verify(own, { network: 'testnet', bytes: doc, keyId });
  assert.strictEqual(defaults.valid, false);
  assert.ok(defaults.checks.some((c) => c.name === 'anchor' && !c.ok));
  assert.ok(defaults.checks.some((c) => c.name === 'revocations' && !c.ok));
  assert.strictEqual(defaults.revocationChecked, false);
  const noList = await qsign.verify(own, { network: 'testnet', bytes: doc, keyId, requireAnchor: false });
  assert.strictEqual(noList.status, 'indeterminate');
  const explicit = await qsign.verify(own, { network: 'testnet', bytes: doc, keyId, requireAnchor: false, revocations: [] });
  assert.strictEqual(explicit.status, 'valid');
});

test('the command line needs the expected signer and a revocation choice', async () => {
  const alice = qsign.generateKey();
  const mallory = qsign.generateKey();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qsign-signer-'));
  try {
    const env = path.join(dir, 'contract.pdf.qsig.json');
    const file = path.join(dir, 'contract.pdf');
    const rev = path.join(dir, 'alice.revoke.json');
    const pub = path.join(dir, 'alice.pub.json');
    fs.writeFileSync(env, JSON.stringify(await qsign.sign({ key: mallory, bytes: doc, signer: 'Alice Holdings' })));
    fs.writeFileSync(file, doc);
    fs.writeFileSync(rev, JSON.stringify(qsign.keyStatement({ key: alice, action: 'revoke' })));
    fs.writeFileSync(pub, JSON.stringify(qsign.describeKey(alice)));
    const run = (args) => spawnSync(process.execPath, [path.join(ROOT, 'bin', 'qsign.js'), 'verify', env, '--file', file].concat(args), { encoding: 'utf8' });
    const noKey = run(['--revocation', rev]);
    assert.strictEqual(noKey.status, 64);
    assert.match(noKey.stderr, /--key-id or --public-key/);
    const noChoice = run(['--public-key', pub]);
    assert.strictEqual(noChoice.status, 64);
    const forged = run(['--network', 'testnet', '--public-key', pub, '--revocation', rev, '--allow-unanchored']);
    assert.strictEqual(forged.status, 1);
    assert.doesNotMatch(forged.stdout, /^VALID$/m);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a signing time more than a day before its anchor is not proven unless the verifier widens the window', async (t) => {
  proven(t);
  const now = Math.floor(Date.now() / 1000);
  const chain = makeChain(ROOT, { time: now - 120 });
  const ep = { trustCustomEndpoints: true, clients: [client(chain, 'a'), client(chain, 'b')] };
  const key = qsign.generateKey();
  const anchorAt = async (env, t0) => {
    chain.nextBlockTime = t0;
    return (await qsign.anchor(env, Object.assign({ seed: SEED, index: 0 }, ep)))[0];
  };
  const old = await anchorAt(await qsign.sign({ key, bytes: doc, signedAt: new Date((now - 3 * 86400 - 60) * 1000).toISOString() }), now - 60);
  const fresh = await anchorAt(await qsign.sign({ key, bytes: doc, signedAt: new Date((now - 180) * 1000).toISOString() }), now - 60);
  chain.newBlock();
  const opts = Object.assign({ network: 'custom', bytes: doc, keyId: qsign.keyId(key), revocations: [] }, ep);
  const late = await qsign.verify(old, opts);
  assert.strictEqual(late.valid, false);
  assert.ok(late.checks.some((c) => !c.ok && /24 hours/.test(c.detail)));
  assert.strictEqual((await qsign.verify(old, Object.assign({ maxAnchorDelay: 4 * 86400 }, opts))).status, 'valid');
  assert.strictEqual((await qsign.verify(fresh, opts)).status, 'valid');
});

test('an anchor interrupted before finality keeps its pending stamp and complete finishes it without a second transaction', async (t) => {
  proven(t);
  const chain = makeChain(ROOT);
  let hold = true;
  const holding = { transaction: (c, id) => {
    const tx = c.txs.get(id);
    return tx ? Object.assign({}, tx, hold ? { status: 'pending' } : {}) : null;
  } };
  const ep = { trustCustomEndpoints: true, clients: [client(chain, 'a', holding), client(chain, 'b', holding)] };
  const key = qsign.generateKey();
  const env = await qsign.sign({ key, bytes: doc });
  let seen = null;
  const err = await qsign.anchor(env, Object.assign({ seed: SEED, index: 0, timeoutMs: 1500, onPending: (p) => { seen = p; } }, ep)).then(() => null, (e) => e);
  assert.ok(err, 'the anchor finished although finality was held back');
  const pending = err.pending || seen;
  assert.ok(pending && pending.records.every((r) => /^[0-9a-f]{64}$/.test(r.salt)));
  hold = false;
  const sent = chain.txs.size;
  const [done] = await qsign.complete(env, pending, ep);
  assert.strictEqual(chain.txs.size, sent);
  assert.strictEqual(done.anchor.anchor.tx, pending.tx);
  await assert.rejects(qsign.complete(await qsign.sign({ key, bytes: Buffer.from('other') }), pending, ep));
  chain.newBlock();
  const r = await qsign.verify(done, Object.assign({ network: 'custom', bytes: doc, keyId: qsign.keyId(key), revocations: [] }, ep));
  assert.strictEqual(r.status, 'valid', JSON.stringify(r.checks.filter((c) => !c.ok)));
});
