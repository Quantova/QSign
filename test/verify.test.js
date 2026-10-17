// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const qsign = require('..');
const { makeChain, client, SEED, qstampRoot } = require('./chain');

const ROOT = path.join(__dirname, '..');
const qstamp = require(qstampRoot(ROOT));
const doc = Buffer.from('loan agreement 2026 0042');

async function signed(signer) {
  const key = qsign.generateKey();
  const env = await qsign.sign({ key, bytes: doc, signer: signer || 'Treasury officer' });
  return { key, env };
}

test('a document signature without the document is not verified', async () => {
  const { key, env } = await signed();
  const r = await qsign.verify(env, { keyId: qsign.keyId(key), revocations: [], requireAnchor: false });
  assert.strictEqual(r.status, 'unverified');
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.contentChecked, false);
  const ok = await qsign.verify(env, { bytes: doc, keyId: qsign.keyId(key), revocations: [], requireAnchor: false });
  assert.strictEqual(ok.status, 'valid');
  const other = await qsign.verify(env, { bytes: Buffer.from('another'), keyId: qsign.keyId(key), revocations: [], requireAnchor: false });
  assert.strictEqual(other.status, 'invalid');
});

test('the command line exits non zero when no document is given', async () => {
  const { key, env } = await signed();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qsign-verify-'));
  try {
    const file = path.join(dir, 'env.json');
    fs.writeFileSync(file, JSON.stringify(env));
    let code = 0;
    let out = '';
    try {
      execFileSync(process.execPath, [path.join(ROOT, 'bin', 'qsign.js'), 'verify', file, '--key-id', qsign.keyId(key), '--no-revocations', '--allow-unanchored'], { encoding: 'utf8' });
    } catch (e) {
      code = e.status;
      out = e.stdout;
    }
    assert.strictEqual(code, 3);
    assert.match(out, /UNVERIFIED/);
    const docFile = path.join(dir, 'doc.bin');
    fs.writeFileSync(docFile, doc);
    const good = execFileSync(process.execPath, [path.join(ROOT, 'bin', 'qsign.js'), 'verify', file, '--file', docFile, '--key-id', qsign.keyId(key), '--no-revocations', '--allow-unanchored'], { encoding: 'utf8' });
    assert.match(good, /\nVALID\n/);
    assert.match(good, /not a verified identity/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('the signer name is reported as self asserted and can be bound to the published key', async () => {
  const { key, env } = await signed('Credit committee');
  const base = { bytes: doc, keyId: qsign.keyId(key), revocations: [], requireAnchor: false };
  const r = await qsign.verify(env, base);
  assert.strictEqual(r.signerBound, false);
  assert.ok(r.notes.some((n) => /not a verified identity/.test(n)));
  const publication = qsign.keyStatement({ key, action: 'publish', signer: 'Credit committee' });
  const bound = await qsign.verify(env, Object.assign({ keyPublication: publication }, base));
  assert.strictEqual(bound.status, 'valid');
  assert.strictEqual(bound.signerBound, true);
  const renamed = qsign.keyStatement({ key, action: 'publish', signer: 'Chief executive' });
  const wrong = await qsign.verify(env, Object.assign({ keyPublication: renamed }, base));
  assert.strictEqual(wrong.status, 'invalid');
  const foreign = qsign.keyStatement({ key: qsign.generateKey(), action: 'publish', signer: 'Credit committee' });
  const notOwn = await qsign.verify(env, Object.assign({ keyPublication: foreign }, base));
  assert.strictEqual(notOwn.status, 'invalid');
});

test('a fabricated receipt from endpoints that are not pinned operators never verifies valid', async () => {
  const { key, env } = await signed();
  const fake = makeChain(ROOT);
  const forged = { trustCustomEndpoints: true, clients: [client(fake, 'a'), client(fake, 'b')] };
  const [anchored] = await qsign.anchor(env, Object.assign({ seed: SEED, index: 0 }, forged));
  const base = { bytes: doc, keyId: qsign.keyId(key), revocations: [] };
  const r = await qsign.verify(anchored, Object.assign({}, base, forged));
  assert.strictEqual(r.status, 'unproven');
  assert.strictEqual(r.anchoredAt, null);
  const single = await qsign.verify(anchored, Object.assign({}, base, { trustCustomEndpoints: true, clients: [forged.clients[0]], trustSingleEndpoint: true }));
  assert.notStrictEqual(single.status, 'valid');
  const elsewhere = makeChain(ROOT);
  const honest = await qsign.verify(anchored, Object.assign({}, base, { trustCustomEndpoints: true, clients: [client(elsewhere, 'c'), client(elsewhere, 'd')] }));
  assert.notStrictEqual(honest.status, 'valid');
});

test('an anchor proven by pinned operators verifies valid', async (t) => {
  const { key, env } = await signed();
  const chain = makeChain(ROOT);
  const ep = { trustCustomEndpoints: true, clients: [client(chain, 'a'), client(chain, 'b')] };
  const [anchored] = await qsign.anchor(env, Object.assign({ seed: SEED, index: 0 }, ep));
  const had = Object.prototype.hasOwnProperty.call(qstamp, 'isProven');
  const before = qstamp.isProven;
  qstamp.isProven = () => true;
  t.after(() => {
    if (had) qstamp.isProven = before;
    else delete qstamp.isProven;
  });
  const r = await qsign.verify(anchored, Object.assign({ bytes: doc, keyId: qsign.keyId(key), revocations: [] }, ep));
  assert.strictEqual(r.status, 'valid', JSON.stringify(r.checks.filter((c) => !c.ok)));
  assert.notStrictEqual(r.anchoredAt, null);
});

test('endpoints chosen by the caller need trustCustomEndpoints, loopback needs allowLoopback and the anchor sender is checked', async (t) => {
  const { key, env } = await signed();
  const chain = makeChain(ROOT);
  const ep = { trustCustomEndpoints: true, clients: [client(chain, 'a'), client(chain, 'b')] };
  const [anchored] = await qsign.anchor(env, Object.assign({ seed: SEED, index: 0 }, ep));
  const base = { bytes: doc, keyId: qsign.keyId(key), revocations: [] };
  const untrusted = await qsign.verify(anchored, Object.assign({}, base, { clients: ep.clients }));
  assert.strictEqual(untrusted.status, 'indeterminate');
  const loop = await qsign.verify(anchored, Object.assign({}, base, { trustCustomEndpoints: true, rpc: 'http://127.0.0.1:9' }));
  assert.notStrictEqual(loop.status, 'valid');
  assert.ok(loop.checks.some((c) => /loopback/.test(c.detail)));
  const before = qstamp.isProven;
  qstamp.isProven = () => true;
  t.after(() => {
    qstamp.isProven = before;
  });
  const wrong = await qsign.verify(anchored, Object.assign({ expectedSender: chain.core.address(new Uint8Array(32).fill(9), 0) }, base, ep));
  assert.strictEqual(wrong.status, 'invalid');
  const right = await qsign.verify(anchored, Object.assign({ expectedSender: chain.core.address(SEED, 0) }, base, ep));
  assert.strictEqual(right.status, 'valid', JSON.stringify(right.checks.filter((c) => !c.ok)));
});
