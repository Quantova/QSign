// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const util = require('util');
const q = require('..');

test('a generated key never shows its bytes when printed or serialised', () => {
  const key = q.generateKey();
  const hex = Buffer.from(key).toString('hex');
  const listed = Array.from(key).join(',');
  const shown = [util.inspect(key), util.inspect({ key }), JSON.stringify({ key }), String(key), `${key}`, util.format('%o', key), util.format('%j', { key }), key.toLocaleString()];
  for (const s of shown) {
    assert.ok(!s.includes(hex), s);
    assert.ok(!s.replace(/\s/g, '').includes(listed.slice(0, 24)), s);
  }
  assert.ok(key instanceof Uint8Array);
  assert.strictEqual(key.length, 32);
  assert.strictEqual(Object.prototype.toString.call(key.slice(0, 4)), '[object Uint8Array]');
  assert.strictEqual(q.keyId(key), q.keyId(Uint8Array.from(key)));
});

test('text with an unassigned code point or a noncharacter is refused', async () => {
  for (const t of ['a\u0378b', 'a\ufffeb', 'a\u{10ffff}b']) {
    await assert.rejects(q.sign({ key: q.generateKey(), bytes: Buffer.from('d'), signer: t }), undefined, JSON.stringify(t));
  }
});

test('a signing key of too few different byte values or in shared memory is refused', async () => {
  const sign = (key) => q.sign({ key, bytes: Buffer.from('d') });
  const shared = new Uint8Array(new SharedArrayBuffer(32));
  shared.set(q.generateKey());
  await assert.rejects(Promise.resolve().then(() => sign(new Uint8Array(32))));
  await assert.rejects(Promise.resolve().then(() => sign(new Uint8Array(32).fill(7))), /too few different byte values/);
  await assert.rejects(Promise.resolve().then(() => sign(shared)));
  await Promise.resolve().then(() => sign(q.generateKey()));
});

test('a misspelled or unknown verify option is refused so a check is never skipped silently', async () => {
  await assert.rejects(q.verify({}, { expectedSendr: 'Q1' }), /is not an option of verify/);
});

test('a misspelled or unknown option of a signing call is refused and nothing is signed', async () => {
  await assert.rejects(Promise.resolve().then(() => q.sign({ key: q.generateKey(), bytes: Buffer.from('d'), signr: 'x' })), /is not (an option of|used by)/);
  await assert.rejects(Promise.resolve().then(() => q.anchor([], { seed: new Uint8Array(32).fill(5), index: 0, untl: '2030-01-01T00:00:00.000Z' })));
});

test('the working copies of the signing key and randomness are wiped after native signing', () => {
  const w = require('../wasm/qsign_native.js');
  const native = require('../lib/native.js');
  const seen = [];
  const real = { sign: w.sign, publicKey: w.publicKey };
  w.sign = (...a) => { seen.push(...a); return real.sign(...a); };
  w.publicKey = (...a) => { seen.push(...a); return real.publicKey(...a); };
  try {
    const seed = Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 3) & 255);
    const rnd = Uint8Array.from({ length: 32 }, (_, i) => (i * 11 + 5) & 255);
    native.publicKey(seed);
    native.sign(seed, Buffer.from('m'), rnd);
    const has = (a, n) => Buffer.from(a.buffer, a.byteOffset, a.byteLength).indexOf(Buffer.from(n)) !== -1;
    assert.strictEqual(seen.filter((a) => has(a, seed) || has(a, rnd)).length, 0);
    assert.strictEqual(seed[1], 10);
    assert.strictEqual(rnd[1], 16);
  } finally {
    Object.assign(w, real);
  }
});

test('an unexpected envelope field is named without control or direction characters', () => {
  let msg = '';
  try {
    q.parseEnvelope({ format: 'x', ['a\u001b[2J\u202eb']: 1 });
  } catch (e) {
    msg = e.message;
  }
  assert.match(msg, /unexpected field/);
  assert.doesNotMatch(msg, /[\u0000-\u001f\u007f-\u009f\u202a-\u202e]/u);
});

test('a file that changes while it is hashed is refused', { skip: process.platform === 'win32' }, async () => {
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'change-'));
  try {
    const doc = path.join(dir, 'doc.bin');
    fs.writeFileSync(doc, Buffer.alloc(4 * 1024 * 1024, 7));
    await new Promise((resolve) => setTimeout(resolve, 50));
    const pending = q.sign({ key: q.generateKey(), file: doc });
    const fd = fs.openSync(doc, 'r+');
    fs.writeSync(fd, Buffer.from('Z'), 0, 1, 0);
    fs.closeSync(fd);
    await assert.rejects(pending, /changed while it was read/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('the envelope error code is produced', () => {
  assert.throws(() => q.parseEnvelope({}), (e) => e.code === 'QSIGN_INVALID_ENVELOPE');
});

test('a signing key, salt or secret made of too few different byte values is refused', () => {
  const pattern = (n) => Uint8Array.from({ length: 32 }, (_, i) => 1 + (i % n));
  const weak = [Uint8Array.from(Buffer.from('secretsecretsecretsecretsecretse')), pattern(2), pattern(12)];
  for (const k of weak) assert.throws(() => q.publicKey(k), /too few different byte values/);
  assert.ok(q.publicKey(pattern(13)).length > 0);
  for (let i = 0; i < 200; i += 1) assert.ok(q.publicKey(q.generateKey()).length > 0);
});
