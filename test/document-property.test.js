'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { iterations, mulberry32 } = require('./fuzz');
const qsign = require('..');

const CODE = 'QSIGN_';

function rng(seed) {
  const rnd = mulberry32(seed);
  const int = (n) => Math.floor(rnd() * n);
  const pick = (a) => a[int(a.length)];
  const bytes = (n) => {
    const b = Buffer.alloc(n);
    for (let i = 0; i < n; i += 1) b[i] = int(256);
    return b;
  };
  return { rnd, int, pick, bytes };
}

function randomDocument(r) {
  const size = r.pick([0, 1, 2, r.int(64), r.int(4096), 65536 + r.int(4096)]);
  return r.bytes(size);
}

function oneByteAway(r, doc) {
  const ops = [
    () => Buffer.concat([doc, Buffer.from([r.int(256)])]),
    () => Buffer.concat([Buffer.from([r.int(256)]), doc]),
  ];
  if (doc.length) {
    ops.push(
      () => {
        const b = Buffer.from(doc);
        b[r.int(b.length)] ^= 1 << r.int(8);
        return b;
      },
      () => doc.subarray(0, doc.length - 1),
      () => doc.subarray(1),
    );
  }
  return r.pick(ops)();
}

async function outcome(fn) {
  try {
    return { result: await fn() };
  } catch (e) {
    return { error: e };
  }
}

function assertNotValid(o, what) {
  if (o.error) {
    assert.ok(typeof o.error.code === 'string' && o.error.code.startsWith(CODE), what + ' threw without the ' + CODE + ' code, ' + o.error.message);
    return;
  }
  assert.notStrictEqual(o.result.status, 'valid', what + ' verified valid');
  assert.notStrictEqual(o.result.valid, true, what + ' verified valid');
}

function documentFree(r, signer) {
  const o = {};
  const choose = r.int(3);
  if (choose === 0) o.keyId = qsign.keyId(signer);
  else if (choose === 1) o.publicKey = qsign.publicKey(signer);
  else o.publicKey = Buffer.from(qsign.publicKey(signer)).toString('base64');
  if (r.int(2)) o.revocations = [];
  if (r.int(2)) o.requireAnchor = r.pick([false, true]);
  if (r.int(2)) o.expectType = 'document';
  if (r.int(3) === 0) o.maxAnchorDelay = r.pick([60, 3600, 86400]);
  if (r.int(3) === 0) o.note = 'x';
  for (const k of ['file', 'bytes', 'digest']) if (r.int(4) === 0) o[k] = undefined;
  return o;
}

test('a document signature without its document never verifies valid, whatever options are combined', async () => {
  const r = rng(0xd0c1);
  const n = iterations(200);
  const keys = [qsign.generateKey(), qsign.generateKey()];
  let unverified = 0;
  for (let i = 0; i < n; i += 1) {
    const signer = r.pick(keys);
    const doc = randomDocument(r);
    const env = await qsign.sign({ key: signer, bytes: doc, signer: r.pick(['', 'Treasury officer', 'Credit committee']) });
    const opts = documentFree(r, signer);
    const o = await outcome(() => qsign.verify(env, opts));
    assertNotValid(o, 'iteration ' + i + ' with ' + Object.keys(opts).join(','));
    if (o.result) {
      assert.strictEqual(o.result.contentChecked, false);
      if (o.result.status === 'unverified') unverified += 1;
    }
    const withDoc = Object.assign({}, opts, { bytes: doc, requireAnchor: false, revocations: [] });
    for (const k of ['file', 'digest']) delete withDoc[k];
    const control = await qsign.verify(env, withDoc);
    assert.strictEqual(control.status, 'valid', 'iteration ' + i + ' the honest document did not verify');
  }
  assert.ok(unverified > 0, 'no run reported the signature as unverified');
});

test('a document signature never verifies valid for another document, one byte away or empty, given as bytes or digest', async () => {
  const r = rng(0xd0c2);
  const n = iterations(200);
  const key = qsign.generateKey();
  const keyId = qsign.keyId(key);
  const base = { keyId, revocations: [], requireAnchor: false };
  for (let i = 0; i < n; i += 1) {
    const doc = r.int(8) === 0 ? Buffer.alloc(0) : randomDocument(r);
    const env = await qsign.sign({ key, bytes: doc });
    const wrongs = [oneByteAway(r, doc), randomDocument(r), Buffer.alloc(0), Buffer.from(doc.toString('hex'))];
    for (const [j, wrong] of wrongs.entries()) {
      if (wrong.equals(doc)) continue;
      const digest = qsign.parseEnvelope(env).digest;
      const wrongDigest = crypto.createHash('sha3-256').update(wrong).digest('hex');
      assert.notStrictEqual(wrongDigest, digest);
      const viaBytes = await outcome(() => qsign.verify(env, Object.assign({ bytes: wrong }, base)));
      assertNotValid(viaBytes, 'iteration ' + i + ' wrong document ' + j + ' as bytes');
      const viaDigest = await outcome(() => qsign.verify(env, Object.assign({ digest: r.int(2) ? wrongDigest : wrongDigest.toUpperCase() }, base)));
      assertNotValid(viaDigest, 'iteration ' + i + ' wrong document ' + j + ' as digest');
      if (viaBytes.result) assert.strictEqual(viaBytes.result.status, 'invalid');
    }
    const right = await qsign.verify(env, Object.assign({ bytes: doc }, base));
    assert.strictEqual(right.status, 'valid', 'iteration ' + i + ' the honest document did not verify');
  }
});

test('a document given in a form the verifier cannot read never verifies valid and is refused with the QSIGN_ code', async () => {
  const r = rng(0xd0c3);
  const key = qsign.generateKey();
  const doc = randomDocument(r);
  const env = await qsign.sign({ key, bytes: doc });
  const hex = qsign.parseEnvelope(env).digest;
  const forms = [
    { bytes: doc.toString('hex') }, { bytes: Array.from(doc) }, { bytes: null }, { bytes: {} },
    { digest: null }, { digest: '' }, { digest: hex.slice(1) }, { digest: hex + '0' }, { digest: '0x' + hex }, { digest: Buffer.from(hex, 'hex').subarray(1) },
    { digest: Buffer.from(hex, 'hex').toString('base64') }, { file: '' }, { file: null }, { file: 123 },
    { bytes: doc, digest: hex }, { bytes: doc, file: '/nonexistent' }, { digest: hex, file: '/nonexistent' },
  ];
  for (const [i, f] of forms.entries()) {
    const o = await outcome(() => qsign.verify(env, Object.assign({ keyId: qsign.keyId(key), revocations: [], requireAnchor: false }, f)));
    assertNotValid(o, 'form ' + i + ' ' + Object.keys(f).join(','));
  }
});
