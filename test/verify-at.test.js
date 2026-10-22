// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const qsign = require('..');
const { makeChain, client, SEED } = require('./chain');

const ROOT = path.join(__dirname, '..');
const qstamp = require('@quantovainc/qstamp');
const doc = Buffer.from('payment order 2026 0077');

test('a signature verified as of a time before its anchor is not proven at that time and one dated later is refused', async (t) => {
  const key = qsign.generateKey();
  const env = await qsign.sign({ key, bytes: doc, signer: 'Treasury officer' });
  const chain = makeChain(ROOT);
  const ep = { trustCustomEndpoints: true, clients: [client(chain, 'a'), client(chain, 'b')] };
  const [anchored] = await qsign.anchor(env, Object.assign({ seed: SEED, index: 0 }, ep));
  const before = qstamp.isProven;
  qstamp.isProven = () => true;
  t.after(() => {
    qstamp.isProven = before;
  });
  const anchorMs = anchored.anchor.anchor.time * 1000;
  const base = Object.assign({ network: 'custom', bytes: doc, keyId: qsign.keyId(key), revocations: [] }, ep);
  const later = await qsign.verify(anchored, Object.assign({ at: new Date(anchorMs + 3600e3).toISOString() }, base));
  assert.strictEqual(later.status, 'valid', JSON.stringify(later.checks.filter((c) => !c.ok)));
  const earlier = await qsign.verify(anchored, Object.assign({ at: new Date(anchorMs - 1800e3).toISOString() }, base));
  assert.notStrictEqual(earlier.status, 'valid');
  assert.ok(earlier.checks.some((c) => /after the time given for verification/.test(c.detail)));
  const signedMs = Date.parse(env.signedAt);
  const beforeSigning = await qsign.verify(env, Object.assign({ at: new Date(signedMs - 3600e3).toISOString(), requireAnchor: false }, base));
  assert.strictEqual(beforeSigning.status, 'invalid');
  await assert.rejects(qsign.verify(env, Object.assign({ at: 'yesterday' }, base)), /at is an ISO 8601 UTC time/);
});
