// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const qsign = require('..');
const qstamp = require('@quantovainc/qstamp');
const { honest, pinFakes } = require('./signed');

test('the shared deadline stops anchor checks across the whole verify pass', async (t) => {
  const h = await honest();
  pinFakes(t);
  const realVerify = qstamp.verify;
  let calls = 0;
  qstamp.verify = (...a) => {
    calls += 1;
    return realVerify(...a);
  };
  const perf = require('perf_hooks').performance;
  const realNow = perf.now.bind(perf);
  let first = true;
  perf.now = () => {
    if (first) {
      first = false;
      return 0;
    }
    return 1e12;
  };
  t.after(() => {
    perf.now = realNow;
    qstamp.verify = realVerify;
  });
  const opts = h.optionsFor('document', Object.assign({}, h.ep, { revocations: [h.anchored['key-revoke']] }));
  const res = await qsign.verify(h.anchored.document, opts);
  assert.equal(calls, 0);
  assert.notEqual(res.status, 'valid');
  assert.ok(res.checks.some((x) => !x.ok && /reached its time limit/.test(x.detail)));
});

test('a generous deadline still checks every anchor', async (t) => {
  const h = await honest();
  pinFakes(t);
  const res = await qsign.verify(h.anchored.document, h.optionsFor('document', Object.assign({}, h.ep, { deadlineMs: 600000 })));
  assert.equal(res.status, 'valid', JSON.stringify(res.checks.filter((x) => !x.ok)));
});

test('deadlineMs is bounded', async () => {
  const h = await honest();
  await assert.rejects(qsign.verify(h.anchored.document, h.optionsFor('document', Object.assign({}, h.ep, { deadlineMs: 0 }))), /deadlineMs/);
  await assert.rejects(qsign.verify(h.anchored.document, h.optionsFor('document', Object.assign({}, h.ep, { deadlineMs: 600001 }))), /deadlineMs/);
});
