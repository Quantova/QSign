'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { campaign } = require('./fuzz');
const { honest, pinFakes } = require('./signed');

const CODE = 'QSIGN_';
const TYPES = ['document', 'key-publish', 'key-revoke'];

function stringsOf(v, out) {
  if (typeof v === 'string' && v.length < 200) out.push(v);
  else if (v && typeof v === 'object') for (const k of Object.keys(v)) stringsOf(v[k], out);
  return out;
}

let world;
async function setup() {
  if (!world) world = await honest();
  return world;
}

const isValid = (r) => r.status === 'valid' || r.valid === true;
const failing = (r) => JSON.stringify(r.checks.filter((c) => !c.ok));

TYPES.forEach((type, n) => {
  test('a changed ' + type + ' envelope never verifies valid, every refusal carries the ' + CODE + ' code and each check ends within the time bound', async (t) => {
    const w = await setup();
    const base = w.envelopes[type];
    const opts = w.optionsFor(type, { requireAnchor: false });
    const honestResult = await w.qsign.verify(base, opts);
    assert.strictEqual(honestResult.status, 'valid', failing(honestResult));
    const stats = await campaign({
      name: type,
      seed: 0x5161 + n,
      base,
      pool: stringsOf([w.envelopes, w.anchored], []),
      code: CODE,
      check: (m) => w.qsign.verify(m, opts),
      valid: isValid,
    });
    t.diagnostic(JSON.stringify(stats));
  });

  test('a changed Qstamp receipt never lets an anchored ' + type + ' envelope verify valid', async (t) => {
    pinFakes(t);
    const w = await setup();
    const base = w.anchored[type];
    const opts = w.optionsFor(type, w.ep);
    const honestResult = await w.qsign.verify(base, opts);
    assert.strictEqual(honestResult.status, 'valid', failing(honestResult));
    assert.notStrictEqual(honestResult.anchoredAt, null);
    const stats = await campaign({
      name: type + ' receipt',
      seed: 0xa71c + n,
      base: base.anchor,
      pool: stringsOf(Object.values(w.anchored).map((e) => e.anchor), []),
      code: CODE,
      check: (r) => w.qsign.verify(Object.assign({}, base, { anchor: r }), opts),
      valid: isValid,
    });
    t.diagnostic(JSON.stringify(stats));
  });

  test('a changed anchored ' + type + ' envelope never verifies valid', async (t) => {
    pinFakes(t);
    const w = await setup();
    const base = w.anchored[type];
    const opts = w.optionsFor(type, w.ep);
    const honestResult = await w.qsign.verify(base, opts);
    assert.strictEqual(honestResult.status, 'valid', failing(honestResult));
    const stats = await campaign({
      name: 'anchored ' + type,
      seed: 0x3e0d + n,
      base,
      pool: stringsOf([w.envelopes, w.anchored], []),
      code: CODE,
      check: (m) => w.qsign.verify(m, opts),
      valid: isValid,
    });
    t.diagnostic(JSON.stringify(stats));
  });
});
