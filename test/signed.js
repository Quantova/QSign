'use strict';

const path = require('path');
const qsign = require('..');
const { makeChain, client, SEED } = require('./chain');

const ROOT = path.join(__dirname, '..');
const qstamp = require('@quantovainc/qstamp');

function provenByFakes(r) {
  return !!r && r.status === 'unproven' && r.trust === 'custom-endpoints' && Array.isArray(r.checks) && r.checks.every((c) => c.ok || c.name === 'proof');
}

function pinFakes(t) {
  const had = Object.prototype.hasOwnProperty.call(qstamp, 'isProven');
  const before = qstamp.isProven;
  qstamp.isProven = provenByFakes;
  t.after(() => {
    if (had) qstamp.isProven = before;
    else delete qstamp.isProven;
  });
}

async function honest() {
  const key = qsign.generateKey();
  const keyId = qsign.keyId(key);
  const doc = Buffer.from('loan agreement 2026 0042');
  const chain = makeChain(ROOT);
  const ep = { trustCustomEndpoints: true, clients: [client(chain, 'a'), client(chain, 'b')] };
  const stamp = async (env) => (await qsign.anchor(env, Object.assign({ seed: SEED, index: 0 }, ep)))[0];
  const envelopes = {
    document: await qsign.sign({ key, bytes: doc, signer: 'Treasury officer', note: 'first tranche' }),
    'key-publish': qsign.keyStatement({ key, action: 'publish', signer: 'Treasury officer' }),
    'key-revoke': qsign.keyStatement({ key, action: 'revoke', signer: 'Treasury officer', note: 'rotated' }),
  };
  const anchored = {};
  for (const type of Object.keys(envelopes)) anchored[type] = await stamp(envelopes[type]);
  const optionsFor = (type, extra) => {
    const o = { keyId, revocations: [] };
    if (type === 'document') o.bytes = doc;
    else o.expectType = type;
    return Object.assign(o, extra || {});
  };
  return { qsign, key, keyId, doc, chain, ep, envelopes, anchored, optionsFor };
}

module.exports = { honest, pinFakes, provenByFakes, ROOT };
