// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const { performance } = require('perf_hooks');
const qstamp = require('@quantovainc/qstamp');
const native = require('./native');
const F = require('./format');
const { own, strictOf } = require('./qsign');

const CLOCK_SKEW_MS = 5 * 60 * 1000;
const PASS = ['rpc', 'client', 'clients', 'contract', 'trustCustomContract', 'trustSingleEndpoint', 'trustCustomEndpoints', 'allowLoopback', 'endpointAllowList', 'expectedSender'];
const CLAIMED_TIME = { release: 'releasedAt', artifact: 'builtAt', attest: 'attestedAt', approve: 'approvedAt', revoke: 'revokedAt' };
const SIGNER_FIELD = { release: 'authorityKeyId', artifact: 'authorityKeyId', attest: 'authorityKeyId', approve: 'authorityKeyId', revoke: 'authorityKeyId' };
const SIGNER_ROLE = { release: 'authority', artifact: 'authority', attest: 'authority', approve: 'authority', revoke: 'authority' };

function plain(text) {
  return String(text).replace(/:\s+/g, ', ').replace(/;\s*/g, ', ').slice(0, 300);
}

function statusOf(checks) {
  const open = checks.filter((c) => !c.ok);
  if (open.some((c) => !c.transport && !c.indeterminate && !c.unproven)) return 'invalid';
  if (open.some((c) => c.transport || c.indeterminate)) return 'indeterminate';
  if (open.length) return 'unproven';
  return 'valid';
}

function recorder() {
  const checks = [];
  const add = (name, ok, detail, transport, indeterminate, unproven) => checks.push({ name, ok: !!ok, detail: plain(detail), transport: !!transport, indeterminate: !!indeterminate, unproven: !!unproven });
  return { checks, add };
}

function provenOf(result) {
  if (!result || (result.status !== 'valid' && result.status !== 'unproven')) return false;
  return typeof qstamp.isProven === 'function' && qstamp.isProven(result) === true;
}

function finish(checks, extra) {
  const status = statusOf(checks);
  return Object.assign({ valid: status === 'valid', status }, extra, { checks: checks.map((c) => Object.assign({}, c)) }, { valid: status === 'valid', status });
}

function anchorOptions(opts) {
  const out = Object.create(null);
  for (const k of PASS) if (opts[k] !== undefined) out[k] = opts[k];
  return out;
}

function networkProblem(opts) {
  if (opts.network === 'custom') return opts.trustCustomEndpoints === true ? null : 'network custom needs trustCustomEndpoints, it accepts anchors on any chain the endpoints name';
  if (typeof opts.network !== 'string' || !Object.prototype.hasOwnProperty.call(qstamp.NETWORKS, opts.network)) return 'network is required and names the network the records were anchored on, one of ' + Object.keys(qstamp.NETWORKS).concat(['custom']).join(', ');
  return null;
}

function onNetwork(receipt, opts) {
  if (opts.network === 'custom') return true;
  const net = qstamp.NETWORKS[opts.network];
  return !!receipt.chain && receipt.chain.id === net.chainId && receipt.chain.genesis === net.genesis;
}

function signatureOk(p) {
  return p.signerId === F.keyIdOf(p.publicKey) && native.verify(p.publicKey, F.encoded(p), p.signature);
}

function iso(pos) {
  return new Date(pos.ms).toISOString();
}

const NET = Symbol('endpoints');
const DEADLINE = Symbol('deadline');
const DEFAULT_ANCHOR_DELAY_S = 24 * 60 * 60;
const ANCHOR_DELAY_MAX_S = 366 * 24 * 60 * 60;
const DEFAULT_DEADLINE_MS = 120000;
const DEADLINE_MAX_MS = 600000;

function deadlineOf(opts) {
  if (opts.deadlineMs === undefined) return DEFAULT_DEADLINE_MS;
  const v = opts.deadlineMs;
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 1 || v > DEADLINE_MAX_MS) F.reject('deadlineMs is a whole number of milliseconds from 1 to ' + DEADLINE_MAX_MS);
  return v;
}

function timeUp(opts) {
  return opts[DEADLINE] !== undefined && performance.now() >= opts[DEADLINE];
}

function delayOf(opts) {
  if (opts.maxAnchorDelay === undefined) return DEFAULT_ANCHOR_DELAY_S * 1000;
  const v = opts.maxAnchorDelay;
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 60 || v > ANCHOR_DELAY_MAX_S) F.reject('maxAnchorDelay is a whole number of seconds from 60 to ' + ANCHOR_DELAY_MAX_S);
  return v * 1000;
}

function noteEndpoints(opts, result) {
  const net = opts[NET];
  if (!net || !(result.endpoints || []).length) return;
  for (const e of result.endpoints) net.endpoints.add(e);
  net.official = net.official !== false && result.officialEndpoints === true;
}

async function checkAnchor(p, opts, add, label) {
  const receipt = p.anchor;
  if (receipt === undefined) return null;
  try {
    if (receipt === null || typeof receipt !== 'object' || Array.isArray(receipt)) {
      add(label, false, 'the anchor is not a Qstamp receipt');
      return null;
    }
    if (receipt.kind !== String(F.KIND)) {
      add(label, false, 'the anchor was not recorded under the QSign record kind');
      return null;
    }
    if (!onNetwork(receipt, opts)) {
      add(label, false, 'the anchor was recorded on another network than ' + opts.network);
      return null;
    }
    if (timeUp(opts)) {
      add(label + ' confirmed', false, 'the anchor was not checked, the verification reached its time limit, so it is treated as not anchored', true, true);
      return null;
    }
    const result = await qstamp.verify(receipt, Object.assign(anchorOptions(opts), { digest: F.anchorDigest(p) }));
    noteEndpoints(opts, result);
    const confirmed = result.status === 'valid' || result.status === 'unproven';
    const proven = provenOf(result);
    for (const c of result.checks) {
      if (proven && !c.ok) continue;
      add(label + ' ' + c.name, c.ok, c.detail, confirmed ? false : c.transport, false, confirmed && !c.ok);
    }
    if (!confirmed) {
      if (result.status === 'invalid') {
        if (!result.checks.some((c) => !c.ok && !c.transport)) add(label, false, 'the anchor was refuted');
      } else {
        add(label + ' confirmed', false, 'the anchor was neither confirmed nor refuted, so it is treated as not anchored', true, true);
      }
      return null;
    }
    if (!proven) {
      const s = strictOf(opts);
      if (!result.checks.some((c) => !c.ok)) add(label + ' proof', false, 'the anchor was confirmed only by endpoints that are not pinned independent operators of the network, so it is not proven' + (s ? ' and is treated as not anchored' : ''), false, false, true);
      if (s) return null;
    }
    const position = {
      ms: receipt.anchor.time * 1000,
      height: receipt.anchor.height,
      tx: receipt.anchor.tx,
      index: receipt.proof.index,
      chain: receipt.chain.id + '/' + receipt.chain.genesis,
    };
    const claimed = Date.parse(p.statement[CLAIMED_TIME[p.type]]);
    if (claimed > position.ms + CLOCK_SKEW_MS) {
      add(label + ' time', false, 'the claimed time is later than the anchor time ' + iso(position));
      return null;
    }
    const delayMs = delayOf(opts);
    if (position.ms - claimed > delayMs) {
      add(label + ' time', false, 'anchored at ' + iso(position) + ', more than ' + Math.round(delayMs / 3600000) + ' hours after its claimed time, so the claimed time is not proven', false, true);
      return position;
    }
    if (opts.at !== undefined && position.ms > Date.parse(opts.at)) {
      add(label + ' time', false, 'anchored at ' + iso(position) + ', after the time given for verification, so it was not proven at that time', false, true);
      return position;
    }
    add(label + ' time', true, 'recorded by ' + iso(position));
    return position;
  } catch (e) {
    add(label, false, 'the anchor could not be checked, ' + ((e && e.message) || 'unknown error'));
    return null;
  }
}

function expectedParty(opts, name, keyIdName, publicKeyName) {
  if (opts[keyIdName] !== undefined && opts[publicKeyName] !== undefined) F.reject('give ' + keyIdName + ' or ' + publicKeyName + ', not both');
  if (opts[keyIdName] !== undefined) {
    if (typeof opts[keyIdName] !== 'string' || !/^[0-9a-f]{64}$/.test(opts[keyIdName])) F.reject(keyIdName + ' is 64 lowercase hex characters');
    return opts[keyIdName];
  }
  if (opts[publicKeyName] !== undefined) {
    let pk = opts[publicKeyName];
    if (typeof pk === 'string') {
      const raw = Buffer.from(pk, 'base64');
      if (raw.toString('base64') !== pk) F.reject(publicKeyName + ' is canonical base64');
      pk = raw;
    }
    return F.keyIdOf(pk);
  }
  return null;
}

async function verifyRecord(envelope, opts) {
  const { checks, add } = recorder();
  let p;
  try {
    p = F.parse(envelope);
  } catch (e) {
    add('format', false, e.message);
    return finish(checks, { type: null });
  }
  if (opts.type !== undefined && p.type !== opts.type) {
    add('format', false, 'a ' + p.type + ' envelope was given where a ' + opts.type + ' was expected');
    return finish(checks, { type: p.type });
  }
  add('format', true, 'a well formed ' + p.type + ' record');
  const role = SIGNER_ROLE[p.type];
  const sigOk = signatureOk(p);
  add('signature', sigOk, sigOk ? 'the ML-DSA-65 signature of the ' + role + ' is valid' : 'the signature does not verify');
  const bound = p.signerId === p.statement[SIGNER_FIELD[p.type]];
  add('signer', bound, bound ? 'signed by the ' + role + ' it names' : 'signed by a key other than the ' + role + ' it names');
  if (opts.signerKeyId !== undefined || opts.signerPublicKey !== undefined) {
    const expected = expectedParty(opts, role, 'signerKeyId', 'signerPublicKey');
    const same = expected !== null && expected === p.signerId;
    add('expected signer', same, same ? 'signed by the expected party' : 'signed by a different party than expected');
  }
  if (opts.releaseId !== undefined) {
    const same = typeof opts.releaseId === 'string' && opts.releaseId === p.statement.releaseId;
    add('expected release', same, same ? 'this record is for the expected release' : 'this record is for a different release than expected');
  }
  if (opts.prior !== undefined) {
    let prior = null;
    try {
      prior = F.parse(opts.prior);
    } catch (e) {
      add('prior', false, 'the prior envelope is not well formed');
    }
    if (prior) {
      const refField = p.type === 'artifact' ? 'releaseRef' : 'priorRef';
      const linked = signatureOk(prior) && prior.statement.releaseId === p.statement.releaseId && p.statement[refField] === F.refOf(prior);
      add('prior', linked, linked ? 'follows the given prior record of the same release' : 'does not follow the given prior record of this release');
    }
  }
  const pos = sigOk && bound ? await checkAnchor(p, opts, add, 'anchor') : null;
  if (sigOk && bound && p.anchor === undefined) {
    if (opts.requireAnchor !== false) add('anchor', false, 'the record is not anchored, so its time is only the claim of the ' + role, false, true);
    else add('anchor', true, 'not anchored');
  }
  return finish(checks, { type: p.type, releaseId: p.statement.releaseId, signerId: p.signerId, statement: p.statement, anchoredAt: pos ? iso(pos) : null });
}

const VERIFY_OPTIONS = new Set(['type', 'prior', 'releaseId', 'signerKeyId', 'signerPublicKey', 'strict', 'requireAnchor', 'maxAnchorDelay', 'at', 'deadlineMs', 'rpc', 'client', 'clients', 'trustSingleEndpoint', 'trustCustomEndpoints', 'allowLoopback', 'endpointAllowList', 'expectedSender', 'contract', 'trustCustomContract', 'network', 'clockSlackMs']);

async function verify(envelope, options) {
  if (options === undefined || options === null || typeof options !== 'object') F.reject('options is an object that names the network and the expected type');
  const opts = own(options);
  const unknown = Object.keys(opts).find((k) => !VERIFY_OPTIONS.has(k));
  if (unknown !== undefined) F.reject('the option ' + unknown.replace(/[^A-Za-z0-9_]/g, '?').slice(0, 40) + ' is not an option of verify');
  if (opts.type !== undefined && !F.TYPES.includes(opts.type)) F.reject('type is one of ' + F.TYPES.join(', ') + ', so a record of one type can never be presented as another');
  delayOf(opts);
  if (strictOf(opts) && opts.trustSingleEndpoint === true) F.reject('strict verification needs at least two independent endpoints and refuses trustSingleEndpoint, set strict to false to see what one endpoint reports, which is never a valid result');
  if (opts.at !== undefined) {
    const tp = F.timeProblem(opts.at, 'at');
    if (tp) F.reject(tp);
  }
  const np = networkProblem(opts);
  if (np) F.reject(np);
  opts[DEADLINE] = performance.now() + deadlineOf(opts);
  const net = { endpoints: new Set(), official: null };
  opts[NET] = net;
  const res = await verifyRecord(envelope, opts);
  const checks = res.checks;
  delete res.checks;
  return Object.assign(res, { endpoints: [...net.endpoints], officialEndpoints: net.official, checks });
}

module.exports = { verify };
