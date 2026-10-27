// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const { performance } = require('perf_hooks');
const native = require('./native');
const qstamp = require('@quantovainc/qstamp');
const F = require('./format');
const { subjectDigest, kindFor } = require('./sign');

const CLOCK_SKEW_MS = 5 * 60 * 1000;
const REVOCATIONS_MAX = 64;
const PASS = ['rpc', 'client', 'clients', 'contract', 'trustCustomContract', 'trustSingleEndpoint', 'trustCustomEndpoints', 'allowLoopback', 'endpointAllowList', 'expectedSender'];

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

function statusOf(checks) {
  const open = checks.filter((c) => !c.ok);
  if (open.some((c) => !c.transport && !c.indeterminate && !c.unproven && !c.unchecked)) return 'invalid';
  if (open.some((c) => c.transport || c.indeterminate)) return 'indeterminate';
  if (open.some((c) => c.unchecked)) return 'unverified';
  if (open.length) return 'unproven';
  return 'valid';
}

function provenOf(result) {
  if (!result || (result.status !== 'valid' && result.status !== 'unproven')) return false;
  return typeof qstamp.isProven === 'function' && qstamp.isProven(result) === true;
}

const SELF_ASSERTED = 'the signer name and the note are text chosen by the holder of the key, they are not a verified identity, the identity that was checked is the expected key';

const NET = Symbol('endpoints');
const DEADLINE = Symbol('deadline');
const DEFAULT_ANCHOR_DELAY_S = 24 * 60 * 60;
const ANCHOR_DELAY_MAX_S = 366 * 24 * 60 * 60;
const DEFAULT_DEADLINE_MS = 120000;
const DEADLINE_MAX_MS = 600000;

function delayOf(opts) {
  if (opts.maxAnchorDelay === undefined) return DEFAULT_ANCHOR_DELAY_S * 1000;
  const v = opts.maxAnchorDelay;
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 60 || v > ANCHOR_DELAY_MAX_S) F.reject('maxAnchorDelay is a whole number of seconds from 60 to ' + ANCHOR_DELAY_MAX_S);
  return v * 1000;
}

function deadlineOf(opts) {
  if (opts.deadlineMs === undefined) return DEFAULT_DEADLINE_MS;
  const v = opts.deadlineMs;
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 1 || v > DEADLINE_MAX_MS) F.reject('deadlineMs is a whole number of milliseconds from 1 to ' + DEADLINE_MAX_MS);
  return v;
}

function timeUp(opts) {
  return opts[DEADLINE] !== undefined && performance.now() >= opts[DEADLINE];
}


function noteEndpoints(opts, result) {
  const net = opts[NET];
  if (!net || !(result.endpoints || []).length) return;
  for (const e of result.endpoints) net.endpoints.add(e);
  net.official = net.official !== false && result.officialEndpoints === true;
}

async function checkAnchor(parsed, opts, add, label) {
  const receipt = parsed.anchor;
  if (receipt === undefined) return null;
  if (receipt === null || typeof receipt !== 'object' || Array.isArray(receipt)) {
    add(label, false, 'the anchor is not a Qstamp receipt');
    return null;
  }
  const expected = kindFor(parsed.statement.type);
  if (receipt.kind !== String(qstamp.KINDS[expected])) {
    add(label, false, 'the anchor was not recorded as a ' + expected.replace('_', ' '));
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
  let result;
  try {
    result = await qstamp.verify(receipt, Object.assign(anchorOptions(opts), { digest: F.anchorDigest(parsed.statement, parsed.signature) }));
  } catch (e) {
    add(label, false, 'the anchor could not be checked, ' + plain((e && e.message) || 'unknown error'));
    return null;
  }
  noteEndpoints(opts, result);
  const confirmed = result.status === 'valid' || result.status === 'unproven';
  const proven = provenOf(result);
  for (const c of result.checks) {
    if (proven && !c.ok) continue;
    add(label + ' ' + c.name, c.ok, plain(c.detail), confirmed ? false : c.transport, false, confirmed && !c.ok);
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
    if (!result.checks.some((c) => !c.ok)) add(label + ' proof', false, 'the anchor was confirmed only by endpoints that are not pinned independent operators of the network, so it is not proven and is treated as not anchored', false, false, true);
    return null;
  }
  const anchoredMs = receipt.anchor.time * 1000;
  const position = { ms: anchoredMs, height: receipt.anchor.height, chain: receipt.chain.id + '/' + receipt.chain.genesis };
  const claimedMs = Date.parse(parsed.statement.signedAt);
  if (claimedMs > anchoredMs + CLOCK_SKEW_MS) {
    add(label + ' time', false, 'the signer claims ' + parsed.statement.signedAt + ', after the anchor time ' + new Date(anchoredMs).toISOString());
    return null;
  }
  if (opts.atMs !== undefined && anchoredMs > opts.atMs) {
    add(label + ' time', false, 'anchored at ' + new Date(anchoredMs).toISOString() + ', after the time given for verification, so it was not proven at that time', false, true);
    return null;
  }
  const delayMs = delayOf(opts);
  if (anchoredMs - claimedMs > delayMs) {
    add(label + ' time', false, 'anchored at ' + new Date(anchoredMs).toISOString() + ', more than ' + Math.round(delayMs / 3600000) + ' hours after its stated time, so the stated time is not proven', false, true);
    return position;
  }
  add(label + ' time', true, 'the signature existed by ' + new Date(anchoredMs).toISOString());
  return position;
}

function plain(text) {
  return String(text).replace(/:\s+/g, ', ').replace(/;\s*/g, ', ').slice(0, 300);
}

function expectedKeyId(opts) {
  if (opts.keyId !== undefined && opts.publicKey !== undefined) F.reject('give keyId or publicKey, not both');
  if (opts.keyId !== undefined) {
    if (typeof opts.keyId !== 'string' || !/^[0-9a-f]{64}$/.test(opts.keyId)) F.reject('keyId is 64 lowercase hex characters');
    return opts.keyId;
  }
  let pk = opts.publicKey;
  if (typeof pk === 'string') {
    const raw = Buffer.from(pk, 'base64');
    if (raw.toString('base64') !== pk) F.reject('publicKey is canonical base64');
    pk = raw;
  }
  if (!((ArrayBuffer.isView(pk) && pk instanceof Uint8Array)) || pk.length !== F.PUBLIC_KEY_BYTES) F.reject('publicKey is ' + F.PUBLIC_KEY_BYTES + ' bytes');
  return F.keyIdOf(pk);
}

function signatureValid(parsed) {
  return F.keyIdOf(parsed.publicKey) === parsed.statement.keyId
    && native.verify(parsed.publicKey, F.payload(parsed.statement), parsed.signature);
}

function publicationCheck(parsed, publication, add) {
  let pub;
  try {
    pub = F.parse(publication);
  } catch (e) {
    add('signer name', false, 'the key publication is not a valid envelope, ' + plain(e.message));
    return false;
  }
  if (pub.statement.type !== 'key-publish' || pub.statement.keyId !== parsed.statement.keyId || pub.statement.digest !== pub.statement.keyId || !signatureValid(pub)) {
    add('signer name', false, 'the key publication is not a key publish statement signed by this key');
    return false;
  }
  const same = pub.statement.signer === parsed.statement.signer;
  add('signer name', same, same ? 'the signer name matches the name published with this key' : 'the signer name differs from the name published with this key');
  return same;
}

async function guarded(fn, add, label) {
  try {
    return await fn();
  } catch (e) {
    add(label, false, 'the anchor could not be checked');
    return null;
  }
}

const VERIFY_OPTIONS = new Set(['network', 'file', 'bytes', 'digest', 'keyId', 'publicKey', 'revocations', 'keyPublication', 'requireAnchor', 'maxAnchorDelay', 'at', 'deadlineMs', 'expectType', 'rpc', 'client', 'clients', 'trustSingleEndpoint', 'trustCustomEndpoints', 'allowLoopback', 'endpointAllowList', 'expectedSender', 'contract', 'trustCustomContract']);

async function verify(envelope, options) {
  if (options !== undefined && (options === null || typeof options !== 'object')) F.reject('options is an object');
  const opts = Object.assign(Object.create(null), options);
  const unknown = Object.keys(opts).find((k) => !VERIFY_OPTIONS.has(k));
  if (unknown !== undefined) F.reject('the option ' + unknown.replace(/[^A-Za-z0-9_]/g, '?').slice(0, 40) + ' is not an option of verify');
  opts[NET] = { endpoints: new Set(), official: null };
  opts[DEADLINE] = performance.now() + deadlineOf(opts);
  delayOf(opts);
  if (opts.at !== undefined) {
    if (typeof opts.at !== 'string' || F.timeProblem(opts.at)) F.reject('at is an ISO 8601 UTC time with milliseconds and a Z suffix');
    opts.atMs = Date.parse(opts.at);
  }
  const checks = [];
  const add = (name, ok, detail, transport, indeterminate, unproven, unchecked) => checks.push({ name, ok: !!ok, detail, transport: !!transport, indeterminate: !!indeterminate, unproven: !!unproven, unchecked: !!unchecked });
  const result = (extra) => {
    const status = statusOf(checks);
    return Object.assign({ valid: status === 'valid', status, checks: checks.map((c) => Object.assign({}, c)) }, extra, { endpoints: [...opts[NET].endpoints], officialEndpoints: opts[NET].official }, { valid: status === 'valid', status });
  };

  let parsed;
  try {
    parsed = F.parse(envelope);
  } catch (e) {
    add('format', false, plain(e.message));
    return result({ type: null, keyId: null, signedAt: null, anchoredAt: null, contentChecked: false, signerTrusted: false, signerBound: false, revocationChecked: false, notes: [] });
  }
  add('format', true, 'a well formed ' + F.FORMAT + ' envelope');
  if (opts.atMs !== undefined && Date.parse(parsed.statement.signedAt) > opts.atMs + CLOCK_SKEW_MS) {
    add('time', false, 'the signature is dated ' + parsed.statement.signedAt + ', after the time given for verification');
  }

  const keyOk = F.keyIdOf(parsed.publicKey) === parsed.statement.keyId;
  add('key', keyOk, keyOk ? 'the key id is the fingerprint of the public key' : 'the key id does not match the public key');

  const sigOk = keyOk && native.verify(parsed.publicKey, F.payload(parsed.statement), parsed.signature);
  add('signature', sigOk, sigOk ? 'the ML-DSA-65 signature is valid for this statement' : 'the signature does not match the statement');

  let contentChecked = false;
  const given = ['file', 'bytes', 'digest'].filter((k) => opts[k] !== undefined);
  if (given.length > 1) F.reject('give at most one of file, bytes or digest');
  const expectType = opts.expectType !== undefined ? opts.expectType : 'document';
  if (!F.TYPES.includes(expectType)) F.reject('expectType is one of ' + F.TYPES.join(', '));
  const sameType = parsed.statement.type === expectType;
  add('type', sameType, sameType ? 'a ' + expectType + ' envelope as expected' : 'this is a ' + parsed.statement.type + ' envelope, not a ' + expectType + ' signature');
  if (parsed.statement.type === 'document') {
    if (given.length === 1) {
      const digest = await subjectDigest(opts);
      contentChecked = true;
      const same = digest === parsed.statement.digest;
      add('content', same, same ? 'the document matches the signed fingerprint' : 'the document differs from the one that was signed');
    } else {
      add('content', false, 'no document was given, so it was not verified that this signature covers any document, give the file, bytes or digest', false, false, false, true);
    }
  } else {
    const same = parsed.statement.digest === parsed.statement.keyId;
    add('content', same, same ? 'the statement concerns the key that signed it' : 'the statement names a different key');
  }

  if (opts.keyId === undefined && opts.publicKey === undefined) F.reject('the expected signer is required, give keyId or publicKey, so a signature by another key can never verify');
  const signerTrusted = expectedKeyId(opts) === parsed.statement.keyId;
  add('signer', signerTrusted, signerTrusted ? 'signed by the expected key' : 'signed by a different key than the one expected');
  const signerBound = sigOk && opts.keyPublication !== undefined ? publicationCheck(parsed, opts.keyPublication, add) : false;
  const np = networkProblem(opts);
  if (np) F.reject(np);

  const anchoredAt = sigOk ? await guarded(() => checkAnchor(parsed, opts, add, 'anchor'), add, 'anchor') : null;
  if (parsed.anchor === undefined) {
    if (opts.requireAnchor !== false) add('anchor', false, 'the signature is not anchored, so its time is only the signer\'s claim', false, true);
    else add('anchor', true, 'not anchored, the signing time is the signer\'s claim');
  }

  const revocations = opts.revocations === undefined ? [] : opts.revocations;
  if (!Array.isArray(revocations) || revocations.length > REVOCATIONS_MAX) F.reject('revocations is a list of at most ' + REVOCATIONS_MAX + ' key-revoke envelopes');
  if (parsed.statement.type !== 'key-revoke' && opts.revocations === undefined) add('revocations', false, 'no revocation list was given, so it is not known whether the key was revoked, give revocations, an empty list when none is held', false, true);
  if (parsed.statement.type !== 'key-revoke' && sigOk) {
    const groups = new Map();
    for (const [i, rev] of revocations.entries()) {
      const name = 'revocation ' + (i + 1);
      let r;
      try {
        r = F.parse(rev);
      } catch (e) {
        add(name, true, 'ignored, it is not a well formed envelope');
        continue;
      }
      if (r.statement.type !== 'key-revoke' || r.statement.keyId !== parsed.statement.keyId) {
        add(name, true, 'ignored, it concerns another key or is not a revocation');
        continue;
      }
      if (!signatureValid(r) || r.statement.digest !== r.statement.keyId) {
        add(name, true, 'ignored, it is not validly signed by this key');
        continue;
      }
      const sigKey = Buffer.from(r.signature).toString('base64');
      if (!groups.has(sigKey)) groups.set(sigKey, []);
      else add(name, true, 'a further copy of an earlier revocation, its anchor is considered with the others');
      groups.get(sigKey).push({ r, name });
    }
    const first = (a, b) => (a.chain === b.chain ? a.height <= b.height : a.ms <= b.ms);
    for (const copies of groups.values()) {
      const name = copies[0].name;
      const sub = [];
      const subAdd = (n, ok, detail, transport) => sub.push({ name: n, ok, detail, transport });
      let revokedAt = null;
      const seen = new Set();
      for (const c of copies) {
        if (c.r.anchor === undefined) continue;
        const key = JSON.stringify(c.r.anchor);
        if (seen.has(key)) continue;
        seen.add(key);
        const pos = await guarded(() => checkAnchor(c.r, opts, subAdd, c.name + ' anchor'), subAdd, c.name + ' anchor');
        if (pos && (revokedAt === null || first(pos, revokedAt))) revokedAt = pos;
      }
      if (revokedAt === null) for (const c of sub) if (!c.ok) add(c.name, false, c.detail, c.transport, true);
      if (revokedAt === null) {
        add(name, false, 'the key was revoked but no copy of the revocation has a verified anchor time, so its order cannot be proven', false, true);
      } else if (anchoredAt === null) {
        add(name, false, 'the key was revoked at ' + new Date(revokedAt.ms).toISOString() + ' and this signature has no anchor proving it came first', false, true);
      } else if (first(revokedAt, anchoredAt)) {
        add(name, false, 'the key was revoked at ' + new Date(revokedAt.ms).toISOString() + ', before the signature was anchored');
      } else {
        add(name, true, 'the key was revoked at ' + new Date(revokedAt.ms).toISOString() + ', after this signature was anchored');
      }
    }
  }

  return result({
    type: parsed.statement.type,
    keyId: parsed.statement.keyId,
    signer: parsed.statement.signer,
    note: parsed.statement.note,
    subject: parsed.statement.digest,
    signedAt: parsed.statement.signedAt,
    anchoredAt: anchoredAt === null ? null : new Date(anchoredAt.ms).toISOString(),
    revocationChecked: opts.revocations !== undefined && parsed.statement.type !== 'key-revoke',
    contentChecked,
    signerTrusted,
    signerBound,
    notes: [SELF_ASSERTED],
  });
}

module.exports = { verify };
