// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const fs = require('fs');
const path = require('path');
const native = require('./native');
const qstamp = require('@quantovainc/qstamp');
const F = require('./format');

function requireProvingQstamp() {
  const dir = path.dirname(require.resolve('@quantovainc/qstamp/package.json'));
  const [major, minor] = String(require(path.join(dir, 'package.json')).version).split('.').map((n) => parseInt(n, 10));
  const released = major > 0 || minor >= 3;
  const staged = fs.existsSync(path.join(dir, 'lib', 'finality.js'));
  if (typeof qstamp.isProven !== 'function' || !(released || staged)) {
    throw new Error('the installed Qstamp is older than 0.3.0 and cannot prove anchors');
  }
}
requireProvingQstamp();

function requireSeed(key) {
  if (!(key instanceof Uint8Array) || key.length !== 32) {
    throw new Error('a signing key is a 32 byte Uint8Array seed, kept by its holder and wiped with fill(0) after use');
  }
  return key;
}

function generateKey() {
  const seed = new Uint8Array(32);
  globalThis.crypto.getRandomValues(seed);
  if (seed.every((b) => b === 0)) throw new Error('the secure random source returned only zeros');
  return seed;
}

function publicKey(key) {
  return Uint8Array.from(native.publicKey(requireSeed(key)));
}

function keyId(key) {
  return F.keyIdOf(publicKey(key));
}

function describeKey(key) {
  const pk = publicKey(key);
  return { format: 'qsign-key/1', algorithm: F.ALGORITHM, id: F.keyIdOf(pk), publicKey: Buffer.from(pk).toString('base64') };
}

function hashFile(file) {
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK || 0));
  } catch (e) {
    F.reject('the document ' + String(file).slice(0, 200) + ' could not be opened');
  }
  try {
    if (!fs.fstatSync(fd).isFile()) F.reject('the document must be a regular file');
  } catch (e) {
    fs.closeSync(fd);
    throw e;
  }
  return new Promise((resolve, reject) => {
    const h = require('crypto').createHash('sha3-256');
    const stream = fs.createReadStream(null, { fd, autoClose: true });
    stream.on('error', () => reject(Object.assign(new Error('the document could not be read'), { code: 'QSIGN_INVALID_INPUT' })));
    stream.on('data', (chunk) => h.update(chunk));
    stream.on('end', () => resolve(h.digest('hex')));
  });
}

async function subjectDigest(options) {
  const given = ['file', 'bytes', 'digest'].filter((k) => options[k] !== undefined);
  if (given.length !== 1) F.reject('give exactly one of file, bytes or digest');
  if (options.file !== undefined) {
    if (typeof options.file !== 'string' || options.file.length === 0) F.reject('file is a path');
    return hashFile(options.file);
  }
  if (options.bytes !== undefined) {
    if (!(options.bytes instanceof Uint8Array)) F.reject('bytes is a Uint8Array');
    return F.sha3(options.bytes).toString('hex');
  }
  if (options.digest instanceof Uint8Array && options.digest.length === 32) return Buffer.from(options.digest).toString('hex');
  if (typeof options.digest === 'string' && /^[0-9a-fA-F]{64}$/.test(options.digest)) return options.digest.toLowerCase();
  F.reject('digest is the SHA3-256 of the document, 32 bytes or 64 hex characters');
}

function seal(key, statement) {
  const pk = publicKey(key);
  const id = F.keyIdOf(pk);
  const full = Object.assign({}, statement, { keyId: id });
  F.requireTime(full.signedAt);
  F.requireText(full.signer, F.SIGNER_MAX, 'signer');
  F.requireText(full.note, F.NOTE_MAX, 'note');
  const rnd = new Uint8Array(32);
  globalThis.crypto.getRandomValues(rnd);
  let signature;
  try {
    signature = native.sign(key, F.payload(full), rnd);
  } finally {
    rnd.fill(0);
  }
  if (!native.verify(pk, F.payload(full), signature)) throw new Error('the new signature did not verify, nothing was produced');
  return {
    format: F.FORMAT,
    type: full.type,
    algorithm: F.ALGORITHM,
    key: { id, publicKey: Buffer.from(pk).toString('base64') },
    subject: { alg: F.DIGEST, digest: full.digest },
    signedAt: full.signedAt,
    signer: full.signer,
    note: full.note,
    signature: Buffer.from(signature).toString('base64'),
  };
}

function nowIso() {
  return new Date().toISOString();
}

async function sign(options) {
  if (!options || typeof options !== 'object') throw new Error('sign needs options');
  requireSeed(options.key);
  const digest = await subjectDigest(options);
  return seal(options.key, {
    type: 'document',
    digest,
    signedAt: options.signedAt === undefined ? nowIso() : options.signedAt,
    signer: options.signer === undefined ? '' : options.signer,
    note: options.note === undefined ? '' : options.note,
  });
}

function keyStatement(options) {
  if (!options || typeof options !== 'object') throw new Error('keyStatement needs options');
  if (options.action !== 'publish' && options.action !== 'revoke') throw new Error('action is publish or revoke');
  const id = keyId(options.key);
  return seal(options.key, {
    type: options.action === 'publish' ? 'key-publish' : 'key-revoke',
    digest: id,
    signedAt: options.signedAt === undefined ? nowIso() : options.signedAt,
    signer: options.signer === undefined ? '' : options.signer,
    note: options.note === undefined ? '' : options.note,
  });
}

function kindFor(type) {
  return type === 'document' ? 'document' : 'public_record';
}

function anchorBatch(envelopes) {
  const list = Array.isArray(envelopes) ? envelopes : [envelopes];
  if (list.length === 0) throw new Error('anchor needs at least one envelope');
  const parsed = list.map((e) => {
    const p = F.parse(e);
    if (p.anchor !== undefined) throw new Error('an envelope is already anchored');
    if (!native.verify(p.publicKey, F.payload(p.statement), p.signature)) throw new Error('an envelope carries a signature that does not verify');
    if (F.keyIdOf(p.publicKey) !== p.statement.keyId) throw new Error('an envelope names a key id that does not match its public key');
    return p;
  });
  const types = new Set(parsed.map((p) => kindFor(p.statement.type)));
  if (types.size !== 1) throw new Error('anchor document signatures and key statements in separate batches');
  return { list, parsed, kind: [...types][0] };
}

function attach(list, receipts) {
  if (!Array.isArray(receipts) || receipts.length !== list.length) throw new Error('the anchoring returned an unexpected number of receipts');
  return list.map((e, i) => Object.assign({}, e, { anchor: receipts[i] }));
}

async function anchor(envelopes, options) {
  const { list, parsed, kind } = anchorBatch(envelopes);
  if (!options || typeof options !== 'object') throw new Error('anchor needs the stamping options of a funded Quantova account');
  const records = parsed.map((p) => ({ alg: 'sha3-256', digest: F.anchorDigest(p.statement, p.signature) }));
  return attach(list, await qstamp.stamp(Object.assign({}, options, { records, kind })));
}

async function complete(envelopes, pending, options) {
  let plain;
  let p;
  try {
    plain = JSON.parse(JSON.stringify(Array.isArray(envelopes) ? envelopes : [envelopes]));
    p = JSON.parse(JSON.stringify(pending));
  } catch (e) {
    throw new Error('the envelopes and the pending stamp must be plain data');
  }
  for (const e of plain) if (e && typeof e === 'object' && !Array.isArray(e)) delete e.anchor;
  const { list, parsed, kind } = anchorBatch(plain);
  if (!p || typeof p !== 'object' || !Array.isArray(p.records) || p.records.length !== parsed.length || String(p.kind) !== String(qstamp.KINDS[kind])) {
    throw new Error('the pending stamp does not belong to these envelopes');
  }
  parsed.forEach((c, i) => {
    const r = p.records[i];
    if (!r || r.alg !== 'sha3-256' || r.digest !== F.anchorDigest(c.statement, c.signature).toString('hex')) throw new Error('the pending stamp does not belong to these envelopes, or they are in another order');
  });
  return attach(list, await qstamp.complete(p, options || {}));
}

module.exports = { generateKey, publicKey, keyId, describeKey, sign, keyStatement, anchor, complete, subjectDigest, kindFor };
