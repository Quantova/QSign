// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const nodeCrypto = require('crypto');

const FORMAT = 'qsign/1';
const ALGORITHM = 'ML-DSA-65';
const DIGEST = 'sha3-256';
const CONTEXT = Buffer.from('quantova/qsign/1', 'ascii');
const KEY_DOMAIN = Buffer.from('quantova/qsign/key/1', 'ascii');
const ANCHOR_DOMAIN = Buffer.from('quantova/qsign/anchor/1', 'ascii');
const MAGIC = Buffer.from('QSIG', 'ascii');
const VERSION = 1;
const PUBLIC_KEY_BYTES = 1952;
const SIGNATURE_BYTES = 3309;
const SIGNER_MAX = 200;
const NOTE_MAX = 1000;
const TYPES = Object.freeze(['document', 'key-publish', 'key-revoke']);
const HEX32 = /^[0-9a-f]{64}$/;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const UNSAFE_TEXT = /[\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000\u2800\u115f\u1160\u3164\uffa0]/u;

function fail(message) {
  const e = new Error('the envelope is not valid, ' + message);
  e.code = 'QSIGN_INVALID_ENVELOPE';
  throw e;
}

function reject(message) {
  const e = new Error(message);
  e.code = 'QSIGN_INVALID_INPUT';
  throw e;
}

function sha3(...parts) {
  const h = nodeCrypto.createHash('sha3-256');
  for (const p of parts) h.update(p);
  return h.digest();
}

function keyIdOf(publicKey) {
  if (!((ArrayBuffer.isView(publicKey) && publicKey instanceof Uint8Array)) || publicKey.length !== PUBLIC_KEY_BYTES) {
    throw new Error('a public key is ' + PUBLIC_KEY_BYTES + ' bytes');
  }
  return sha3(KEY_DOMAIN, Buffer.from([0]), publicKey).toString('hex');
}

function textProblem(value, max, what) {
  if (typeof value !== 'string') return what + ' must be text';
  if (value.length > max) return what + ' is longer than ' + max + ' characters';
  if (!value.isWellFormed()) return what + ' holds a broken Unicode surrogate';
  if (value.normalize('NFC') !== value) return what + ' must be in Unicode normal form C';
  if (UNSAFE_TEXT.test(value)) return what + ' holds control, invisible or direction characters';
  return null;
}

function checkText(value, max, what) {
  const problem = textProblem(value, max, what);
  if (problem) fail(problem);
  return value;
}

function requireText(value, max, what) {
  const problem = textProblem(value, max, what);
  if (problem) reject(problem);
  return value;
}

function timeProblem(value) {
  if (typeof value !== 'string' || !ISO_UTC.test(value)) return 'signedAt must be an ISO 8601 UTC time with milliseconds and a Z suffix';
  const ms = Date.parse(value);
  if (!Number.isFinite(ms) || new Date(ms).toISOString() !== value) return 'signedAt is not a real calendar time';
  return null;
}

function requireTime(value) {
  const problem = timeProblem(value);
  if (problem) reject(problem);
  return value;
}

function decodeBase64(value, bytes, what) {
  if (typeof value !== 'string' || value.length === 0) fail(what + ' must be base64 text');
  if (value.length !== Math.ceil(bytes / 3) * 4) fail(what + ' must encode exactly ' + bytes + ' bytes');
  const raw = Buffer.from(value, 'base64');
  if (raw.toString('base64') !== value) fail(what + ' is not canonical base64');
  if (raw.length !== bytes) fail(what + ' must decode to ' + bytes + ' bytes');
  return raw;
}

function exactKeys(obj, required, optional, where) {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) fail(where + ' must be an object');
  const allowed = new Set(required.concat(optional));
  for (const k of Object.keys(obj)) if (!allowed.has(k)) fail(where + ' holds an unexpected field ' + JSON.stringify(k).replace(/[^\x20-\x7e]/gu, (c) => '\\u{' + c.codePointAt(0).toString(16) + '}').slice(0, 40));
  for (const k of required) if (!Object.prototype.hasOwnProperty.call(obj, k)) fail(where + ' is missing ' + k);
}

function field(buf) {
  if (buf.length > 0xffff) throw new Error('a signed field is too long');
  const len = Buffer.alloc(2);
  len.writeUInt16BE(buf.length);
  return Buffer.concat([len, buf]);
}

function payload(statement) {
  return Buffer.concat([
    MAGIC,
    Buffer.from([VERSION]),
    field(Buffer.from(statement.type, 'ascii')),
    field(Buffer.from(DIGEST, 'ascii')),
    field(Buffer.from(statement.digest, 'hex')),
    field(Buffer.from(statement.keyId, 'hex')),
    field(Buffer.from(statement.signedAt, 'ascii')),
    field(Buffer.from(statement.signer, 'utf8')),
    field(Buffer.from(statement.note, 'utf8')),
  ]);
}

function parse(envelope) {
  exactKeys(envelope, ['format', 'type', 'algorithm', 'key', 'subject', 'signedAt', 'signer', 'note', 'signature'], ['anchor'], 'the envelope');
  if (envelope.format !== FORMAT) fail('format must be ' + FORMAT);
  if (!TYPES.includes(envelope.type)) fail('type must be one of ' + TYPES.join(', '));
  if (envelope.algorithm !== ALGORITHM) fail('algorithm must be ' + ALGORITHM);
  exactKeys(envelope.key, ['id', 'publicKey'], [], 'key');
  if (typeof envelope.key.id !== 'string' || !HEX32.test(envelope.key.id)) fail('key.id must be 64 lowercase hex characters');
  const publicKey = decodeBase64(envelope.key.publicKey, PUBLIC_KEY_BYTES, 'key.publicKey');
  exactKeys(envelope.subject, ['alg', 'digest'], [], 'subject');
  if (envelope.subject.alg !== DIGEST) fail('subject.alg must be ' + DIGEST);
  if (typeof envelope.subject.digest !== 'string' || !HEX32.test(envelope.subject.digest)) fail('subject.digest must be 64 lowercase hex characters');
  const timeIssue = timeProblem(envelope.signedAt);
  if (timeIssue) fail(timeIssue);
  checkText(envelope.signer, SIGNER_MAX, 'signer');
  checkText(envelope.note, NOTE_MAX, 'note');
  const signature = decodeBase64(envelope.signature, SIGNATURE_BYTES, 'signature');
  const statement = {
    type: envelope.type,
    digest: envelope.subject.digest,
    keyId: envelope.key.id,
    signedAt: envelope.signedAt,
    signer: envelope.signer,
    note: envelope.note,
  };
  const anchor = Object.prototype.hasOwnProperty.call(envelope, 'anchor') ? envelope.anchor : undefined;
  return { statement, publicKey, signature, anchor };
}

function anchorDigest(statement, signature) {
  return sha3(ANCHOR_DOMAIN, Buffer.from([0]), payload(statement), signature);
}

module.exports = {
  timeProblem,
  FORMAT,
  ALGORITHM,
  DIGEST,
  CONTEXT,
  TYPES,
  PUBLIC_KEY_BYTES,
  SIGNATURE_BYTES,
  SIGNER_MAX,
  NOTE_MAX,
  sha3,
  keyIdOf,
  checkText,
  requireText,
  requireTime,
  reject,
  payload,
  parse,
  anchorDigest,
};
