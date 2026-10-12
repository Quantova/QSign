#!/usr/bin/env node
// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const qsign = require('..');

const ENVELOPE_MAX = 64 * 1024;
const RECEIPT_EXT = '.qsig.json';

const HELP = `qsign, post quantum document signatures with Quantova time proofs

  qsign keygen <keyfile>
  qsign key <keyfile>
  qsign sign <file> --key <keyfile> [--signer TEXT] [--note TEXT] [--out FILE] [--force]
  qsign statement publish|revoke --key <keyfile> [--signer TEXT] [--note TEXT] --out FILE [--force]
  qsign anchor <envelope>... --seed-file <file> [--index N] [--rpc URL] [--max-fee N]
  qsign verify <envelope> [--file FILE | --digest HEX] [--key-id HEX | --public-key FILE]
               [--revocation FILE]... [--require-anchor] [--rpc URL] [--json]

Exit codes are 0 for valid, 1 for invalid or an error, 2 for indeterminate and 64 for usage errors.`;

function usageError(message) {
  const e = new Error(message);
  e.usage = true;
  return e;
}

const SPEC = {
  keygen: { flags: ['force'], values: [] },
  key: { flags: [], values: [] },
  sign: { flags: ['force'], values: ['key', 'signer', 'note', 'out'] },
  statement: { flags: ['force'], values: ['key', 'signer', 'note', 'out'] },
  anchor: { flags: [], values: ['seed-file', 'index', 'rpc', 'max-fee'] },
  verify: { flags: ['require-anchor', 'json'], values: ['file', 'digest', 'key-id', 'public-key', 'rpc'], multi: ['revocation'] },
};

function parse(command, argv) {
  const spec = SPEC[command];
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (!a.startsWith('--')) {
      positional.push(a);
      continue;
    }
    const name = a.slice(2);
    if (spec.flags.includes(name)) {
      flags[name] = true;
    } else if (spec.values.includes(name) || (spec.multi || []).includes(name)) {
      const v = argv[i + 1];
      if (v === undefined || v.startsWith('--')) throw usageError('--' + name + ' needs a value');
      if (v.length === 0) throw usageError('--' + name + ' was given an empty value');
      i += 1;
      if ((spec.multi || []).includes(name)) (flags[name] = flags[name] || []).push(v);
      else if (flags[name] !== undefined) throw usageError('--' + name + ' was given twice');
      else flags[name] = v;
    } else {
      throw usageError('unknown option ' + a.slice(0, 40));
    }
  }
  return { positional, flags };
}

function hexNibble(code) {
  if (code >= 48 && code <= 57) return code - 48;
  if (code >= 97 && code <= 102) return code - 87;
  if (code >= 65 && code <= 70) return code - 55;
  return -1;
}

function readSeed(file, what) {
  if (!file) throw usageError(what + ' is required');
  const fd = openRegular(file, 'key file');
  const raw = Buffer.allocUnsafeSlow(131);
  const seed = new Uint8Array(32);
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) throw usageError('the key file must be a regular file');
    if (process.platform !== 'win32') {
      if ((st.mode & 0o077) !== 0) throw usageError('the key file ' + file + ' is readable by other users, restrict it with chmod 600');
      if (typeof process.getuid === 'function' && st.uid !== process.getuid()) throw usageError('the key file ' + file + ' is not owned by the current user');
    }
    const n = fs.readSync(fd, raw, 0, raw.length, 0);
    if (n > 66) throw usageError('the key file must hold only a 32 byte seed as 64 hex characters');
    let end = n;
    while (end > 0 && (raw[end - 1] === 10 || raw[end - 1] === 13 || raw[end - 1] === 32)) end -= 1;
    if (end !== 64) throw usageError('the key file must hold a 32 byte seed as 64 hex characters');
    for (let i = 0; i < 32; i += 1) {
      const hi = hexNibble(raw[2 * i]);
      const lo = hexNibble(raw[2 * i + 1]);
      if (hi < 0 || lo < 0) throw usageError('the key file must hold a 32 byte seed as 64 hex characters');
      seed[i] = (hi << 4) | lo;
    }
    return seed;
  } catch (e) {
    seed.fill(0);
    throw e;
  } finally {
    raw.fill(0);
    fs.closeSync(fd);
  }
}

function openRegular(file, what) {
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0);
  let fd;
  try {
    fd = fs.openSync(file, flags);
  } catch (e) {
    throw usageError(e.code === 'ELOOP' ? 'the ' + what + ' must not be a symbolic link' : 'the ' + what + ' ' + safe(file) + ' could not be opened');
  }
  if (!fs.fstatSync(fd).isFile()) {
    fs.closeSync(fd);
    throw usageError('the ' + what + ' must be a regular file');
  }
  return fd;
}

function statOf(file) {
  try {
    return fs.lstatSync(file);
  } catch (e) {
    if (e.code === 'ENOENT') return null;
    throw e;
  }
}

const pendingTemp = new Set();

function cleanupTemp() {
  for (const t of pendingTemp) {
    try {
      fs.rmSync(t, { force: true });
    } catch (e) {
      continue;
    }
  }
}

for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
  process.on(sig, () => {
    cleanupTemp();
    process.exit(130);
  });
}

function atomicWrite(dest, data, force) {
  const existing = statOf(dest);
  if (existing && existing.isSymbolicLink()) throw usageError('refusing to write through the symbolic link ' + safe(dest));
  if (existing && !existing.isFile()) throw usageError('something other than a file exists at ' + safe(dest));
  if (existing && !force) throw usageError('a file already exists at ' + safe(dest) + ', pass --force to replace it');
  const dir = path.dirname(dest);
  const tmp = path.join(dir, '.' + path.basename(dest) + '.' + crypto.randomBytes(6).toString('hex') + '.tmp');
  pendingTemp.add(tmp);
  try {
    const fd = fs.openSync(tmp, 'wx', 0o600);
    try {
      fs.fchmodSync(fd, 0o600);
      fs.writeSync(fd, data);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    if (force) {
      fs.renameSync(tmp, dest);
    } else {
      try {
        fs.linkSync(tmp, dest);
      } catch (e) {
        if (e.code === 'EEXIST') throw usageError('a file already exists at ' + safe(dest) + ', pass --force to replace it');
        throw e;
      }
      fs.rmSync(tmp, { force: true });
    }
    try {
      const dfd = fs.openSync(dir, 'r');
      try {
        fs.fsyncSync(dfd);
      } finally {
        fs.closeSync(dfd);
      }
    } catch (e) {
      if (e.code !== 'EISDIR' && e.code !== 'EPERM' && e.code !== 'EINVAL') throw e;
    }
  } finally {
    fs.rmSync(tmp, { force: true });
    pendingTemp.delete(tmp);
  }
}

function readJson(file, what, invalidExit) {
  const fd = openRegular(file, what);
  const buf = Buffer.alloc(ENVELOPE_MAX + 1);
  let n;
  try {
    n = fs.readSync(fd, buf, 0, buf.length, 0);
  } finally {
    fs.closeSync(fd);
  }
  const bad = (message) => {
    const e = new Error(message);
    if (invalidExit) e.invalid = true;
    else e.usage = true;
    return e;
  };
  if (n > ENVELOPE_MAX) throw bad('the ' + what + ' is larger than ' + ENVELOPE_MAX + ' bytes');
  try {
    return JSON.parse(buf.subarray(0, n).toString('utf8'));
  } catch (e) {
    throw bad('the ' + what + ' ' + safe(file) + ' is not valid JSON');
  }
}

function asciiJson(value) {
  return JSON.stringify(value, null, 2).replace(/[\u007f-\uffff]/g, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
}

function safe(value) {
  return String(value).replace(/[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff\ufff9-\ufffb]/gu, '?');
}

function withSeed(file, what, fn) {
  const seed = readSeed(file, what);
  try {
    return fn(seed);
  } finally {
    seed.fill(0);
  }
}

async function cmdKeygen(positional, flags) {
  if (positional.length !== 1) throw usageError('keygen takes one key file path');
  const seed = qsign.generateKey();
  const text = Buffer.alloc(65);
  try {
    const digits = '0123456789abcdef';
    for (let i = 0; i < 32; i += 1) {
      text[2 * i] = digits.charCodeAt(seed[i] >> 4);
      text[2 * i + 1] = digits.charCodeAt(seed[i] & 15);
    }
    text[64] = 10;
    atomicWrite(positional[0], text, flags.force);
    console.log('key id ' + qsign.keyId(seed));
  } finally {
    seed.fill(0);
    text.fill(0);
  }
  return 0;
}

async function cmdKey(positional) {
  if (positional.length !== 1) throw usageError('key takes one key file path');
  const desc = withSeed(positional[0], 'a key file', (seed) => qsign.describeKey(seed));
  process.stdout.write(asciiJson(desc) + '\n');
  return 0;
}

async function cmdSign(positional, flags) {
  if (positional.length !== 1) throw usageError('sign takes one document');
  const out = flags.out || positional[0] + RECEIPT_EXT;
  const seed = readSeed(flags.key, '--key');
  let env;
  try {
    env = await qsign.sign({ key: seed, file: positional[0], signer: flags.signer, note: flags.note });
  } finally {
    seed.fill(0);
  }
  atomicWrite(out, JSON.stringify(env, null, 2) + '\n', flags.force);
  console.log('signed ' + safe(positional[0]) + ' with key ' + env.key.id + ', envelope ' + safe(out));
  return 0;
}

async function cmdStatement(positional, flags) {
  if (positional.length !== 1 || !['publish', 'revoke'].includes(positional[0])) throw usageError('statement takes publish or revoke');
  if (!flags.out) throw usageError('--out is required');
  const env = withSeed(flags.key, '--key', (seed) => qsign.keyStatement({ key: seed, action: positional[0], signer: flags.signer, note: flags.note }));
  atomicWrite(flags.out, JSON.stringify(env, null, 2) + '\n', flags.force);
  console.log(positional[0] + ' statement for key ' + env.key.id + ' written to ' + safe(flags.out));
  return 0;
}

async function cmdAnchor(positional, flags) {
  if (positional.length === 0) throw usageError('anchor takes one or more envelopes');
  const envs = positional.map((f) => readJson(f, 'envelope', true));
  let index = 0;
  if (flags.index !== undefined) {
    if (!/^\d{1,9}$/.test(flags.index)) throw usageError('--index is a whole number');
    index = Number(flags.index);
  }
  const seed = readSeed(flags['seed-file'] || process.env.QSTAMP_SEED_FILE, '--seed-file of a funded Quantova account');
  let anchored;
  try {
    anchored = await qsign.anchor(envs, { seed, index, network: 'testnet', rpc: flags.rpc, maxFee: flags['max-fee'] });
  } finally {
    seed.fill(0);
  }
  anchored.forEach((env, i) => {
    atomicWrite(positional[i], JSON.stringify(env, null, 2) + '\n', true);
    console.log('anchored ' + safe(positional[i]) + ' in transaction ' + env.anchor.anchor.tx);
  });
  return 0;
}

async function cmdVerify(positional, flags) {
  if (positional.length !== 1) throw usageError('verify takes one envelope');
  if (flags.file !== undefined && flags.digest !== undefined) throw usageError('give --file or --digest, not both');
  if (flags['key-id'] !== undefined && flags['public-key'] !== undefined) throw usageError('give --key-id or --public-key, not both');
  if (flags['key-id'] !== undefined && !/^[0-9a-f]{64}$/.test(flags['key-id'])) throw usageError('--key-id is 64 lowercase hex characters');
  if (flags.digest !== undefined && !/^[0-9a-fA-F]{64}$/.test(flags.digest)) throw usageError('--digest is 64 hex characters');
  if (flags.file !== undefined) fs.closeSync(openRegular(flags.file, 'document'));
  const env = readJson(positional[0], 'envelope', true);
  const opts = { requireAnchor: !!flags['require-anchor'] };
  if (flags.file !== undefined) opts.file = flags.file;
  if (flags.digest !== undefined) opts.digest = flags.digest;
  if (flags['key-id'] !== undefined) opts.keyId = flags['key-id'];
  if (flags['public-key'] !== undefined) {
    const desc = readJson(flags['public-key'], 'public key');
    if (!desc || desc.format !== 'qsign-key/1' || typeof desc.publicKey !== 'string') throw usageError('the public key file is not a qsign-key/1 description');
    opts.publicKey = desc.publicKey;
  }
  if (flags.revocation) opts.revocations = flags.revocation.map((f) => readJson(f, 'revocation'));
  if (flags.rpc) opts.rpc = flags.rpc;
  const res = await qsign.verify(env, opts);
  if (flags.json) {
    process.stdout.write(asciiJson(res) + '\n');
  } else {
    if (res.type) console.log('type  ' + res.type);
    for (const c of res.checks) console.log((c.ok ? 'ok    ' : c.transport ? 'retry ' : c.indeterminate ? 'open  ' : 'FAIL  ') + safe(c.name) + '  ' + safe(c.detail));
    console.log(res.status.toUpperCase());
  }
  return res.status === 'valid' ? 0 : res.status === 'indeterminate' ? 2 : 1;
}

async function main() {
  const [command, ...rest] = process.argv.slice(2);
  if (!command || command === 'help' || command === '--help' || command === '-h') {
    console.log(HELP);
    return command ? 0 : 64;
  }
  if (!Object.hasOwn(SPEC, command)) throw usageError('unknown command ' + safe(command).slice(0, 40));
  const { positional, flags } = parse(command, rest);
  const run = { keygen: cmdKeygen, key: cmdKey, sign: cmdSign, statement: cmdStatement, anchor: cmdAnchor, verify: cmdVerify }[command];
  return run(positional, flags);
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (e) => {
    console.error(safe((e && e.message) || e).slice(0, 400));
    process.exitCode = e && (e.usage || e.code === 'QSIGN_INVALID_INPUT') ? 64 : 1;
  },
);
