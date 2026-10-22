#!/usr/bin/env node
// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const qsign = require('..');
const qstamp = require('@quantovainc/qstamp');

const ENVELOPE_MAX = 64 * 1024;
const RECEIPT_EXT = '.qsig.json';

const HELP = `qsign, post quantum document signatures with Quantova time proofs

  qsign keygen <keyfile>
  qsign key <keyfile>
  qsign sign <file> --key <keyfile> [--signer TEXT] [--note TEXT] [--out FILE] [--force]
  qsign statement publish|revoke --key <keyfile> [--signer TEXT] [--note TEXT] --out FILE [--force]
  qsign anchor <envelope>... --network NAME --seed-file <file> [--index N] [--rpc URL]... [--trust-single-endpoint] [--allow-endpoint HOST]... [--allow-loopback] [--max-fee N]
  qsign complete <envelope>... --pending FILE [--tx ID] [--rpc URL]... [--trust-single-endpoint] [--allow-endpoint HOST]...
                [--allow-loopback]
  qsign verify <envelope> --network NAME [--file FILE | --digest HEX] [--type document|key-publish|key-revoke] (--key-id HEX | --public-key FILE)
               (--revocation FILE... | --no-revocations) [--key-publication FILE] [--allow-unanchored]
               [--max-anchor-delay SECONDS] [--at TIME] [--expect-sender ADDRESS]... [--rpc URL]... [--trust-custom-endpoints]
               [--trust-single-endpoint] [--allow-endpoint HOST]... [--allow-loopback] [--json]

A document signature is VALID only when the document is given with --file or --digest. Without it the
result is UNVERIFIED. The signer name is text chosen by the holder of the key and is not a verified
identity. --key-publication checks it against the name the key published. An anchor counts only when
it is proven by a finality certificate or by official endpoints of two different operators, any other
anchor is UNPROVEN and never VALID. Endpoints given with --rpc are consulted by verify only with
--trust-custom-endpoints, loopback endpoints only with --allow-loopback and private network endpoints
only when named with --allow-endpoint. --expect-sender names the account that must have signed the anchor.
--network names the network the envelopes are anchored on, testnet for the public network, and verify also
takes custom for a chain reached only through endpoints given with --rpc and --trust-custom-endpoints. An
anchor recorded on another network fails.

Exit codes are 0 for valid, 1 for invalid or an error, 2 for indeterminate or unproven, 3 for unverified
because no document was given, and 64 for usage errors.`;

function usageError(message) {
  const e = new Error(message);
  e.usage = true;
  return e;
}

function networkFlag(flags, verifying) {
  const names = Object.keys(qstamp.NETWORKS).concat(verifying ? ['custom'] : []);
  if (flags.network === undefined) throw usageError('--network is required');
  if (!names.includes(flags.network)) throw usageError('--network is one of ' + names.join(', ') + ', the network the envelopes are anchored on');
  return flags.network;
}

function endpointOptions(flags) {
  const out = {};
  if (flags.rpc) out.clients = flags.rpc;
  if (flags['allow-endpoint']) out.endpointAllowList = flags['allow-endpoint'];
  if (flags['trust-single-endpoint']) out.trustSingleEndpoint = true;
  if (flags['trust-custom-endpoints']) out.trustCustomEndpoints = true;
  if (flags['allow-loopback']) out.allowLoopback = true;
  return out;
}

const SPEC = {
  keygen: { flags: ['force'], values: [] },
  key: { flags: [], values: [] },
  sign: { flags: ['force'], values: ['key', 'signer', 'note', 'out'] },
  statement: { flags: ['force'], values: ['key', 'signer', 'note', 'out'] },
  anchor: { flags: ['trust-single-endpoint', 'allow-loopback'], values: ['seed-file', 'index', 'max-fee', 'network'], multi: ['rpc', 'allow-endpoint'] },
  complete: { flags: ['trust-single-endpoint', 'allow-loopback'], values: ['pending', 'tx'], multi: ['rpc', 'allow-endpoint'] },
  verify: { flags: ['allow-unanchored', 'no-revocations', 'json', 'trust-single-endpoint', 'trust-custom-endpoints', 'allow-loopback'], values: ['file', 'digest', 'type', 'key-id', 'public-key', 'key-publication', 'max-anchor-delay', 'at', 'network'], multi: ['revocation', 'rpc', 'allow-endpoint', 'expect-sender'] },
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
      void e;
    }
  } finally {
    fs.rmSync(tmp, { force: true });
    pendingTemp.delete(tmp);
  }
}

function strictJson(text) {
  const value = JSON.parse(text);
  const stack = [];
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    const top = stack[stack.length - 1];
    if (ch === '"') {
      let j = i + 1;
      while (text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      if (top && top.keys && top.expectKey) {
        const key = JSON.parse(text.slice(i, j + 1));
        if (top.keys.has(key)) throw new Error('the JSON repeats the key ' + JSON.stringify(key));
        top.keys.add(key);
        top.expectKey = false;
      }
      i = j;
    } else if (ch === '{') {
      stack.push({ keys: new Set(), expectKey: true });
    } else if (ch === '[') {
      stack.push({ keys: null });
    } else if (ch === '}' || ch === ']') {
      stack.pop();
    } else if (ch === ',' && top && top.keys) {
      top.expectKey = true;
    }
  }
  return value;
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
    return strictJson(buf.subarray(0, n).toString('utf8'));
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

function pendingPath(file) {
  return file + '.pending.json';
}

function saveAnchored(files, anchored) {
  anchored.forEach((env, i) => {
    atomicWrite(files[i], JSON.stringify(env, null, 2) + '\n', true);
    console.log('anchored ' + safe(files[i]) + ' in transaction ' + env.anchor.anchor.tx);
  });
}

async function cmdAnchor(positional, flags) {
  if (positional.length === 0) throw usageError('anchor takes one or more envelopes');
  if (new Set(positional.map((f) => path.resolve(f))).size !== positional.length) throw usageError('each envelope may be given once');
  for (const f of positional) {
    if (statOf(pendingPath(f))) throw usageError('an unfinished anchor exists in ' + safe(pendingPath(f)) + ', finish it with complete first');
  }
  const pendingFile = pendingPath(positional[0]);
  const envs = positional.map((f) => readJson(f, 'envelope', true));
  let index = 0;
  if (flags.index !== undefined) {
    if (!/^\d{1,9}$/.test(flags.index)) throw usageError('--index is a whole number');
    index = Number(flags.index);
  }
  const network = networkFlag(flags, false);
  const seed = readSeed(flags['seed-file'] || process.env.QSTAMP_SEED_FILE, '--seed-file of a funded Quantova account');
  let saved = false;
  const keep = (pending) => {
    const text = asciiJson(pending) + '\n';
    for (const f of positional) atomicWrite(pendingPath(f), text, saved);
    saved = true;
  };
  let anchored;
  try {
    anchored = await qsign.anchor(envs, { seed, index, network, ...endpointOptions(flags), maxFee: flags['max-fee'], onPending: keep });
  } catch (e) {
    if (e && e.pending && typeof e.pending === 'object') {
      try {
        keep(e.pending);
        e.message += ', the pending stamp was saved in ' + safe(pendingFile) + ', finish it with qsign complete ' + positional.map(safe).join(' ') + ' --pending ' + safe(pendingFile);
      } catch (e2) {
        e.message += ', the pending stamp follows on standard output, keep it to finish the anchor';
        process.stdout.write(asciiJson(e.pending) + '\n');
      }
    }
    throw e;
  } finally {
    seed.fill(0);
  }
  saveAnchored(positional, anchored);
  if (saved) for (const f of positional) fs.rmSync(pendingPath(f), { force: true });
  return 0;
}

async function cmdComplete(positional, flags) {
  if (positional.length === 0) throw usageError('complete takes the envelopes given to anchor, in the same order');
  if (!flags.pending) throw usageError('--pending is required');
  const pending = readJson(flags.pending, 'pending stamp');
  if (flags.tx !== undefined) {
    if (!/^QTX1[0-9A-Z]{20,120}$/.test(flags.tx)) throw usageError('--tx is the QTX1 identifier of the stamp transaction');
    if (pending && typeof pending === 'object' && typeof pending.tx === 'string' && pending.tx !== flags.tx) throw usageError('the pending stamp already names another transaction');
    if (pending && typeof pending === 'object') pending.tx = flags.tx;
  }
  const envs = positional.map((f) => readJson(f, 'envelope', true));
  const anchored = await qsign.complete(envs, pending, endpointOptions(flags));
  saveAnchored(positional, anchored);
  fs.rmSync(flags.pending, { force: true });
  for (const f of positional) fs.rmSync(pendingPath(f), { force: true });
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
  if (flags['key-id'] === undefined && flags['public-key'] === undefined) throw usageError('give the expected signer with --key-id or --public-key');
  if (flags['no-revocations'] && flags.revocation) throw usageError('give --revocation files or --no-revocations, not both');
  if (!flags['no-revocations'] && !flags.revocation) throw usageError('give the revocations held with --revocation, or --no-revocations when none is held');
  const opts = { network: networkFlag(flags, true), requireAnchor: !flags['allow-unanchored'] };
  if (flags.file !== undefined) opts.file = flags.file;
  if (flags.digest !== undefined) opts.digest = flags.digest;
  if (flags.type !== undefined) opts.expectType = flags.type;
  if (flags['key-id'] !== undefined) opts.keyId = flags['key-id'];
  if (flags['public-key'] !== undefined) {
    const desc = readJson(flags['public-key'], 'public key');
    if (!desc || desc.format !== 'qsign-key/1' || typeof desc.publicKey !== 'string') throw usageError('the public key file is not a qsign-key/1 description');
    opts.publicKey = desc.publicKey;
  }
  opts.revocations = flags.revocation ? flags.revocation.map((f) => readJson(f, 'revocation')) : [];
  if (flags['key-publication'] !== undefined) opts.keyPublication = readJson(flags['key-publication'], 'key publication');
  if (flags['max-anchor-delay'] !== undefined) {
    if (!/^[1-9][0-9]{0,9}$/.test(flags['max-anchor-delay'])) throw usageError('--max-anchor-delay is a whole number of seconds');
    opts.maxAnchorDelay = Number(flags['max-anchor-delay']);
  }
  if (flags.at !== undefined) {
    opts.at = flags.at;
  }
  Object.assign(opts, endpointOptions(flags));
  if (flags['expect-sender']) opts.expectedSender = flags['expect-sender'];
  const res = await qsign.verify(env, opts);
  if (flags.json) {
    process.stdout.write(asciiJson(res) + '\n');
  } else {
    if (res.type) console.log('type  ' + res.type);
    for (const c of res.checks) console.log((c.ok ? 'ok    ' : c.transport ? 'retry ' : c.indeterminate || c.unproven || c.unchecked ? 'open  ' : 'FAIL  ') + safe(c.name) + '  ' + safe(c.detail));
    if (res.signer) console.log('signer  ' + safe(res.signer) + (res.signerBound ? ', matches the name published with this key' : ', as stated by the holder of the key, not a verified identity'));
    if ((res.endpoints || []).length) {
      console.log('endpoints  ' + res.endpoints.map(safe).join(', '));
      if (res.officialEndpoints === false) console.log('notice  endpoints other than the official ones of this network were consulted, an anchor confirmed only by them is not proven');
    }
    console.log(res.status.toUpperCase());
  }
  if (res.status === 'valid') return 0;
  if (res.status === 'unverified') return 3;
  return res.status === 'indeterminate' || res.status === 'unproven' ? 2 : 1;
}

async function main() {
  const [command, ...rest] = process.argv.slice(2);
  if (!command || command === 'help' || command === '--help' || command === '-h') {
    console.log(HELP);
    return command ? 0 : 64;
  }
  if (!Object.hasOwn(SPEC, command)) throw usageError('unknown command ' + safe(command).slice(0, 40));
  const { positional, flags } = parse(command, rest);
  const run = { keygen: cmdKeygen, key: cmdKey, sign: cmdSign, statement: cmdStatement, anchor: cmdAnchor, complete: cmdComplete, verify: cmdVerify }[command];
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
