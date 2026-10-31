// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const Q = require('..');

function freshKey() {
  return Q.generateKey();
}

function releaseOf(key) {
  return Q.release({ key, product: 'quantova-core', version: '1.2.3', sourceRef: 'git 9f1a2b', authorityLabel: 'Release Engineering' });
}

function artifactOf(key, release) {
  return Q.artifact({ key, release, artifactId: 'linux-x86-64', digestAlg: 'sha-256', digest: 'a'.repeat(64), platform: 'linux/amd64' });
}

test('a signed release is a well formed signed record of the authority', () => {
  const authority = freshKey();
  const env = releaseOf(authority);
  assert.strictEqual(env.format, 'qsign/1');
  assert.strictEqual(env.type, 'release');
  assert.strictEqual(env.algorithm, 'ML-DSA-65');
  assert.strictEqual(env.signer.id, Q.keyId(authority));
  assert.strictEqual(env.statement.authorityKeyId, Q.keyId(authority));
  assert.match(env.statement.releaseId, /^[0-9a-f]{32}$/);
  assert.strictEqual(Buffer.from(env.signer.publicKey, 'base64').length, Q.PUBLIC_KEY_BYTES);
  assert.strictEqual(Buffer.from(env.signature, 'base64').length, Q.SIGNATURE_BYTES);
});

test('the artifact, attest, approve and revoke records chain to the same release', () => {
  const authority = freshKey();
  const release = releaseOf(authority);
  const artifact = artifactOf(authority, release);
  const attest = Q.attest({ key: authority, record: artifact, predicate: 'sbom', outcome: 'pass' });
  const approve = Q.approve({ key: authority, record: attest, stage: 'production' });
  const revoke = Q.revoke({ key: authority, record: approve, reason: 'signing key compromise suspected' });
  assert.strictEqual(artifact.statement.releaseId, release.statement.releaseId);
  assert.strictEqual(artifact.statement.releaseRef, Q.recordRef(release));
  assert.strictEqual(attest.statement.priorRef, Q.recordRef(artifact));
  assert.strictEqual(approve.statement.priorRef, Q.recordRef(attest));
  assert.strictEqual(revoke.statement.priorRef, Q.recordRef(approve));
});

test('invalid inputs are refused before anything is signed', () => {
  const key = freshKey();
  const release = releaseOf(key);
  const base = { key, release, artifactId: 'a1', digestAlg: 'sha-256', digest: 'a'.repeat(64), platform: 'linux/amd64' };
  assert.throws(() => Q.artifact(Object.assign({}, base, { digestAlg: 'widget' })), /digestAlg must be one of/);
  assert.throws(() => Q.artifact(Object.assign({}, base, { artifactId: '' })), /artifactId is 1 to/);
  assert.throws(() => Q.artifact(Object.assign({}, base, { digest: 'zz' })), /digest must be 64, 96 or 128/);
  assert.throws(() => Q.artifact(Object.assign({}, base, { unknownField: 1 })), /is not an option of artifact/);
  assert.throws(() => Q.attest({ key, record: release, predicate: 'maybe', outcome: 'pass' }), /predicate must be one of/);
  assert.throws(() => Q.attest({ key, record: release, predicate: 'sbom', outcome: 'ignored' }), /outcome must be one of/);
});

test('a signing key must be a well formed 32 byte seed', () => {
  assert.throws(() => Q.release({ key: new Uint8Array(16), product: 'p', version: '1', sourceRef: 's' }), /32 byte Uint8Array seed/);
  assert.throws(() => Q.release({ key: new Uint8Array(32), product: 'p', version: '1', sourceRef: 's' }), /too few different byte values/);
});

test('a well formed record verifies and a type mismatch is invalid', async () => {
  const authority = freshKey();
  const release = releaseOf(authority);
  const ok = await Q.verify(release, { type: 'release', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(ok.status, 'valid');
  assert.strictEqual(ok.type, 'release');
  assert.strictEqual(ok.releaseId, release.statement.releaseId);
  const wrongType = await Q.verify(release, { type: 'artifact', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(wrongType.status, 'invalid');
  const wrongSigner = await Q.verify(release, { type: 'release', network: 'testnet', requireAnchor: false, strict: false, signerKeyId: Q.keyId(freshKey()) });
  assert.strictEqual(wrongSigner.status, 'invalid');
});

test('a tampered statement no longer verifies', async () => {
  const authority = freshKey();
  const release = releaseOf(authority);
  const artifact = artifactOf(authority, release);
  const forged = JSON.parse(JSON.stringify(artifact));
  forged.statement.digest = 'b'.repeat(64);
  const r = await Q.verify(forged, { type: 'artifact', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(r.status, 'invalid');
  assert.ok(r.checks.some((c) => c.name === 'signature' && !c.ok));
});

test('the prior link binds an artifact to the release it refers to', async () => {
  const authority = freshKey();
  const release = releaseOf(authority);
  const artifact = artifactOf(authority, release);
  const good = await Q.verify(artifact, { type: 'artifact', network: 'testnet', requireAnchor: false, strict: false, prior: release });
  assert.ok(good.checks.some((c) => c.name === 'prior' && c.ok));
  const otherRelease = releaseOf(authority);
  const bad = await Q.verify(artifact, { type: 'artifact', network: 'testnet', requireAnchor: false, strict: false, prior: otherRelease });
  assert.strictEqual(bad.status, 'invalid');
  assert.ok(bad.checks.some((c) => c.name === 'prior' && !c.ok));
});

test('subjectRef is deterministic for the same secret and reference and differs otherwise', () => {
  const secret = new Uint8Array(32);
  globalThis.crypto.getRandomValues(secret);
  const a = Q.subjectRef(secret, 'release quantova-core 1.2.3');
  const b = Q.subjectRef(secret, 'release quantova-core 1.2.3');
  const c = Q.subjectRef(secret, 'release quantova-core 1.2.4');
  assert.strictEqual(a, b);
  assert.notStrictEqual(a, c);
  assert.match(a, /^[0-9a-f]{64}$/);
});

test('the kind and constants are the ones pinned for the qsign line', () => {
  assert.strictEqual(Q.KIND, 1602);
  assert.strictEqual(Q.FORMAT, 'qsign/1');
  assert.deepStrictEqual([...Q.TYPES], ['release', 'artifact', 'attest', 'approve', 'revoke']);
  assert.deepStrictEqual([...Q.DIGESTS], ['sha-256', 'sha-384', 'sha-512', 'sha3-256']);
  assert.deepStrictEqual([...Q.PREDICATES], ['slsa-provenance', 'sbom', 'vulnerability-scan', 'test-report', 'policy']);
  assert.deepStrictEqual([...Q.OUTCOMES], ['pass', 'fail', 'waived']);
});
