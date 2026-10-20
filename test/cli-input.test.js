'use strict';

const fs = require('fs');
const path = require('path');
const test = require('node:test');
const assert = require('node:assert');
const { runCli, tempDir, SAYS_VALID } = require('./fuzz');
const { hostileCampaign, summary } = require('./hostile');
const { honest, ROOT } = require('./signed');

const qstamp = require('@quantovainc/qstamp');

const BIN = path.join(ROOT, 'bin', 'qsign.js');
const ENVELOPE_MAX = 64 * 1024;

test('hostile envelope and key publication files make the command line exit non zero quickly and never print VALID', async (t) => {
  const w = await honest();
  const dir = tempDir('qsign-ok');
  try {
    const env = path.join(dir, 'honest.json');
    const doc = path.join(dir, 'doc.bin');
    const publication = path.join(dir, 'publication.json');
    const pending = path.join(dir, 'pending.json');
    fs.writeFileSync(env, JSON.stringify(w.envelopes.document, null, 2) + '\n');
    fs.writeFileSync(doc, w.doc);
    fs.writeFileSync(publication, JSON.stringify(w.envelopes['key-publish']));
    fs.writeFileSync(pending, '{}');
    const tail = ['--file', doc, '--key-id', w.keyId, '--no-revocations', '--allow-unanchored'];
    const control = await runCli(BIN, ['verify', env].concat(tail));
    assert.strictEqual(control.code, 0, control.out + control.err);
    assert.ok(SAYS_VALID.test(control.out), control.out);
    const bound = await runCli(BIN, ['verify', env].concat(tail, ['--key-publication', publication]));
    assert.strictEqual(bound.code, 0, bound.out + bound.err);
    assert.match(bound.out, /matches the name published with this key/);
    const envelopes = await hostileCampaign({
      bin: BIN,
      tag: 'qsign-env',
      cap: ENVELOPE_MAX,
      validText: JSON.stringify(w.envelopes.document),
      commands: [
        (file) => ['verify', file].concat(tail),
        (file) => ['verify', file].concat(tail, ['--json']),
        (file) => ['verify', file, '--type', 'key-revoke', '--key-id', w.keyId, '--no-revocations', '--allow-unanchored'],
        (file) => ['complete', file, '--pending', pending],
      ],
    });
    t.diagnostic('envelope ' + summary(envelopes.results, envelopes.unchanged));
    const publications = await hostileCampaign({
      bin: BIN,
      tag: 'qsign-pub',
      cap: ENVELOPE_MAX,
      validText: JSON.stringify(w.envelopes['key-publish']),
      commands: [
        (file) => ['verify', env].concat(tail, ['--key-publication', file]),
        (file) => ['verify', file, '--type', 'key-publish', '--key-id', w.keyId, '--no-revocations', '--allow-unanchored'],
      ],
    });
    t.diagnostic('key publication ' + summary(publications.results, publications.unchanged));
    const pendings = await hostileCampaign({
      bin: BIN,
      tag: 'qsign-pending',
      cap: ENVELOPE_MAX,
      validText: JSON.stringify({ format: qstamp.PENDING_FORMAT, kind: String(qstamp.KINDS.document), records: [{ alg: 'sha3-256', digest: w.qsign.anchorDigest(w.envelopes.document) }] }),
      commands: [(file) => ['complete', env, '--pending', file]],
    });
    t.diagnostic('pending stamp ' + summary(pendings.results, pendings.unchanged));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
