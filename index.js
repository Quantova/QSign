// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const B = require('./lib/qsign');
const { verify } = require('./lib/verify');
const F = require('./lib/format');

module.exports = {
  generateKey: B.generateKey,
  publicKey: B.publicKey,
  keyId: B.keyId,
  describeKey: B.describeKey,
  subjectRef: B.subjectRef,
  release: B.release,
  artifact: B.artifact,
  attest: B.attest,
  approve: B.approve,
  revoke: B.revoke,
  anchor: B.anchor,
  complete: B.complete,
  verify,
  anchorDigest: (envelope) => F.anchorDigest(F.parse(envelope)).toString('hex'),
  recordRef: (envelope) => F.refOf(F.parse(envelope)),
  FORMAT: F.FORMAT,
  ALGORITHM: F.ALGORITHM,
  KIND: F.KIND,
  TYPES: F.TYPES,
  DIGESTS: F.DIGESTS,
  PREDICATES: F.PREDICATES,
  OUTCOMES: F.OUTCOMES,
  PUBLIC_KEY_BYTES: F.PUBLIC_KEY_BYTES,
  SIGNATURE_BYTES: F.SIGNATURE_BYTES,
};
