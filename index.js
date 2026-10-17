// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const { generateKey, publicKey, keyId, describeKey, sign, keyStatement, anchor, complete } = require('./lib/sign');
const { verify } = require('./lib/verify');
const F = require('./lib/format');

module.exports = {
  generateKey,
  publicKey,
  keyId,
  describeKey,
  sign,
  keyStatement,
  anchor,
  complete,
  verify,
  parseEnvelope: (envelope) => F.parse(envelope).statement,
  anchorDigest: (envelope) => {
    const p = F.parse(envelope);
    return F.anchorDigest(p.statement, p.signature).toString('hex');
  },
  FORMAT: F.FORMAT,
  ALGORITHM: F.ALGORITHM,
  CONTEXT: F.CONTEXT.toString('ascii'),
  TYPES: F.TYPES,
};
