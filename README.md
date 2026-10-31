# QSign

QSign is a live production post quantum signing tool for software release and artifact provenance on the Quantova network. It proves the release, artifact, attestation, approval and revocation of a software release, and it lets any third party confirm that history without trusting the party that created it.

QSign proves records without disclosing them. Build details, source paths and internal notes stay private on the systems of the party that holds them. Only a salted cryptographic commitment is written to the chain, and no private detail is ever published. An authority is named only by a chain address.

## What it records

Each record is a signed envelope of one of five types.

1. release, an authority states the product, version and source revision of a software release.
2. artifact, the authority records a built artifact of the release with its digest and platform.
3. attest, the authority attaches a predicate such as an SBOM or a scan with its outcome.
4. approve, the authority approves the release for a named stage.
5. revoke, the authority revokes the release and states why.

Every record is signed with ML-DSA-65 under FIPS 204 by the authority whose role it names, and each later record links to the one before it so the whole life of a release forms a chain.

## Proving the time

A record on its own carries only the claim of its signer. Anchoring a record on the Quantova network through Qstamp adds a post quantum evidence anchor that fixes the latest moment the record existed, provable against the record and the signer by anyone, without claiming a regulated timestamp status that Quantova Inc does not hold.

## Install

```
npm install @quantovainc/qsign
```

## Use

```js
const qsign = require('@quantovainc/qsign');

const authority = qsign.generateKey();
const release = qsign.release({
  key: authority,
  product: 'quantova-core',
  version: '1.2.3',
  sourceRef: 'git 9f1a2b',
  authorityLabel: 'Release Engineering',
});

const artifact = qsign.artifact({
  key: authority,
  release,
  artifactId: 'linux-x86-64',
  digestAlg: 'sha-256',
  digest: 'a'.repeat(64),
  platform: 'linux/amd64',
});

const anchored = await qsign.anchor(artifact, { seed, index: 0, network: 'testnet' });
const result = await qsign.verify(anchored[0], { type: 'artifact', network: 'testnet' });
```

## What a record does not establish

1. It does not show that the stated facts are true. It shows only that the signer stated them and that the statement existed unchanged at a point in time.
2. It does not identify a natural person. The authority is a chain address, and linking an address to a person is a separate attestation held off the chain.
3. The labels are text written by the signer, they are not a verified identity.

## License

Apache-2.0 OR MIT
