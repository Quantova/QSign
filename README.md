# QSign

QSign is a post quantum document signature SDK for the Quantova network. It signs any document with the Module Lattice Digital Signature Algorithm, parameter set 65, as standardised in FIPS 204, and it can bind each signature to a Qstamp time proof so that any third party can establish that the signature existed no later than a stated moment.

A QSign signature does not depend on elliptic curve or RSA cryptography at any point. The signature, the key fingerprint, the time proof and the chain that carries it are all built on primitives that no known quantum algorithm breaks.

## What QSign is

QSign is a software library and command line tool that gives any organisation post quantum digital signatures for its documents. A signature made with QSign proves three things to anyone who checks it. It proves who signed, because only the holder of the signing key can produce it. It proves what was signed, because any change to a single byte of the document breaks the signature. And when the signature is anchored, it proves when it was signed, because the Quantova network records independent evidence of the moment the signature existed.

QSign is designed to sit beside the systems an organisation already runs. It does not replace a document management system, an electronic signature platform or a records archive. It adds a signature layer that remains secure after the arrival of large scale quantum computers, and an evidence layer that a court, a regulator or an auditor can check without relying on the signer, on the platform that stored the document or on Quantova Inc.

QSign is standalone. It runs on the servers of the organisation, holds its keys locally and uses the Quantova network only as a neutral public ledger for time proofs.

## Why organisations need it

Nearly every digital signature in use today relies on RSA or elliptic curve cryptography. A sufficiently capable quantum computer will be able to forge those signatures, and from that point a forged contract and a genuine one cannot be told apart. Records that must be kept for five, ten or more years are signed today but must still be provable after that point.

Governments have set dates for the transition. United States Executive Order 14412 requires federal systems and their contractors to move to post quantum signatures by the end of 2031. The NSA CNSA 2.0 suite requires post quantum software and firmware signing by 2030. NIST proposes to retire classical signatures after 2030 and to disallow them after 2035. The European Union, the United Kingdom, Singapore, Hong Kong, Japan and South Korea have published comparable roadmaps for the financial sector and public bodies.

QSign meets that requirement for documents now, with a standardised algorithm, and adds independent proof of signing time so that every signature made before any future compromise can still be shown to be genuine.

## Who uses it

1. Banks and lenders signing loan agreements, credit decisions, mandates and board resolutions.
2. Payment firms and insurers signing policies, claims decisions, settlement instructions and customer correspondence.
3. Asset managers and broker dealers signing trade confirmations, client agreements and regulatory reports.
4. Government bodies and agencies signing permits, procurement awards, certificates and official decisions.
5. Law firms, notaries and auditors sealing executed copies, evidence bundles and audit reports.
6. Software and AI companies signing releases, model cards and outputs that their clients must later rely on.

## How an organisation integrates QSign

Integration follows the same sequence in every organisation, whatever its size.

1. Decide who signs. Each signing role, such as a treasury officer, a credit committee, a compliance function or an automated system, receives its own key. Keys are never shared between people or systems.

2. Create and protect the keys. Each key is created with the keygen command or the generateKey function and stored where the organisation stores its most sensitive secrets, such as a secrets manager, an encrypted vault or a hardware protected store. The key file is a 32 byte seed and must be readable only by the signing service or person.

3. Publish the keys. For every key the organisation signs and anchors a key publish statement, and gives the resulting key description to its counterparties, auditors and regulators. Anyone who verifies a signature then checks it against that published key.

4. Sign at the point of decision. The signing call is added to the workflow at the moment a document becomes final, for example when a loan is approved, a policy is issued or a filing is submitted. The application passes the document and the signing key to QSign and stores the returned envelope beside the document. The document itself never leaves the systems of the organisation.

5. Anchor on a schedule. A single service with a funded Quantova account anchors new envelopes in batches, for example every few minutes or once an hour. One transaction can anchor many signatures at negligible cost, and each envelope receives its own receipt.

6. Keep the envelope with the record. The envelope with its receipt is stored for the full retention period alongside the document, in the same archive and under the same retention rules.

7. Verify when evidence is needed. When a court, a regulator, an auditor or a counterparty asks for proof, the organisation hands over the document and its envelope. The recipient verifies them with the verify command, the library or the independent procedure below, without any access to the systems of the organisation.

8. Revoke keys when people leave or devices are retired. A key revoke statement is signed and anchored at once. Signatures anchored before the revocation remain valid, and any later use of the key is shown to be invalid.

## Integration patterns

1. Document management and archives. A hook in the archive signs each document when it is marked final and stores the envelope as an attachment.
2. Loan origination, policy administration and case management. The approval step calls QSign with the approver key and records the key identifier in the decision log.
3. Electronic signature platforms. A completed agreement from an existing platform is sealed with an organisation key, adding a post quantum signature and an independent time proof to the classical one.
4. Regulatory reporting. Each report file is signed before submission and the envelope is retained as evidence of what was filed and when.
5. Software and AI release pipelines. The build step signs each artefact and its manifest so that clients can verify exactly what was delivered.
6. Service integration. Any language that can call a Node service can use QSign through a small internal signing service that holds the keys and exposes sign and verify to other systems on the internal network.

## What is published and what stays private

The document never leaves the systems of its holder. QSign signs the SHA3 digest of the document, and the signature envelope holds that digest, never the document itself.

When a signature is anchored, only a 32 byte Qstamp commitment reaches the chain. That commitment is derived from a salted fingerprint of the signature and cannot be reversed into the signature, the document digest, the signer label or the note. The signature envelope and its receipt stay with the parties who hold them and are disclosed only when they choose, for example to a court, a regulator or an auditor.

## Cryptographic construction

1. Key. A signing key is a 32 byte seed held only by its owner. The ML-DSA-65 key pair is derived from the seed by the key generation procedure of FIPS 204. The public key is 1952 bytes.

2. Key identifier. The key identifier is the SHA3 hash with a 256 bit output of the ASCII label quantova/qsign/key/1, the byte 0x00 and the public key. It is written as 64 lowercase hexadecimal characters.

3. Subject. The subject of a document signature is the SHA3 digest with a 256 bit output of the document bytes, as specified in FIPS 202.

4. Statement. The signed message is a canonical binary statement. It begins with the ASCII bytes QSIG and the version byte 1, followed by seven fields in a fixed order. Each field is an unsigned 16 bit big endian length followed by its bytes. The fields are the statement type, the digest algorithm name sha3-256, the 32 byte subject digest, the 32 byte key identifier, the signing time as an ISO 8601 UTC string with milliseconds, the signer label in UTF-8 and the note in UTF-8. The length prefixes make every statement uniquely decodable, so no two distinct statements share an encoding.

5. Signature. The statement is signed with ML-DSA-65 in its hedged form, using 32 bytes of fresh randomness from the platform secure random source, under the FIPS 204 context string quantova/qsign/1. The context separates QSign signatures from every other use of the algorithm, including Quantova network transactions and contract orders, so a QSign signature can never be replayed as either. The signature is 3309 bytes and is checked against the public key before it is returned.

6. Envelope. The result is a JSON envelope in the format qsign/1. It holds the statement type, the algorithm name, the key identifier and public key, the subject digest, the signing time, the signer label, the note, the signature and, once anchored, a Qstamp receipt. Every field is validated strictly and any unknown field is refused.

7. Anchor. To anchor a signature, QSign computes the SHA3 hash of the ASCII label quantova/qsign/anchor/1, the byte 0x00, the encoded statement and the signature. That value is stamped as a Qstamp record of kind document, or of kind public record for key statements. Because the anchor value covers the signature itself, a receipt for one signature can never be attached to another.

## Key statements and revocation

A key holder can sign a key publish statement, which records that the key is in use, and a key revoke statement, which withdraws it. Both are QSign envelopes whose subject is the key identifier and both are anchored in the same way as document signatures.

A revocation takes effect from its anchor time. A document signature anchored before the revocation remains valid. A document signature anchored at or after the revocation, or within the same block, is invalid. When the chain of both anchors is the same, the order is decided by block height. A revocation that is not validly signed by the key it names is ignored, so no third party can withdraw a key or invalidate a genuine signature.

## What a valid result establishes

When verification succeeds, the following statements hold.

1. The envelope is well formed and every field satisfies the format.
2. The key identifier is the fingerprint of the public key in the envelope.
3. The signature is a valid ML-DSA-65 signature by that public key over the exact statement.
4. When the document is supplied, its SHA3 digest equals the signed subject.
5. The signature was made by the expected key, which the verifier must always supply, so a signature by any other key never verifies.
6. The envelope is anchored, unless the verifier explicitly allows an unanchored signature, and the anchor is a valid Qstamp receipt on the named chain, it covers this exact signature, and the claimed signing time is no later than five minutes after the anchor time.
7. None of the revocations supplied was anchored before this signature. The verifier must always supply the revocations it holds, an empty list when it holds none, and without a list the result is indeterminate.

## What a valid result does not establish

1. The identity of the person or organisation behind a key. A key identifier must be matched to its holder by the verifier, for example through a published key statement or an agreement between the parties.
2. The signing time when the envelope is not anchored. Without an anchor the time is only the claim of the signer.
3. That a key has not been revoked by a revocation the verifier does not hold.
4. Legal status as a qualified electronic signature in any jurisdiction, which requires a qualified trust service provider.

## Trust model of this release

This release anchors on the live Quantova network Q-test-net-1. The signing module is compiled from the Quantova Q-Crypto library, which follows FIPS 204 and FIPS 202 and has been tested against the NIST vectors and cross checked against an independent implementation. It has not been validated under FIPS 140-3. Anchor times are confirmed by the endpoints a verifier queries, so a time is only as reliable as those endpoints. Verification names the endpoints it consulted and says whether they are the official endpoints of the network, and a verifier who needs independence from any single operator should query several independent endpoints.

Secret material is handled with care. The seed is accepted only as a byte array that the caller can wipe. Inside the signing module every copy of the seed, the randomness and the expanded private key is overwritten with zeros after each call, and the working memory used during signing is cleared.

## Installation

```
npm install @quantovainc/qsign
```

QSign requires Node 20 or later.

## Command line use

Create a key. The key file holds the 32 byte seed as 64 hexadecimal characters and is written readable only by its owner.

```
qsign keygen alice.key
qsign key alice.key > alice.pub.json
```

Sign a document. The envelope is written beside the document with the suffix .qsig.json unless another path is given.

```
qsign sign contract.pdf --key alice.key --signer "Alice Holdings" --note "Executed copy"
```

Anchor one or more envelopes through a funded Quantova account.

```
qsign anchor contract.pdf.qsig.json --seed-file account.key --index 0
```

Verify an envelope against the document and the expected signer.

```
qsign verify contract.pdf.qsig.json --file contract.pdf --public-key alice.pub.json --no-revocations
```

Publish or revoke a key.

```
qsign statement publish --key alice.key --out alice.publish.json
qsign statement revoke --key alice.key --note "Device retired" --out alice.revoke.json
qsign verify contract.pdf.qsig.json --file contract.pdf --public-key alice.pub.json --revocation alice.revoke.json
```

The command exits with status 0 when the result is valid, 1 when it is invalid or the envelope cannot be read, 2 when it cannot be decided, for example because no endpoint could be reached or a revocation has no proven time, and 64 for usage errors. An unreachable endpoint never produces a valid result. Key files that are readable by other users, are symbolic links or are not regular files are refused. Output files are written privately and moved into place, and an existing file is replaced only with the force option.

## Programmatic use

```js
const qsign = require('@quantovainc/qsign');

const key = qsign.generateKey();
const envelope = await qsign.sign({ key, file: 'contract.pdf', signer: 'Alice Holdings' });
const publicKey = qsign.describeKey(key).publicKey;
key.fill(0);

const [anchored] = await qsign.anchor([envelope], { seed, index: 0 });

const result = await qsign.verify(anchored, { file: 'contract.pdf', publicKey, revocations: [] });
```

The result reports a status of valid, invalid or indeterminate, lists every check with its outcome and reason, and states whether the document was checked, whether the signer matched the expected key and whether revocations were considered. A key statement is never accepted as a document signature.

## Independent verification procedure

An auditor can verify an envelope without this SDK by following these steps.

1. Decode the public key and signature from base64 and confirm their lengths are 1952 and 3309 bytes.
2. Compute the SHA3 hash of the label quantova/qsign/key/1, the byte 0x00 and the public key, and compare it with the key identifier.
3. Encode the statement as described above and verify the signature over it with ML-DSA-65 under the context string quantova/qsign/1, following FIPS 204.
4. Compute the SHA3 digest of the document and compare it with the subject digest.
5. Compute the anchor value from the label quantova/qsign/anchor/1, the byte 0x00, the encoded statement and the signature, and verify the attached receipt for that value by the procedure published with Qstamp.
6. Confirm the signing time is no later than five minutes after the block time of the anchor.

## Network

The live Quantova network is named Q-test-net-1 with genesis hash ca91e093bb8de33e90db52d7c89876597d14760703793ea7211929e73e613062. Anchors are recorded by the official Qstamp contract on that network. The public endpoint is https://rpc-testnet.quantova.org.

## Licence

QSign is created and owned by Quantova Inc. It is licensed under the Apache License 2.0 or the MIT licence, at your option. The full texts are in the files LICENSE-APACHE and LICENSE-MIT, and the notice is in NOTICE.
