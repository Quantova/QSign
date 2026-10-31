// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

export type Digest = 'sha-256' | 'sha-384' | 'sha-512' | 'sha3-256';
export type Predicate = 'slsa-provenance' | 'sbom' | 'vulnerability-scan' | 'test-report' | 'policy';
export type Outcome = 'pass' | 'fail' | 'waived';
export type RecordType = 'release' | 'artifact' | 'attest' | 'approve' | 'revoke';

export interface KeyDescription {
  format: 'qsign-key/1';
  algorithm: 'ML-DSA-65';
  id: string;
  publicKey: string;
}

export type Party = string | Uint8Array | KeyDescription;

export interface Signer {
  id: string;
  publicKey: string;
}

export interface Envelope<T = Record<string, unknown>> {
  format: 'qsign/1';
  type: RecordType;
  algorithm: 'ML-DSA-65';
  signer: Signer;
  statement: T;
  signature: string;
  anchor?: unknown;
}

export interface ReleaseOptions {
  key: Uint8Array;
  product: string;
  version: string;
  sourceRef: string;
  authorityLabel?: string;
  releasedAt?: string;
  note?: string;
}

export interface ArtifactOptions {
  key: Uint8Array;
  release: Envelope;
  artifactId: string;
  digestAlg: Digest;
  digest: string;
  platform: string;
  authorityLabel?: string;
  builtAt?: string;
  note?: string;
}

export interface AttestOptions {
  key: Uint8Array;
  record: Envelope;
  predicate: Predicate;
  outcome: Outcome;
  authorityLabel?: string;
  attestedAt?: string;
  note?: string;
}

export interface ApproveOptions {
  key: Uint8Array;
  record: Envelope;
  stage: string;
  authorityLabel?: string;
  approvedAt?: string;
  note?: string;
}

export interface RevokeOptions {
  key: Uint8Array;
  record: Envelope;
  reason: string;
  authorityLabel?: string;
  revokedAt?: string;
  note?: string;
}

export interface AnchorOptions {
  seed?: Uint8Array;
  index?: number;
  network?: string;
  rpc?: string;
  clients?: unknown[];
  trustSingleEndpoint?: boolean;
  trustCustomEndpoints?: boolean;
  allowLoopback?: boolean;
  maxFee?: string | number | bigint;
  meter?: string | number | bigint;
  timeoutMs?: number;
  onPending?: (pending: unknown) => void;
  signal?: AbortSignal;
}

export interface VerifyOptions {
  type?: RecordType;
  prior?: Envelope;
  releaseId?: string;
  signerKeyId?: string;
  signerPublicKey?: string | Uint8Array;
  network: string;
  strict?: boolean;
  requireAnchor?: boolean;
  maxAnchorDelay?: number;
  at?: string;
  deadlineMs?: number;
  rpc?: string;
  clients?: unknown[];
  trustSingleEndpoint?: boolean;
  trustCustomEndpoints?: boolean;
  allowLoopback?: boolean;
}

export interface Check {
  name: string;
  ok: boolean;
  detail: string;
  transport: boolean;
  indeterminate: boolean;
  unproven: boolean;
}

export interface VerifyResult {
  valid: boolean;
  status: 'valid' | 'unproven' | 'indeterminate' | 'invalid';
  type: RecordType | null;
  releaseId?: string;
  signerId?: string;
  statement?: Record<string, unknown>;
  anchoredAt?: string | null;
  endpoints: string[];
  officialEndpoints: boolean | null;
  checks: Check[];
}

export function generateKey(): Uint8Array;
export function publicKey(key: Uint8Array): Uint8Array;
export function keyId(key: Uint8Array): string;
export function describeKey(key: Uint8Array): KeyDescription;
export function subjectRef(secret: Uint8Array, reference: string): string;
export function release(options: ReleaseOptions): Envelope;
export function artifact(options: ArtifactOptions): Envelope;
export function attest(options: AttestOptions): Envelope;
export function approve(options: ApproveOptions): Envelope;
export function revoke(options: RevokeOptions): Envelope;
export function anchor(envelopes: Envelope | Envelope[], options: AnchorOptions): Promise<Envelope[]>;
export function complete(envelopes: Envelope | Envelope[], pending: unknown, options?: AnchorOptions): Promise<Envelope[]>;
export function verify(envelope: Envelope, options: VerifyOptions): Promise<VerifyResult>;
export function anchorDigest(envelope: Envelope): string;
export function recordRef(envelope: Envelope): string;

export const FORMAT: 'qsign/1';
export const ALGORITHM: 'ML-DSA-65';
export const KIND: 1602;
export const TYPES: readonly RecordType[];
export const DIGESTS: readonly Digest[];
export const PREDICATES: readonly Predicate[];
export const OUTCOMES: readonly Outcome[];
export const PUBLIC_KEY_BYTES: 1952;
export const SIGNATURE_BYTES: 3309;
