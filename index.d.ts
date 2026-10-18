// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

export type EnvelopeType = 'document' | 'key-publish' | 'key-revoke';

export interface Envelope {
  format: 'qsign/1';
  type: EnvelopeType;
  algorithm: 'ML-DSA-65';
  key: { id: string; publicKey: string };
  subject: { alg: 'sha3-256'; digest: string };
  signedAt: string;
  signer: string;
  note: string;
  signature: string;
  anchor?: unknown;
}

export interface KeyDescription {
  format: 'qsign-key/1';
  algorithm: 'ML-DSA-65';
  id: string;
  publicKey: string;
}

export interface SignOptions {
  key: Uint8Array;
  file?: string;
  bytes?: Uint8Array;
  digest?: Uint8Array | string;
  signer?: string;
  note?: string;
  signedAt?: string;
}

export interface KeyStatementOptions {
  key: Uint8Array;
  action: 'publish' | 'revoke';
  signer?: string;
  note?: string;
  signedAt?: string;
}

export interface AnchorOptions {
  seed: Uint8Array;
  index: number;
  network?: 'testnet';
  rpc?: string | string[];
  client?: unknown;
  clients?: Array<string | unknown>;
  trustSingleEndpoint?: boolean;
  allowLoopback?: boolean;
  endpointAllowList?: string[];
  meter?: number;
  maxFee?: string | number;
  timeoutMs?: number;
  onPending?: (pending: unknown) => void | Promise<void>;
}

export interface VerifyOptions {
  file?: string;
  bytes?: Uint8Array;
  digest?: Uint8Array | string;
  keyId?: string;
  publicKey?: Uint8Array | string;
  revocations?: Envelope[];
  keyPublication?: Envelope;
  requireAnchor?: boolean;
  maxAnchorDelay?: number;
  at?: string;
  expectType?: EnvelopeType;
  rpc?: string | string[];
  client?: unknown;
  clients?: Array<string | unknown>;
  trustSingleEndpoint?: boolean;
  trustCustomEndpoints?: boolean;
  allowLoopback?: boolean;
  endpointAllowList?: string[];
  expectedSender?: string | string[];
  contract?: string;
  trustCustomContract?: boolean;
}

export interface VerifyCheck {
  name: string;
  ok: boolean;
  detail: string;
  transport: boolean;
  indeterminate: boolean;
  unproven: boolean;
  unchecked: boolean;
}

export interface VerifyResult {
  valid: boolean;
  status: 'valid' | 'invalid' | 'indeterminate' | 'unverified' | 'unproven';
  type: EnvelopeType | null;
  keyId: string | null;
  signer?: string;
  note?: string;
  subject?: string;
  signedAt: string | null;
  anchoredAt: string | null;
  contentChecked: boolean;
  signerTrusted: boolean;
  signerBound: boolean;
  revocationChecked: boolean;
  notes: string[];
  checks: VerifyCheck[];
  endpoints: string[];
  officialEndpoints: boolean | null;
}

export function generateKey(): Uint8Array;
export function publicKey(key: Uint8Array): Uint8Array;
export function keyId(key: Uint8Array): string;
export function describeKey(key: Uint8Array): KeyDescription;
export function sign(options: SignOptions): Promise<Envelope>;
export function keyStatement(options: KeyStatementOptions): Envelope;
export function anchor(envelopes: Envelope | Envelope[], options: AnchorOptions): Promise<Envelope[]>;
export function complete(envelopes: Envelope | Envelope[], pending: unknown, options?: { rpc?: string | string[]; client?: unknown; clients?: Array<string | unknown>; trustSingleEndpoint?: boolean; allowLoopback?: boolean; endpointAllowList?: string[]; timeoutMs?: number }): Promise<Envelope[]>;
export function verify(envelope: unknown, options?: VerifyOptions): Promise<VerifyResult>;
export function parseEnvelope(envelope: unknown): { type: EnvelopeType; digest: string; keyId: string; signedAt: string; signer: string; note: string };
export function anchorDigest(envelope: unknown): string;
export const FORMAT: 'qsign/1';
export const ALGORITHM: 'ML-DSA-65';
export const CONTEXT: string;
export const TYPES: readonly EnvelopeType[];
