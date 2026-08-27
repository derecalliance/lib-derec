// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

/**
 * Message marshalling.
 *
 * Every `extract_*` entry point in the C ABI hands back protobuf wire bytes,
 * and every `produce_*` / `process_*` that takes a message takes the same.
 * Go and .NET decode those with generated protobuf bindings; this SDK has
 * none, so it goes through `derec_decode_message_json` /
 * `derec_encode_message_json` instead (`library/src/interop/ffi/message_json.rs`),
 * which re-emits each message as the JSON mirror the WASM SDKs already
 * surface. The wire format therefore stays a single Rust-side decision — this
 * file only changes representation.
 *
 * Two representation changes are needed to reach the exact JavaScript shape
 * `@derec-alliance/nodejs` exposes, where `serde-wasm-bindgen` produces it
 * natively:
 *
 *   - Wide numerics cross the JSON seam as decimal strings and are `bigint`
 *     in the typed surface. `serde_json` would otherwise emit them as JSON
 *     numbers, and `JSON.parse` silently rounds anything above 2^53 — the
 *     corruption only appears once a real id happens to be large.
 *   - Byte fields cross as arrays of decimal byte values (`serde_json` draws
 *     no distinction for `serde_bytes`) and are `Uint8Array` in the typed
 *     surface.
 *
 * Both conversions are keyed by field name, matching the lists in
 * `message_json.rs`. A name-keyed walk is deliberate: `keep_list` is a
 * genuine `number[]` and must stay one, so a structural "array of numbers is
 * bytes" rule would corrupt it.
 */

import { jsonFromBytes, jsonToBytes } from './codec';
import { getNative } from './native';

/**
 * Selects which message the JSON codec operates on.
 *
 * Mirrors the crate's `MessageKind`, which the shared enum fixture holds
 * both sides to — so a message
 * added in Rust cannot reach this SDK as a silently unhandled value.
 */
export enum MessageKind {
  PairRequest = 0,
  PairResponse = 1,
  PrePairRequest = 2,
  PrePairResponse = 3,
  GetSecretIdsVersionsRequest = 4,
  GetSecretIdsVersionsResponse = 5,
  GetShareRequest = 6,
  GetShareResponse = 7,
  StoreShareRequest = 8,
  StoreShareResponse = 9,
  UnpairRequest = 10,
  UnpairResponse = 11,
  VerifyShareRequest = 12,
  VerifyShareResponse = 13,
  TransportProtocol = 14,
  CommunicationInfo = 15,
  ParameterRange = 16,
  CommittedDeRecShare = 17,
}

/** Fields the codec widens to decimal strings; `bigint` on this side. */
const BIGINT_STRING_FIELDS = new Set([
  'channel_id',
  'nonce',
  'secret_id',
  'replica_id',
  'min_share_size',
  'max_share_size',
  'min_time_between_verifications',
  'max_time_between_verifications',
  'min_time_between_share_updates',
  'max_time_between_share_updates',
  'min_unresponsive_deletion_timeout',
  'max_unresponsive_deletion_timeout',
  'min_unresponsive_deactivation_timeout',
  'max_unresponsive_deactivation_timeout',
]);

/**
 * `Timestamp.seconds` is an `i64` holding a Unix seconds value. It stays a
 * JSON number — no realistic timestamp approaches 2^53 — but the typed
 * surface declares it `bigint`, matching `@derec-alliance/nodejs`.
 */
const BIGINT_NUMBER_FIELDS = new Set(['seconds']);

/** Fields carrying `Vec<u8>`; `Uint8Array` on this side. */
const BYTE_FIELDS = new Set([
  'mlkem_ciphertext',
  'mlkem_encapsulation_key',
  'ecies_public_key',
  'contact_binding_hash',
  'bytes_value',
  'share',
  'committed_de_rec_share',
  'de_rec_share',
  'commitment',
  'hash',
]);

/** JSON as it arrives from Rust, turned into the typed surface. */
export function reviveMessage(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(reviveMessage);
  }
  if (value === null || typeof value !== 'object') {
    return value;
  }
  const out: Record<string, unknown> = {};
  for (const [key, field] of Object.entries(value as Record<string, unknown>)) {
    if (field === null || field === undefined) {
      // A `null` from an absent `Option` reads as `undefined` in the typed
      // surface, matching what `serde-wasm-bindgen` produces.
      out[key] = undefined;
    } else if (BIGINT_STRING_FIELDS.has(key) && typeof field === 'string') {
      out[key] = BigInt(field);
    } else if (BIGINT_NUMBER_FIELDS.has(key) && typeof field === 'number') {
      out[key] = BigInt(field);
    } else if (BYTE_FIELDS.has(key) && Array.isArray(field)) {
      out[key] = Uint8Array.from(field as number[]);
    } else {
      out[key] = reviveMessage(field);
    }
  }
  return out;
}

/** Inverse of {@link reviveMessage}. */
export function plainMessage(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(plainMessage);
  }
  if (value instanceof Uint8Array) {
    return Array.from(value);
  }
  if (typeof value === 'bigint') {
    return value.toString();
  }
  if (value === null || typeof value !== 'object') {
    return value;
  }
  const out: Record<string, unknown> = {};
  for (const [key, field] of Object.entries(value as Record<string, unknown>)) {
    if (field === undefined) {
      // Left out entirely rather than sent as `null`: serde reads a missing
      // `Option` field as `None`, and an explicit `null` for a field the DTO
      // does not declare optional would fail to deserialize.
      continue;
    }
    if (BIGINT_NUMBER_FIELDS.has(key) && typeof field === 'bigint') {
      out[key] = Number(field);
    } else if (field instanceof Uint8Array) {
      out[key] = Array.from(field);
    } else {
      out[key] = plainMessage(field);
    }
  }
  return out;
}

function host(): Record<string, (...args: unknown[]) => unknown> {
  return getNative() as never as Record<string, (...args: unknown[]) => unknown>;
}

/** Protobuf wire bytes -> the typed message. */
export function decodeMessage<T>(kind: MessageKind, proto: Uint8Array | ArrayBuffer): T {
  const buffer = host().decode_message_json(kind, proto) as ArrayBuffer;
  return reviveMessage(jsonFromBytes(buffer)) as T;
}

/** The typed message -> protobuf wire bytes. */
export function encodeMessage(kind: MessageKind, value: unknown): Uint8Array {
  const json = jsonToBytes(plainMessage(value));
  return new Uint8Array(host().encode_message_json(kind, json) as ArrayBuffer);
}

/**
 * Encodes an optional message argument. The C ABI reads a zero-length buffer
 * as "absent" for every optional message parameter, so `null`/`undefined`
 * becomes an empty array rather than a decision made here.
 */
export function encodeOptionalMessage(
  kind: MessageKind,
  value: unknown | null | undefined,
): Uint8Array {
  return value === null || value === undefined
    ? new Uint8Array(0)
    : encodeMessage(kind, value);
}
