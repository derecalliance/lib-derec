// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

import type { DeRecEvent } from './types';

/**
 * Every category name `derec_error_category_name` can return, and no others.
 *
 * This is the authoritative list for this SDK, held to the Rust enum by a
 * test against the shared enum fixture so the two cannot drift.
 * It deliberately differs from `@derec-alliance/nodejs`'s union, which was
 * the original source of this file: that union lists `"wasm"`, a category no
 * C-ABI binding can ever emit, and omits `"ok"`, `"ffi"` and `"state_store"`,
 * which are live arms of `library/src/interop/ffi/error_names.rs` and reachable here.
 * The nodejs union is arguably wrong on its own terms too, but correcting it
 * is a change to that package, not this one.
 */
export const DEREC_ERROR_CATEGORIES = [
  "ok",
  "ffi",
  "pairing",
  "sharing",
  "recovery",
  "verification",
  "discovery",
  "unpairing",
  "derec_message",
  "secret_store",
  "channel_store",
  "share_store",
  "input",
  "protobuf",
  "invariant",
  "state_store",
] as const;

export type DeRecErrorCategory = (typeof DEREC_ERROR_CATEGORIES)[number];

/**
 * Every code `derec_error_code_name` can return, and no others.
 *
 * Held to the shared enum fixture by a test, like {@link DEREC_ERROR_CATEGORIES}.
 * Unlike the WASM bindings, this SDK raises no marshalling-level codes of its
 * own before a value reaches the library, so this list is exactly the Rust
 * `Code` table in `library/src/interop/error_codes.rs`.
 */
export const DEREC_ERROR_CODES = [
  "ok",
  "non_ok_status",
  "version_mismatch",
  "invariant",
  "invalid_input",
  "protobuf_decode",
  "protobuf_encode",
  "protocol_violation",
  "store_error",
  "builder_error",
  "missing_shared_key",
  "role_mismatch",
  "replica_id_not_configured",
  "channel_already_paired",
  "already_restored",
  "restore_conflict",
  "replica_id_conflict",
  "encryption",
  "keygen",
  "finish_pairing_initiator",
  "finish_pairing_responder",
  "empty_transport_uri",
  "invalid_contact_message",
  "invalid_pair_request_message",
  "invalid_pair_response_message",
  "prepair_hash_mismatch",
  "missing_replica_id",
  "unexpected_replica_id",
  "incompatible_parameter_range",
  "empty_channels",
  "duplicate_channel_id",
  "invalid_threshold",
  "empty_secret_data",
  "vss_share_failed",
  "invalid_weight",
  "too_many_subshares",
  "empty_responses",
  "empty_committed_derec_share",
  "decode_committed_derec_share",
  "decode_derec_share",
  "secret_id_mismatch",
  "reconstruction_failed",
  "malformed_recovered_secret",
  "ffi_null_ptr",
  "ffi_bad_length",
  "ffi_bad_utf8",
  "ffi_bad_proto",
  "ffi_invalid_enum",
  "ffi_bad_shared_key",
  "ffi_nul_in_string",
  "transport_invalid",
  "no_usable_endpoint",
] as const;

export type DeRecErrorCode = (typeof DEREC_ERROR_CODES)[number];

export interface DeRecError {
  category: DeRecErrorCategory;
  code: DeRecErrorCode;
  message: string;
  status?: number;
  memo?: string;
  expected?: number;
  got?: number;
  /**
   * Present only when `code` is `"restore_conflict"`: the channels already
   * living at the recovered canonical ids, as decimal strings — the same
   * field `@derec-alliance/nodejs` carries on its restore conflict error.
   * Clear exactly these and retry `restore`.
   */
  channel_ids?: string[];
  /** The channel the failing inbound message arrived on, when `process()` could tell. */
  channel_id?: string;
  /**
   * On a failed `process()`: the events it produced before failing, such as
   * sharing-round and unpair timeouts. They are not reported again, so
   * handle them as you would a successful call's events.
   */
  events?: DeRecEvent[];
}
