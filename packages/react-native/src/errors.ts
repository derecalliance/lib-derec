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

export interface DeRecError {
  category: DeRecErrorCategory;
  code: string;
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
