// SPDX-License-Identifier: Apache-2.0
//
// Assembles the flat wasm-bindgen exports into the primitives.* namespace hierarchy,
// mirroring the Rust module structure:
//   crate::primitives::sharing::request::split(...)
//   → derec.primitives.sharing.request.split(...)
//
// The consumer must call `await init()` before using any primitives function.

export { default as init } from "./derec_library.js";

import { DeRecProtocolWasm } from "./derec_library.js";

/** Higher-level protocol orchestrator. Re-exported from the WASM module. */
export const DeRecProtocol = DeRecProtocolWasm;

/** Mirrors the Rust SenderKind enum used in pairing. */
export const SenderKind = Object.freeze({ OwnerNonRecovery: 0, OwnerRecovery: 1, Helper: 2, Replica: 3 });

/** Discriminant values for the `start()` flow parameter. */
export const FlowKind = Object.freeze({ Pairing: 0, Discovery: 1, ProtectSecret: 2, VerifyShares: 3, RecoverSecret: 4 });

import {
  pairing_request_create_contact,
  pairing_request_encode_contact,
  pairing_request_decode_contact,
  pairing_request_produce,
  pairing_response_accept,
  pairing_response_reject,
  pairing_response_process,
  sharing_request_split,
  sharing_request_produce,
  sharing_response_produce,
  sharing_response_process,
  sharing_decode_committed_share,
  verification_request_produce,
  verification_request_extract,
  verification_response_produce,
  verification_response_extract,
  verification_response_process,
  discovery_request_produce,
  discovery_request_extract,
  discovery_response_produce,
  discovery_response_process,
  recovery_request_produce,
  recovery_response_produce,
  recovery_response_recover,
} from "./derec_library.js";

export const primitives = {
  pairing: {
    request: {
      create_contact: pairing_request_create_contact,
      encode_contact: pairing_request_encode_contact,
      decode_contact: pairing_request_decode_contact,
      produce: pairing_request_produce,
    },
    response: {
      accept: pairing_response_accept,
      reject: pairing_response_reject,
      process: pairing_response_process,
    },
  },
  sharing: {
    request: {
      split: sharing_request_split,
      produce: sharing_request_produce,
    },
    response: {
      produce: sharing_response_produce,
      process: sharing_response_process,
    },
    decode_committed_share: sharing_decode_committed_share,
  },
  verification: {
    request: {
      produce: verification_request_produce,
      extract: verification_request_extract,
    },
    response: {
      produce: verification_response_produce,
      extract: verification_response_extract,
      process: verification_response_process,
    },
  },
  discovery: {
    request: {
      produce: discovery_request_produce,
      extract: discovery_request_extract,
    },
    response: {
      produce: discovery_response_produce,
      process: discovery_response_process,
    },
  },
  recovery: {
    request: {
      produce: recovery_request_produce,
    },
    response: {
      produce: recovery_response_produce,
      recover: recovery_response_recover,
    },
  },
};
