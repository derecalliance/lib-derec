// SPDX-License-Identifier: Apache-2.0
//
// Assembles the flat wasm-bindgen exports into the primitives.* namespace hierarchy,
// mirroring the Rust module structure:
//   crate::primitives::sharing::request::split(...)
//   → derec.primitives.sharing.request.split(...)
//
// The consumer must call `await init()` before using any primitives function.

export { default as init } from "./derec_library.js";

import {
  pairing_request_create_contact,
  pairing_request_encode_contact,
  pairing_request_decode_contact,
  pairing_request_produce,
  pairing_response_produce,
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
      produce: pairing_response_produce,
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
