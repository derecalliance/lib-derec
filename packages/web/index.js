// SPDX-License-Identifier: Apache-2.0

export { default as init } from "./derec_library.js";

import {
  DeRecProtocolWasm,
  DeRecProtocolBuilder as DeRecProtocolBuilderImpl,
  envelope_apply_trace_id,
  envelope_read_trace_id,
} from "./derec_library.js";

export const envelope = {
  apply_trace_id: envelope_apply_trace_id,
  read_trace_id: envelope_read_trace_id,
};

export const DeRecProtocol = DeRecProtocolWasm;
export const DeRecProtocolBuilder = DeRecProtocolBuilderImpl;

export const SenderKind = Object.freeze({ Owner: 0, Helper: 1, ReplicaSource: 3, ReplicaDestination: 4 });

export const ContactMode = Object.freeze({ InlineKeys: 0, HashedKeys: 1 });

export const FlowKind = Object.freeze({ Pairing: 0, Discovery: 1, ProtectSecret: 2, VerifyShares: 3, RecoverSecret: 4, Unpair: 5, UpdateChannelInfo: 6 });

import {
  discovery_request_produce,
  discovery_request_extract,
  discovery_response_produce,
  discovery_response_extract,
  discovery_response_process,
  pairing_request_create_contact,
  pairing_request_encode_contact,
  pairing_request_decode_contact,
  pairing_request_produce,
  pairing_request_extract,
  pairing_request_produce_pre_pair,
  pairing_request_extract_pre_pair,
  pairing_response_produce,
  pairing_response_extract,
  pairing_response_process,
  pairing_response_produce_pre_pair,
  pairing_response_extract_pre_pair,
  pairing_response_process_pre_pair,
  recovery_request_produce,
  recovery_request_extract,
  recovery_response_produce,
  recovery_response_extract,
  recovery_response_recover,
  sharing_request_split,
  sharing_request_produce,
  sharing_request_extract,
  sharing_response_produce,
  sharing_response_extract,
  sharing_response_process,
  unpairing_request_produce,
  unpairing_request_extract,
  unpairing_response_produce,
  unpairing_response_extract,
  unpairing_response_process,
  verification_request_produce,
  verification_request_extract,
  verification_response_produce,
  verification_response_extract,
  verification_response_process,
} from "./derec_library.js";

export const primitives = {
  discovery: {
    request: {
      produce: discovery_request_produce,
      extract: discovery_request_extract,
    },
    response: {
      produce: discovery_response_produce,
      extract: discovery_response_extract,
      process: discovery_response_process,
    },
  },
  pairing: {
    request: {
      create_contact: pairing_request_create_contact,
      encode_contact: pairing_request_encode_contact,
      decode_contact: pairing_request_decode_contact,
      produce: pairing_request_produce,
      extract: pairing_request_extract,
      produce_pre_pair: pairing_request_produce_pre_pair,
      extract_pre_pair: pairing_request_extract_pre_pair,
    },
    response: {
      produce: pairing_response_produce,
      extract: pairing_response_extract,
      process: pairing_response_process,
      produce_pre_pair: pairing_response_produce_pre_pair,
      extract_pre_pair: pairing_response_extract_pre_pair,
      process_pre_pair: pairing_response_process_pre_pair,
    },
  },
  recovery: {
    request: {
      produce: recovery_request_produce,
      extract: recovery_request_extract,
    },
    response: {
      produce: recovery_response_produce,
      extract: recovery_response_extract,
      recover: recovery_response_recover,
    },
  },
  sharing: {
    request: {
      split: sharing_request_split,
      produce: sharing_request_produce,
      extract: sharing_request_extract,
    },
    response: {
      produce: sharing_response_produce,
      extract: sharing_response_extract,
      process: sharing_response_process,
    },
  },
  unpairing: {
    request: {
      produce: unpairing_request_produce,
      extract: unpairing_request_extract,
    },
    response: {
      produce: unpairing_response_produce,
      extract: unpairing_response_extract,
      process: unpairing_response_process,
    },
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
};
