// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

const wasm = require("./derec_library.js");

const DeRecProtocol = wasm.DeRecProtocolWasm;
const DeRecProtocolBuilder = wasm.DeRecProtocolBuilder;

const SenderKind = Object.freeze({ Owner: 0, Helper: 1, ReplicaSource: 3, ReplicaDestination: 4 });

const ContactMode = Object.freeze({ InlineKeys: 0, HashedKeys: 1, NoKeys: 2 });

const FlowKind = Object.freeze({ Pairing: 0, Discovery: 1, ProtectSecret: 2, VerifyShares: 3, RecoverSecret: 4, Unpair: 5, UpdateChannelInfo: 6, ReplicaDiscovery: 7, UnpairReplica: 8 });

const primitives = {
  discovery: {
    request: {
      produce: wasm.discovery_request_produce,
      extract: wasm.discovery_request_extract,
    },
    response: {
      produce: wasm.discovery_response_produce,
      extract: wasm.discovery_response_extract,
      process: wasm.discovery_response_process,
    },
  },
  pairing: {
    request: {
      create_contact: wasm.pairing_request_create_contact,
      encode_contact: wasm.pairing_request_encode_contact,
      decode_contact: wasm.pairing_request_decode_contact,
      produce: wasm.pairing_request_produce,
      extract: wasm.pairing_request_extract,
      produce_pre_pair: wasm.pairing_request_produce_pre_pair,
      extract_pre_pair: wasm.pairing_request_extract_pre_pair,
    },
    response: {
      produce: wasm.pairing_response_produce,
      extract: wasm.pairing_response_extract,
      process: wasm.pairing_response_process,
      produce_pre_pair: wasm.pairing_response_produce_pre_pair,
      extract_pre_pair: wasm.pairing_response_extract_pre_pair,
      process_pre_pair: wasm.pairing_response_process_pre_pair,
    },
  },
  recovery: {
    request: {
      produce: wasm.recovery_request_produce,
      extract: wasm.recovery_request_extract,
    },
    response: {
      produce: wasm.recovery_response_produce,
      extract: wasm.recovery_response_extract,
      recover: wasm.recovery_response_recover,
    },
  },
  sharing: {
    request: {
      split: wasm.sharing_request_split,
      produce: wasm.sharing_request_produce,
      extract: wasm.sharing_request_extract,
    },
    response: {
      produce: wasm.sharing_response_produce,
      extract: wasm.sharing_response_extract,
      process: wasm.sharing_response_process,
    },
  },
  unpairing: {
    request: {
      produce: wasm.unpairing_request_produce,
      extract: wasm.unpairing_request_extract,
    },
    response: {
      produce: wasm.unpairing_response_produce,
      extract: wasm.unpairing_response_extract,
      process: wasm.unpairing_response_process,
    },
  },
  verification: {
    request: {
      produce: wasm.verification_request_produce,
      extract: wasm.verification_request_extract,
    },
    response: {
      produce: wasm.verification_response_produce,
      extract: wasm.verification_response_extract,
      process: wasm.verification_response_process,
    },
  },
};

const envelope = {
  apply_trace_id: wasm.envelope_apply_trace_id,
  read_trace_id: wasm.envelope_read_trace_id,
};

/**
 * Whether a channel or member with these attributes survives `filter`.
 *
 * Every empty field means "do not restrict", `exclude` is applied after `ids`,
 * and the restrictions combine with AND — the same contract the core states on
 * `ChannelFilter`. A store whose backing cannot express the filter as a query
 * can list and call this; that is correct but transfers the rows the filter
 * exists to leave behind.
 *
 * `id` is a decimal string, as ids are everywhere on this bridge. `role` is the
 * peer's `SenderKind` name for `listHelpers` and the member's `ReplicaRole`
 * name for `listReplicas`.
 */
function channelFilterMatches(filter, id, status, role) {
  if (!filter) return true;
  const ids = filter.ids ?? [];
  const statuses = filter.status ?? [];
  const exclude = filter.exclude ?? [];
  if (ids.length > 0 && !ids.includes(id)) return false;
  if (statuses.length > 0 && !statuses.includes(status)) return false;
  if (filter.role != null && filter.role !== role) return false;
  return !exclude.includes(id);
}

module.exports = {
  primitives,
  channelFilterMatches,
  envelope,
  DeRecProtocol,
  DeRecProtocolBuilder,
  SenderKind,
  ContactMode,
  FlowKind,
};
