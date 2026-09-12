// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

export { default as init } from "./derec_library.js";

import {
  DeRecProtocolWasm,
  DeRecProtocolBuilder as DeRecProtocolBuilderImpl,
  envelope_apply_trace_id,
  envelope_read_trace_id,
} from "./derec_library.js";

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
export function channelFilterMatches(filter, id, status, role) {
  if (!filter) return true;
  const ids = filter.ids ?? [];
  const statuses = filter.status ?? [];
  const exclude = filter.exclude ?? [];
  if (ids.length > 0 && !ids.includes(id)) return false;
  if (statuses.length > 0 && !statuses.includes(status)) return false;
  if (filter.role != null && filter.role !== role) return false;
  return !exclude.includes(id);
}

export function advertisedEndpoints(message) {
  if (!message) return [];
  const offers = message.supported_transports ?? [];
  if (offers.length > 0) return offers;
  return message.transport_protocol ? [message.transport_protocol] : [];
}

export function sequentialFailover(dialer) {
  return {
    async send(endpoints, message) {
      let last;
      for (const endpoint of endpoints) {
        try {
          await dialer(endpoint, message);
          return;
        } catch (e) {
          last = e;
        }
      }
      // `endpoints` is never empty — the library refuses to record a peer
      // whose endpoints were all filtered away — so reaching here means at
      // least one attempt was made and `last` is populated.
      throw last ?? new Error("send was called with no endpoints");
    },
  };
}

export function singleEndpointTransport(dialer) {
  return {
    async send(endpoints, message) {
      if (endpoints.length === 0) {
        throw new Error("send was called with no endpoints");
      }
      await dialer(endpoints[0], message);
    },
  };
}

export const envelope = {
  apply_trace_id: envelope_apply_trace_id,
  read_trace_id: envelope_read_trace_id,
};

export const DeRecProtocol = DeRecProtocolWasm;
export const DeRecProtocolBuilder = DeRecProtocolBuilderImpl;

export const SenderKind = Object.freeze({ Owner: 0, Helper: 1, ReplicaSource: 3, ReplicaDestination: 4 });

export const ContactMode = Object.freeze({ InlineKeys: 0, HashedKeys: 1, NoKeys: 2 });

export const FlowKind = Object.freeze({ Pairing: 0, Discovery: 1, ProtectSecret: 2, VerifyShares: 3, RecoverSecret: 4, Unpair: 5, UpdateChannelInfo: 6, ReplicaDiscovery: 7, UnpairReplica: 8 });

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
