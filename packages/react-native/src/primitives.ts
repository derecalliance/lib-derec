// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

/**
 * The stateless primitive surface, shaped identically to
 * `@derec-alliance/nodejs`.
 *
 * Primitives are synchronous: they are pure byte transforms with no store or
 * transport callbacks, so they run on the JavaScript thread. `sharing.request.
 * split` does real cryptographic work, which is why an application that needs
 * it off-thread should drive it through `DeRecProtocol` instead.
 *
 * Each function marshals between the typed surface and the C ABI's own shapes
 * — protobuf wire bytes for messages, hand-packed little-endian containers for
 * the three set-valued arguments. See `./messages` and `./binary`. Nothing
 * here interprets a protocol value: no defaulting, no clamping, no branching
 * on what a field contains.
 */

import {
  decodeCommittedShareEntries,
  decodeSecretList,
  encodeSecretList,
  encodeShareResponses,
} from './binary';
import { jsonFromBytes, jsonToBytes, utf8Encode } from './codec';
import {
  MessageKind,
  decodeMessage,
  encodeMessage,
  encodeOptionalMessage,
  plainMessage,
  reviveMessage,
} from './messages';
import { getNative } from './native';
import type {
  CommittedDeRecShare,
  CommunicationInfo,
  ContactMessage,
  ContactMode,
  CreateContactResult,
  DiscoveryProcessResult,
  GetSecretIdsVersionsRequestMessage,
  GetSecretIdsVersionsResponseMessage,
  GetShareRequestMessage,
  GetShareResponseMessage,
  PairRequestMessage,
  PairResponseMessage,
  PairingProcessResult,
  PairingRequestProduceResult,
  PairingResponseProduceResult,
  ParameterRange,
  PrePairRequestExtractResult,
  PrePairRequestMessage,
  PrePairResponseExtractResult,
  PrePairResponseMessage,
  ProcessPrePairResult,
  ProducePrePairResult,
  ProduceResult,
  RecoverResult,
  SecretVersionEntry,
  SenderKind,
  SharingResponseProduceResult,
  SplitResult,
  StoreShareRequestMessage,
  StoreShareResponseMessage,
  TransportProtocol,
  UnpairRequestMessage,
  UnpairResponseMessage,
  UnpairingProcessResult,
  VerifyShareRequestMessage,
  VerifyShareResponseMessage,
} from './types';

/** Shape of the `__DeRec` host object: every member is a plain callable, since
 *  the JSI layer exposes host functions this way and TypeScript has no static
 *  knowledge of them. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type NativeHost = Record<string, (...args: any[]) => any>;

function call(name: string, ...args: unknown[]): unknown {
  return (getNative() as never as NativeHost)[name](...args);
}

function bytes(value: unknown): Uint8Array {
  return new Uint8Array(value as ArrayBuffer);
}

/** An omitted or empty list means "no override" for every reply-to argument;
 *  the C ABI reads a zero-length buffer as absent, and the responder then
 *  routes to the endpoints already recorded for the channel. */
function replyTo(value: TransportProtocol[] | undefined): Uint8Array {
  return value && value.length > 0 ? encodeTransportList(value) : new Uint8Array(0);
}

/**
 * `ContactMessage` keeps its own dedicated codec rather than going through
 * the generic message codec: `encode_contact_message` /
 * `decode_contact_message` also enforce the mode/field invariant — an
 * `InlineKeys` contact must carry keys, a `HashedKeys` one must carry only
 * the commitment — so a malformed contact is rejected here rather than
 * travelling.
 */
function encodeContact(contact_message: ContactMessage): Uint8Array {
  return bytes(
    call('encode_contact_message', jsonToBytes(plainMessage(contact_message))),
  );
}

function decodeContact(wire: Uint8Array | ArrayBuffer): ContactMessage {
  const json = call('decode_contact_message', wire) as ArrayBuffer;
  return reviveMessage(jsonFromBytes(json)) as ContactMessage;
}

const discovery = {
  request: {
    produce(
      channel_id: bigint,
      shared_key: Uint8Array,
      reply_to?: TransportProtocol[],
    ): ProduceResult {
      const envelope = call(
        'produce_get_secret_ids_versions_request_message',
        channel_id,
        shared_key,
        replyTo(reply_to),
      );
      return { envelope: bytes(envelope) };
    },

    extract(
      envelope_bytes: Uint8Array,
      shared_key: Uint8Array,
    ): { request: GetSecretIdsVersionsRequestMessage } {
      const result = call(
        'extract_get_secret_ids_versions_request',
        envelope_bytes,
        shared_key,
      ) as { request_proto_bytes: ArrayBuffer };
      return {
        request: decodeMessage<GetSecretIdsVersionsRequestMessage>(
          MessageKind.GetSecretIdsVersionsRequest,
          result.request_proto_bytes,
        ),
      };
    },
  },

  response: {
    produce(
      channel_id: bigint,
      secret_list: SecretVersionEntry[],
      shared_key: Uint8Array,
    ): ProduceResult {
      const envelope = call(
        'produce_get_secret_ids_versions_response_message',
        channel_id,
        encodeSecretList(secret_list),
        shared_key,
      );
      return { envelope: bytes(envelope) };
    },

    extract(
      envelope_bytes: Uint8Array,
      shared_key: Uint8Array,
    ): { response: GetSecretIdsVersionsResponseMessage } {
      const result = call(
        'extract_get_secret_ids_versions_response',
        envelope_bytes,
        shared_key,
      ) as { response_proto_bytes: ArrayBuffer };
      return {
        response: decodeMessage<GetSecretIdsVersionsResponseMessage>(
          MessageKind.GetSecretIdsVersionsResponse,
          result.response_proto_bytes,
        ),
      };
    },

    process(response: GetSecretIdsVersionsResponseMessage): DiscoveryProcessResult {
      const packed = call(
        'process_get_secret_ids_versions_response_message',
        encodeMessage(MessageKind.GetSecretIdsVersionsResponse, response),
      );
      return { secret_list: decodeSecretList(packed as ArrayBuffer) };
    },
  },
};

/**
 * Frames a preference-ordered endpoint list for the native seam: each entry
 * preceded by its protobuf varint byte length. Order is preserved exactly.
 */
function encodeTransportList(transports: TransportProtocol[]): Uint8Array {
  const entries = transports.map((t) =>
    new Uint8Array(encodeMessage(MessageKind.TransportProtocol, t)),
  );
  const out: number[] = [];
  for (const entry of entries) {
    let len = entry.length;
    do {
      let b = len & 0x7f;
      len >>>= 7;
      if (len !== 0) b |= 0x80;
      out.push(b);
    } while (len !== 0);
    out.push(...entry);
  }
  return new Uint8Array(out);
}

/**
 * Reads the framing `encodeTransportList` writes. Order is the peer's and is
 * preserved exactly — the library filters a peer's endpoints but never ranks
 * them, so this order is the peer's own preference, not a recommendation.
 */
function decodeTransportList(framed: Uint8Array | ArrayBuffer): TransportProtocol[] {
  const buf = framed instanceof Uint8Array ? framed : new Uint8Array(framed);
  const out: TransportProtocol[] = [];
  let i = 0;
  while (i < buf.length) {
    let len = 0;
    let shift = 0;
    for (;;) {
      if (i >= buf.length) {
        throw new Error('truncated transport list: length prefix runs past the end');
      }
      const b = buf[i++]!;
      len |= (b & 0x7f) << shift;
      if ((b & 0x80) === 0) break;
      shift += 7;
    }
    if (i + len > buf.length) {
      throw new Error('truncated transport list: entry runs past the end');
    }
    out.push(
      decodeMessage<TransportProtocol>(
        MessageKind.TransportProtocol,
        buf.subarray(i, i + len),
      ),
    );
    i += len;
  }
  return out;
}

const pairing = {
  request: {
    create_contact(
      channel_id: bigint,
      contact_mode: ContactMode | number,
      transport_protocols: TransportProtocol[],
    ): CreateContactResult {
      // The C entry point also accepts a caller-supplied nonce behind a
      // presence flag. `@derec-alliance/nodejs` has no such parameter, so the
      // flag is 0 and the library generates one — the same behaviour, not a
      // default invented here.
      const result = call(
        'create_contact_message',
        channel_id,
        contact_mode,
        encodeTransportList(transport_protocols),
        0,
        0n,
      ) as { contact_wire_bytes: ArrayBuffer; secret_key_material: ArrayBuffer };
      return {
        contact_message: decodeContact(result.contact_wire_bytes),
        secret_key: bytes(result.secret_key_material),
      };
    },

    /** Proto-encodes a `ContactMessage`. Rejects a contact that violates the
     *  mode/field invariant rather than serializing it. */
    encode_contact: encodeContact,

    /** Decodes proto `ContactMessage` bytes. Rejects a contact that violates
     *  the mode/field invariant rather than returning it. */
    decode_contact: decodeContact,

    produce(
      kind: SenderKind,
      transport_protocols: TransportProtocol[],
      contact_message: ContactMessage,
      communication_info: CommunicationInfo | null,
      parameter_range: ParameterRange | null,
    ): PairingRequestProduceResult {
      const result = call(
        'produce_pair_request_message',
        kind,
        encodeTransportList(transport_protocols),
        encodeContact(contact_message),
        encodeOptionalMessage(MessageKind.CommunicationInfo, communication_info),
        encodeOptionalMessage(MessageKind.ParameterRange, parameter_range),
      ) as {
        request_wire_bytes: ArrayBuffer;
        initiator_contact_message_wire_bytes: ArrayBuffer;
        secret_key_material: ArrayBuffer;
      };
      return {
        envelope: bytes(result.request_wire_bytes),
        initiator_contact_message: decodeContact(
          result.initiator_contact_message_wire_bytes,
        ),
        secret_key: bytes(result.secret_key_material),
      };
    },

    extract(envelope_bytes: Uint8Array, secret_key: Uint8Array): { request: PairRequestMessage } {
      const result = call('extract_pair_request', envelope_bytes, secret_key) as {
        request_proto_bytes: ArrayBuffer;
      };
      return {
        request: decodeMessage<PairRequestMessage>(
          MessageKind.PairRequest,
          result.request_proto_bytes,
        ),
      };
    },

    produce_pre_pair(
      own_transports: TransportProtocol[],
      contact_message: ContactMessage,
    ): ProducePrePairResult {
      const envelope = call(
        'produce_pre_pair_request_message',
        encodeTransportList(own_transports),
        encodeContact(contact_message),
      );
      return { envelope: bytes(envelope) };
    },

    extract_pre_pair(envelope_bytes: Uint8Array): PrePairRequestExtractResult {
      const result = call('extract_pre_pair_request', envelope_bytes) as {
        request_proto_bytes: ArrayBuffer;
      };
      return {
        request: decodeMessage<PrePairRequestMessage>(
          MessageKind.PrePairRequest,
          result.request_proto_bytes,
        ),
      };
    },
  },

  response: {
    produce(
      channel_id: bigint,
      request: PairRequestMessage,
      secret_key: Uint8Array,
      communication_info: CommunicationInfo | null,
      parameter_range: ParameterRange | null,
      unsafe_connection = false,
    ): PairingResponseProduceResult {
      const result = call(
        'produce_pair_response_message',
        channel_id,
        encodeMessage(MessageKind.PairRequest, request),
        secret_key,
        encodeOptionalMessage(MessageKind.CommunicationInfo, communication_info),
        encodeOptionalMessage(MessageKind.ParameterRange, parameter_range),
        unsafe_connection,
      ) as {
        response_wire_bytes: ArrayBuffer;
        peer_transports: ArrayBuffer;
        shared_key: ArrayBuffer;
        channel_id: bigint;
      };
      return {
        envelope: bytes(result.response_wire_bytes),
        peer_transports: decodeTransportList(result.peer_transports),
        shared_key: bytes(result.shared_key),
        channel_id: result.channel_id,
      };
    },

    extract(
      envelope_bytes: Uint8Array,
      secret_key: Uint8Array,
    ): { response: PairResponseMessage } {
      const result = call('extract_pair_response', envelope_bytes, secret_key) as {
        response_proto_bytes: ArrayBuffer;
      };
      return {
        response: decodeMessage<PairResponseMessage>(
          MessageKind.PairResponse,
          result.response_proto_bytes,
        ),
      };
    },

    process(
      contact_message: ContactMessage,
      response: PairResponseMessage,
      secret_key: Uint8Array,
    ): PairingProcessResult {
      const result = call(
        'process_pair_response_message',
        encodeContact(contact_message),
        encodeMessage(MessageKind.PairResponse, response),
        secret_key,
      ) as { shared_key: ArrayBuffer; channel_id: bigint };
      return { shared_key: bytes(result.shared_key), channel_id: result.channel_id };
    },

    produce_pre_pair(
      channel_id: bigint,
      request: PrePairRequestMessage,
      secret_key: Uint8Array,
    ): ProducePrePairResult {
      const envelope = call(
        'produce_pre_pair_response_message',
        channel_id,
        encodeMessage(MessageKind.PrePairRequest, request),
        secret_key,
      );
      return { envelope: bytes(envelope) };
    },

    extract_pre_pair(envelope_bytes: Uint8Array): PrePairResponseExtractResult {
      const result = call('extract_pre_pair_response', envelope_bytes) as {
        response_proto_bytes: ArrayBuffer;
      };
      return {
        response: decodeMessage<PrePairResponseMessage>(
          MessageKind.PrePairResponse,
          result.response_proto_bytes,
        ),
      };
    },

    process_pre_pair(
      contact_message: ContactMessage,
      response: PrePairResponseMessage,
    ): ProcessPrePairResult {
      const result = call(
        'process_pre_pair_response_message',
        encodeContact(contact_message),
        encodeMessage(MessageKind.PrePairResponse, response),
      ) as {
        mlkem_encapsulation_key: ArrayBuffer;
        ecies_public_key: ArrayBuffer;
        nonce: bigint;
      };
      return {
        mlkem_encapsulation_key: bytes(result.mlkem_encapsulation_key),
        ecies_public_key: bytes(result.ecies_public_key),
        nonce: result.nonce,
      };
    },
  },
};

const recovery = {
  request: {
    produce(
      channel_id: bigint,
      secret_id: bigint,
      version: number,
      shared_key: Uint8Array,
      reply_to?: TransportProtocol[],
    ): ProduceResult {
      const envelope = call(
        'produce_get_share_request_message',
        channel_id,
        secret_id,
        version,
        shared_key,
        replyTo(reply_to),
      );
      return { envelope: bytes(envelope) };
    },

    extract(
      envelope_bytes: Uint8Array,
      shared_key: Uint8Array,
    ): { request: GetShareRequestMessage } {
      const result = call('extract_get_share_request', envelope_bytes, shared_key) as {
        request_proto_bytes: ArrayBuffer;
      };
      return {
        request: decodeMessage<GetShareRequestMessage>(
          MessageKind.GetShareRequest,
          result.request_proto_bytes,
        ),
      };
    },
  },

  response: {
    produce(
      channel_id: bigint,
      request: GetShareRequestMessage,
      stored_share_request: StoreShareRequestMessage,
      shared_key: Uint8Array,
    ): ProduceResult {
      const envelope = call(
        'produce_get_share_response_message',
        channel_id,
        encodeMessage(MessageKind.GetShareRequest, request),
        encodeMessage(MessageKind.StoreShareRequest, stored_share_request),
        shared_key,
      );
      return { envelope: bytes(envelope) };
    },

    extract(
      envelope_bytes: Uint8Array,
      shared_key: Uint8Array,
    ): { response: GetShareResponseMessage } {
      const result = call('extract_get_share_response', envelope_bytes, shared_key) as {
        response_proto_bytes: ArrayBuffer;
      };
      return {
        response: decodeMessage<GetShareResponseMessage>(
          MessageKind.GetShareResponse,
          result.response_proto_bytes,
        ),
      };
    },

    recover(
      secret_id: bigint,
      version: number,
      responses: GetShareResponseMessage[],
    ): RecoverResult {
      const packed = encodeShareResponses(
        responses.map((response) => encodeMessage(MessageKind.GetShareResponse, response)),
      );
      const secret = call('recover_from_share_responses', packed, secret_id, version);
      return { secret_data: bytes(secret) };
    },
  },
};

const sharing = {
  request: {
    split(
      channels: bigint[],
      secret_id: bigint,
      version: number,
      secret_data: Uint8Array,
      threshold: number,
    ): SplitResult {
      const packed = call('protect_secret', secret_id, secret_data, channels, threshold, version);
      const shares = new Map<bigint, CommittedDeRecShare>();
      for (const entry of decodeCommittedShareEntries(packed as ArrayBuffer)) {
        shares.set(
          entry.channelId,
          decodeMessage<CommittedDeRecShare>(MessageKind.CommittedDeRecShare, entry.shareProto),
        );
      }
      return { shares };
    },

    produce(
      channel_id: bigint,
      version: number,
      secret_id: bigint,
      committed_share: CommittedDeRecShare,
      keep_list: number[],
      description: string,
      shared_key: Uint8Array,
      reply_to?: TransportProtocol[],
    ): ProduceResult {
      const envelope = call(
        'produce_store_share_request_message',
        channel_id,
        version,
        secret_id,
        encodeMessage(MessageKind.CommittedDeRecShare, committed_share),
        keep_list,
        utf8Encode(description),
        shared_key,
        replyTo(reply_to),
      );
      return { envelope: bytes(envelope) };
    },

    extract(
      envelope_bytes: Uint8Array,
      shared_key: Uint8Array,
    ): { request: StoreShareRequestMessage } {
      const result = call('extract_store_share_request', envelope_bytes, shared_key) as {
        request_proto_bytes: ArrayBuffer;
      };
      return {
        request: decodeMessage<StoreShareRequestMessage>(
          MessageKind.StoreShareRequest,
          result.request_proto_bytes,
        ),
      };
    },
  },

  response: {
    produce(
      channel_id: bigint,
      request: StoreShareRequestMessage,
      shared_key: Uint8Array,
    ): SharingResponseProduceResult {
      const result = call(
        'produce_store_share_response_message',
        channel_id,
        encodeMessage(MessageKind.StoreShareRequest, request),
        shared_key,
      ) as {
        wire_bytes: ArrayBuffer;
        committed_share_bytes: ArrayBuffer;
        secret_id: bigint;
        version: number;
      };
      return {
        envelope: bytes(result.wire_bytes),
        committed_share: decodeMessage<CommittedDeRecShare>(
          MessageKind.CommittedDeRecShare,
          result.committed_share_bytes,
        ),
        secret_id: result.secret_id,
        version: result.version,
      };
    },

    extract(
      envelope_bytes: Uint8Array,
      shared_key: Uint8Array,
    ): { response: StoreShareResponseMessage } {
      const result = call('extract_store_share_response', envelope_bytes, shared_key) as {
        response_proto_bytes: ArrayBuffer;
      };
      return {
        response: decodeMessage<StoreShareResponseMessage>(
          MessageKind.StoreShareResponse,
          result.response_proto_bytes,
        ),
      };
    },

    process(version: number, response: StoreShareResponseMessage): void {
      call(
        'process_store_share_response_message',
        version,
        encodeMessage(MessageKind.StoreShareResponse, response),
      );
    },
  },
};

const unpairing = {
  request: {
    produce(
      channel_id: bigint,
      memo: string,
      shared_key: Uint8Array,
      reply_to?: TransportProtocol[],
    ): ProduceResult {
      const envelope = call(
        'produce_unpair_request_message',
        channel_id,
        utf8Encode(memo),
        shared_key,
        replyTo(reply_to),
      );
      return { envelope: bytes(envelope) };
    },

    extract(
      envelope_bytes: Uint8Array,
      shared_key: Uint8Array,
    ): { request: UnpairRequestMessage } {
      const result = call('extract_unpair_request', envelope_bytes, shared_key) as {
        request_proto_bytes: ArrayBuffer;
      };
      return {
        request: decodeMessage<UnpairRequestMessage>(
          MessageKind.UnpairRequest,
          result.request_proto_bytes,
        ),
      };
    },
  },

  response: {
    produce(channel_id: bigint, shared_key: Uint8Array): ProduceResult {
      const envelope = call('produce_unpair_response_message', channel_id, shared_key);
      return { envelope: bytes(envelope) };
    },

    extract(
      envelope_bytes: Uint8Array,
      shared_key: Uint8Array,
    ): { response: UnpairResponseMessage } {
      const result = call('extract_unpair_response', envelope_bytes, shared_key) as {
        response_proto_bytes: ArrayBuffer;
      };
      return {
        response: decodeMessage<UnpairResponseMessage>(
          MessageKind.UnpairResponse,
          result.response_proto_bytes,
        ),
      };
    },

    /**
     * `acknowledged` is `true` for every value this can return. The library's
     * `unpairing::response::process` yields `ProcessResult { acknowledged:
     * true }` on success and an error on a non-Ok peer status, and the C ABI
     * carries only the error — so a refusal arrives as a thrown `DeRecError`,
     * never as `acknowledged: false`. The field exists because
     * `@derec-alliance/nodejs` surfaces it, where serde serializes the same
     * constant.
     */
    process(response: UnpairResponseMessage): UnpairingProcessResult {
      call('process_unpair_response_message', encodeMessage(MessageKind.UnpairResponse, response));
      return { acknowledged: true };
    },
  },
};

const verification = {
  request: {
    produce(
      channel_id: bigint,
      secret_id: bigint,
      version: number,
      shared_key: Uint8Array,
      reply_to?: TransportProtocol[],
    ): ProduceResult {
      const envelope = call(
        'produce_verify_share_request_message',
        channel_id,
        secret_id,
        version,
        shared_key,
        replyTo(reply_to),
      );
      return { envelope: bytes(envelope) };
    },

    extract(
      envelope_bytes: Uint8Array,
      shared_key: Uint8Array,
    ): { request: VerifyShareRequestMessage } {
      const result = call('extract_verify_share_request', envelope_bytes, shared_key) as {
        request_proto_bytes: ArrayBuffer;
      };
      return {
        request: decodeMessage<VerifyShareRequestMessage>(
          MessageKind.VerifyShareRequest,
          result.request_proto_bytes,
        ),
      };
    },
  },

  response: {
    produce(
      channel_id: bigint,
      request: VerifyShareRequestMessage,
      shared_key: Uint8Array,
      share_content: Uint8Array,
    ): ProduceResult {
      const envelope = call(
        'produce_verify_share_response_message',
        channel_id,
        encodeMessage(MessageKind.VerifyShareRequest, request),
        shared_key,
        share_content,
      );
      return { envelope: bytes(envelope) };
    },

    extract(
      envelope_bytes: Uint8Array,
      shared_key: Uint8Array,
    ): { response: VerifyShareResponseMessage } {
      const result = call('extract_verify_share_response', envelope_bytes, shared_key) as {
        response_proto_bytes: ArrayBuffer;
      };
      return {
        response: decodeMessage<VerifyShareResponseMessage>(
          MessageKind.VerifyShareResponse,
          result.response_proto_bytes,
        ),
      };
    },

    /** `request` must be the request the owner previously produced for this
     *  challenge. Responses whose `(nonce, secret_id, version)` triple does
     *  not match are rejected — that is the anti-replay gate. */
    process(
      request: VerifyShareRequestMessage,
      response: VerifyShareResponseMessage,
      share_content: Uint8Array,
    ): boolean {
      return call(
        'process_verify_share_response_message',
        encodeMessage(MessageKind.VerifyShareRequest, request),
        encodeMessage(MessageKind.VerifyShareResponse, response),
        share_content,
      ) as boolean;
    },
  },
};

export const primitives = {
  discovery,
  pairing,
  recovery,
  sharing,
  unpairing,
  verification,
};

/**
 * Envelope-level helpers that operate on raw `DeRecMessage` bytes without
 * touching the encrypted inner payload.
 */
export const envelope = {
  apply_trace_id(envelope_bytes: Uint8Array, trace_id: bigint): Uint8Array {
    return bytes(call('apply_trace_id_to_envelope', envelope_bytes, trace_id));
  },
  read_trace_id(envelope_bytes: Uint8Array): bigint {
    return call('read_trace_id_from_envelope', envelope_bytes) as bigint;
  },
};
