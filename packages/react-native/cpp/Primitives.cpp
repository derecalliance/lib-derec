// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#include "Primitives.h"

#include <cstring>
#include <string>
#include <vector>

#include "Convert.h"

using namespace facebook;

namespace derec {

void throwDeRecError(jsi::Runtime& rt, const DeRecError& error) {
  auto names = errorName(error.category, error.code);
  // `message` and `peer_memo` are Rust-owned strings; copy before releasing.
  std::string message =
      error.message == nullptr ? std::string() : std::string(error.message);
  std::string memo =
      error.peer_memo == nullptr ? std::string() : std::string(error.peer_memo);
  int32_t peerStatus = error.peer_status;
  uint32_t expected = error.expected;
  uint32_t got = error.got;

  // Release both owned strings in one call, matching the ABI contract.
  DeRecError owned = error;
  derec_free_error(&owned);

  auto payload = jsi::Object(rt);
  payload.setProperty(rt, "category", jsi::String::createFromUtf8(rt, names.first));
  payload.setProperty(rt, "code", jsi::String::createFromUtf8(rt, names.second));
  payload.setProperty(rt, "message", jsi::String::createFromUtf8(rt, message));
  if (peerStatus != 0) {
    payload.setProperty(rt, "status", jsi::Value(static_cast<int>(peerStatus)));
  }
  if (!memo.empty()) {
    payload.setProperty(rt, "memo", jsi::String::createFromUtf8(rt, memo));
  }
  if (expected != 0 || got != 0) {
    payload.setProperty(rt, "expected", jsi::Value(static_cast<int>(expected)));
    payload.setProperty(rt, "got", jsi::Value(static_cast<int>(got)));
  }
  throw jsi::JSError(rt, jsi::Value(rt, payload));
}

ByteView asBytes(jsi::Runtime& rt, const jsi::Value& value) {
  if (value.isNull() || value.isUndefined()) {
    return ByteView{nullptr, 0};
  }
  auto object = value.asObject(rt);
  if (object.isArrayBuffer(rt)) {
    auto buffer = object.getArrayBuffer(rt);
    return ByteView{buffer.data(rt), buffer.size(rt)};
  }
  // Typed arrays expose their backing store via `buffer` plus offsets.
  auto backing = object.getProperty(rt, "buffer").asObject(rt).getArrayBuffer(rt);
  auto offset =
      static_cast<size_t>(object.getProperty(rt, "byteOffset").asNumber());
  auto length =
      static_cast<size_t>(object.getProperty(rt, "byteLength").asNumber());
  return ByteView{backing.data(rt) + offset, length};
}

jsi::Value toArrayBuffer(jsi::Runtime& rt, const uint8_t* bytes, size_t len) {
  auto constructor = rt.global().getPropertyAsFunction(rt, "ArrayBuffer");
  auto result = constructor.callAsConstructor(rt, jsi::Value(static_cast<double>(len)))
                    .asObject(rt)
                    .getArrayBuffer(rt);
  if (len > 0 && bytes != nullptr) {
    std::memcpy(result.data(rt), bytes, len);
  }
  return jsi::Value(rt, result);
}

uint64_t asU64(jsi::Runtime& rt, const jsi::Value& value) {
  if (value.isBigInt()) {
    return value.asBigInt(rt).asUint64(rt);
  }
  return static_cast<uint64_t>(value.asNumber());
}

namespace {

/// Read a JS array of `bigint`/`number` elements as a `uint64_t` vector.
/// Used for `protect_secret`'s `channels` argument.
std::vector<uint64_t> asU64Array(jsi::Runtime& rt, const jsi::Value& value) {
  std::vector<uint64_t> out;
  if (value.isNull() || value.isUndefined()) {
    return out;
  }
  auto array = value.asObject(rt).asArray(rt);
  size_t length = array.size(rt);
  out.reserve(length);
  for (size_t i = 0; i < length; ++i) {
    out.push_back(asU64(rt, array.getValueAtIndex(rt, i)));
  }
  return out;
}

/// Read a JS array of `number` elements as a `uint32_t` vector. Used for
/// `produce_store_share_request_message`'s `keep_list` argument.
std::vector<uint32_t> asU32Array(jsi::Runtime& rt, const jsi::Value& value) {
  std::vector<uint32_t> out;
  if (value.isNull() || value.isUndefined()) {
    return out;
  }
  auto array = value.asObject(rt).asArray(rt);
  size_t length = array.size(rt);
  out.reserve(length);
  for (size_t i = 0; i < length; ++i) {
    out.push_back(static_cast<uint32_t>(array.getValueAtIndex(rt, i).asNumber()));
  }
  return out;
}

void requireArgs(jsi::Runtime& rt, const char* name, size_t count, size_t required) {
  if (count < required) {
    throw jsi::JSError(rt, std::string(name) + " expects " +
                                std::to_string(required) + " arguments");
  }
}

/// `produce_get_secret_ids_versions_request_message(channelId: bigint,
///   sharedKey: ArrayBuffer, replyTo: ArrayBuffer|null) -> ArrayBuffer`
jsi::Value produceGetSecretIdsVersionsRequestMessage(jsi::Runtime& rt,
                                                     const jsi::Value&,
                                                     const jsi::Value* args,
                                                     size_t count) {
  requireArgs(rt, "produce_get_secret_ids_versions_request_message", count, 3);
  uint64_t channelId = asU64(rt, args[0]);
  ByteView sharedKey = asBytes(rt, args[1]);
  ByteView replyTo = asBytes(rt, args[2]);
  ProduceGetSecretIdsVersionsRequestMessageResult result =
      produce_get_secret_ids_versions_request_message(
          channelId, sharedKey.ptr, sharedKey.len, replyTo.ptr, replyTo.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> bytes = takeBuffer(result.envelope_wire_bytes);
  return toArrayBuffer(rt, bytes.data(), bytes.size());
}

/// `extract_get_secret_ids_versions_request(request: ArrayBuffer,
///   sharedKey: ArrayBuffer) -> { channel_id, request_proto_bytes }`
jsi::Value extractGetSecretIdsVersionsRequest(jsi::Runtime& rt,
                                              const jsi::Value&,
                                              const jsi::Value* args,
                                              size_t count) {
  requireArgs(rt, "extract_get_secret_ids_versions_request", count, 2);
  ByteView request = asBytes(rt, args[0]);
  ByteView sharedKey = asBytes(rt, args[1]);
  ExtractGetSecretIdsVersionsRequestResult result =
      extract_get_secret_ids_versions_request(request.ptr, request.len,
                                               sharedKey.ptr, sharedKey.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> bytes = takeBuffer(result.request_proto_bytes);
  auto payload = jsi::Object(rt);
  payload.setProperty(rt, "channel_id",
                      jsi::Value(rt, jsi::BigInt::fromUint64(rt, result.channel_id)));
  payload.setProperty(rt, "request_proto_bytes",
                      toArrayBuffer(rt, bytes.data(), bytes.size()));
  return jsi::Value(rt, payload);
}

/// `produce_get_secret_ids_versions_response_message(channelId: bigint,
///   secretList: ArrayBuffer, sharedKey: ArrayBuffer) -> ArrayBuffer`
jsi::Value produceGetSecretIdsVersionsResponseMessage(jsi::Runtime& rt,
                                                      const jsi::Value&,
                                                      const jsi::Value* args,
                                                      size_t count) {
  requireArgs(rt, "produce_get_secret_ids_versions_response_message", count, 3);
  uint64_t channelId = asU64(rt, args[0]);
  ByteView secretList = asBytes(rt, args[1]);
  ByteView sharedKey = asBytes(rt, args[2]);
  ProduceGetSecretIdsVersionsResponseMessageResult result =
      produce_get_secret_ids_versions_response_message(
          channelId, secretList.ptr, secretList.len, sharedKey.ptr, sharedKey.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> bytes = takeBuffer(result.envelope_wire_bytes);
  return toArrayBuffer(rt, bytes.data(), bytes.size());
}

/// `extract_get_secret_ids_versions_response(response: ArrayBuffer,
///   sharedKey: ArrayBuffer) -> { channel_id, response_proto_bytes }`
jsi::Value extractGetSecretIdsVersionsResponse(jsi::Runtime& rt,
                                               const jsi::Value&,
                                               const jsi::Value* args,
                                               size_t count) {
  requireArgs(rt, "extract_get_secret_ids_versions_response", count, 2);
  ByteView response = asBytes(rt, args[0]);
  ByteView sharedKey = asBytes(rt, args[1]);
  ExtractGetSecretIdsVersionsResponseResult result =
      extract_get_secret_ids_versions_response(response.ptr, response.len,
                                                sharedKey.ptr, sharedKey.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> bytes = takeBuffer(result.response_proto_bytes);
  auto payload = jsi::Object(rt);
  payload.setProperty(rt, "channel_id",
                      jsi::Value(rt, jsi::BigInt::fromUint64(rt, result.channel_id)));
  payload.setProperty(rt, "response_proto_bytes",
                      toArrayBuffer(rt, bytes.data(), bytes.size()));
  return jsi::Value(rt, payload);
}

/// `process_get_secret_ids_versions_response_message(responseProto:
///   ArrayBuffer) -> ArrayBuffer`
jsi::Value processGetSecretIdsVersionsResponseMessage(jsi::Runtime& rt,
                                                      const jsi::Value&,
                                                      const jsi::Value* args,
                                                      size_t count) {
  requireArgs(rt, "process_get_secret_ids_versions_response_message", count, 1);
  ByteView responseProto = asBytes(rt, args[0]);
  ProcessGetSecretIdsVersionsResponseMessageResult result =
      process_get_secret_ids_versions_response_message(responseProto.ptr,
                                                         responseProto.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> bytes = takeBuffer(result.secret_list_bytes);
  return toArrayBuffer(rt, bytes.data(), bytes.size());
}

/// `apply_trace_id_to_envelope(envelope: ArrayBuffer, traceId: bigint)
///   -> ArrayBuffer`
jsi::Value applyTraceId(jsi::Runtime& rt,
                        const jsi::Value&,
                        const jsi::Value* args,
                        size_t count) {
  requireArgs(rt, "apply_trace_id_to_envelope", count, 2);
  ByteView envelope = asBytes(rt, args[0]);
  uint64_t traceId = asU64(rt, args[1]);

  ApplyTraceIdResult result =
      apply_trace_id_to_envelope(envelope.ptr, envelope.len, traceId);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> bytes = takeBuffer(result.wire_bytes);
  return toArrayBuffer(rt, bytes.data(), bytes.size());
}

/// `read_trace_id_from_envelope(envelope: ArrayBuffer) -> bigint`
jsi::Value readTraceId(jsi::Runtime& rt,
                       const jsi::Value&,
                       const jsi::Value* args,
                       size_t count) {
  requireArgs(rt, "read_trace_id_from_envelope", count, 1);
  ByteView envelope = asBytes(rt, args[0]);
  ReadTraceIdResult result =
      read_trace_id_from_envelope(envelope.ptr, envelope.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  return jsi::Value(rt, jsi::BigInt::fromUint64(rt, result.trace_id));
}

/// `create_contact_message(channelId: bigint, contactMode: number,
///   transportProtocol: ArrayBuffer, hasNonce: number, nonce: bigint)
///   -> { contact_wire_bytes, secret_key_material }`
jsi::Value createContactMessage(jsi::Runtime& rt,
                                const jsi::Value&,
                                const jsi::Value* args,
                                size_t count) {
  requireArgs(rt, "create_contact_message", count, 5);
  uint64_t channelId = asU64(rt, args[0]);
  auto contactMode = static_cast<int32_t>(args[1].asNumber());
  ByteView transportProtocol = asBytes(rt, args[2]);
  auto hasNonce = static_cast<uint32_t>(args[3].asNumber());
  uint64_t nonce = asU64(rt, args[4]);
  CreateContactMessageResult result = create_contact_message(
      channelId, contactMode, transportProtocol.ptr, transportProtocol.len,
      hasNonce, nonce);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> contactBytes = takeBuffer(result.contact_wire_bytes);
  std::vector<uint8_t> keyMaterial = takeBuffer(result.secret_key_material);
  auto payload = jsi::Object(rt);
  payload.setProperty(rt, "contact_wire_bytes",
                      toArrayBuffer(rt, contactBytes.data(), contactBytes.size()));
  payload.setProperty(rt, "secret_key_material",
                      toArrayBuffer(rt, keyMaterial.data(), keyMaterial.size()));
  return jsi::Value(rt, payload);
}

/// `validate_contact_message(contactMessage: ArrayBuffer) -> undefined`
jsi::Value validateContactMessage(jsi::Runtime& rt,
                                  const jsi::Value&,
                                  const jsi::Value* args,
                                  size_t count) {
  requireArgs(rt, "validate_contact_message", count, 1);
  ByteView contactMessage = asBytes(rt, args[0]);
  DeRecError error =
      validate_contact_message(contactMessage.ptr, contactMessage.len);
  if (error.code != 0) {
    throwDeRecError(rt, error);
  }
  return jsi::Value::undefined();
}

/// `encode_contact_message(contactJson: ArrayBuffer) -> ArrayBuffer`
jsi::Value encodeContactMessage(jsi::Runtime& rt,
                                const jsi::Value&,
                                const jsi::Value* args,
                                size_t count) {
  requireArgs(rt, "encode_contact_message", count, 1);
  ByteView contactJson = asBytes(rt, args[0]);
  EncodeContactMessageResult result =
      encode_contact_message(contactJson.ptr, contactJson.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> bytes = takeBuffer(result.wire_bytes);
  return toArrayBuffer(rt, bytes.data(), bytes.size());
}

/// `decode_contact_message(contactWireBytes: ArrayBuffer) -> ArrayBuffer`
jsi::Value decodeContactMessage(jsi::Runtime& rt,
                                const jsi::Value&,
                                const jsi::Value* args,
                                size_t count) {
  requireArgs(rt, "decode_contact_message", count, 1);
  ByteView contactWire = asBytes(rt, args[0]);
  DecodeContactMessageResult result =
      decode_contact_message(contactWire.ptr, contactWire.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> bytes = takeBuffer(result.contact_json);
  return toArrayBuffer(rt, bytes.data(), bytes.size());
}

/// `decode_message_json(kind: number, protoBytes: ArrayBuffer) -> ArrayBuffer`
///
/// Turns the opaque `*_proto_bytes` an `extract_*` call returns into the JSON
/// mirror of the message. `kind` is a `DEREC_MESSAGE_KIND_*` value; the
/// binding forwards it as an opaque scalar and never interprets it.
jsi::Value decodeMessageJson(jsi::Runtime& rt,
                             const jsi::Value&,
                             const jsi::Value* args,
                             size_t count) {
  requireArgs(rt, "decode_message_json", count, 2);
  auto kind = static_cast<int32_t>(args[0].asNumber());
  ByteView proto = asBytes(rt, args[1]);
  DeRecMessageJsonResult result =
      derec_decode_message_json(kind, proto.ptr, proto.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> bytes = takeBuffer(result.bytes);
  return toArrayBuffer(rt, bytes.data(), bytes.size());
}

/// `encode_message_json(kind: number, json: ArrayBuffer) -> ArrayBuffer`
///
/// Inverse of `decode_message_json`, producing the protobuf bytes a
/// `produce_*` or `process_*` call expects.
jsi::Value encodeMessageJson(jsi::Runtime& rt,
                             const jsi::Value&,
                             const jsi::Value* args,
                             size_t count) {
  requireArgs(rt, "encode_message_json", count, 2);
  auto kind = static_cast<int32_t>(args[0].asNumber());
  ByteView json = asBytes(rt, args[1]);
  DeRecMessageJsonResult result =
      derec_encode_message_json(kind, json.ptr, json.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> bytes = takeBuffer(result.bytes);
  return toArrayBuffer(rt, bytes.data(), bytes.size());
}

/// `produce_pair_request_message(senderKind: number, transportProtocol:
///   ArrayBuffer, contactMessage: ArrayBuffer, communicationInfo:
///   ArrayBuffer|null, parameterRange: ArrayBuffer|null) ->
///   { request_wire_bytes, initiator_contact_message_wire_bytes,
///     secret_key_material }`
jsi::Value producePairRequestMessage(jsi::Runtime& rt,
                                     const jsi::Value&,
                                     const jsi::Value* args,
                                     size_t count) {
  requireArgs(rt, "produce_pair_request_message", count, 5);
  auto senderKind = static_cast<int32_t>(args[0].asNumber());
  ByteView transportProtocol = asBytes(rt, args[1]);
  ByteView contactMessage = asBytes(rt, args[2]);
  ByteView communicationInfo = asBytes(rt, args[3]);
  ByteView parameterRange = asBytes(rt, args[4]);
  ProducePairRequestMessageResult result = produce_pair_request_message(
      senderKind, transportProtocol.ptr, transportProtocol.len,
      contactMessage.ptr, contactMessage.len, communicationInfo.ptr,
      communicationInfo.len, parameterRange.ptr, parameterRange.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> requestBytes = takeBuffer(result.request_wire_bytes);
  std::vector<uint8_t> contactBytes =
      takeBuffer(result.initiator_contact_message_wire_bytes);
  std::vector<uint8_t> keyMaterial = takeBuffer(result.secret_key_material);
  auto payload = jsi::Object(rt);
  payload.setProperty(rt, "request_wire_bytes",
                      toArrayBuffer(rt, requestBytes.data(), requestBytes.size()));
  payload.setProperty(rt, "initiator_contact_message_wire_bytes",
                      toArrayBuffer(rt, contactBytes.data(), contactBytes.size()));
  payload.setProperty(rt, "secret_key_material",
                      toArrayBuffer(rt, keyMaterial.data(), keyMaterial.size()));
  return jsi::Value(rt, payload);
}

/// `extract_pair_request(request: ArrayBuffer, secretKeyMaterial: ArrayBuffer)
///   -> { channel_id, request_proto_bytes }`
jsi::Value extractPairRequest(jsi::Runtime& rt,
                              const jsi::Value&,
                              const jsi::Value* args,
                              size_t count) {
  requireArgs(rt, "extract_pair_request", count, 2);
  ByteView request = asBytes(rt, args[0]);
  ByteView secretKeyMaterial = asBytes(rt, args[1]);
  ExtractPairRequestResult result = extract_pair_request(
      request.ptr, request.len, secretKeyMaterial.ptr, secretKeyMaterial.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> bytes = takeBuffer(result.request_proto_bytes);
  auto payload = jsi::Object(rt);
  payload.setProperty(rt, "channel_id",
                      jsi::Value(rt, jsi::BigInt::fromUint64(rt, result.channel_id)));
  payload.setProperty(rt, "request_proto_bytes",
                      toArrayBuffer(rt, bytes.data(), bytes.size()));
  return jsi::Value(rt, payload);
}

/// `produce_pair_response_message(channelId: bigint, requestProto:
///   ArrayBuffer, secretKeyMaterial: ArrayBuffer, communicationInfo:
///   ArrayBuffer|null, parameterRange: ArrayBuffer|null) ->
///   { response_wire_bytes, peer_transport_protocol, shared_key, channel_id }`
jsi::Value producePairResponseMessage(jsi::Runtime& rt,
                                      const jsi::Value&,
                                      const jsi::Value* args,
                                      size_t count) {
  requireArgs(rt, "produce_pair_response_message", count, 5);
  uint64_t channelId = asU64(rt, args[0]);
  ByteView requestProto = asBytes(rt, args[1]);
  ByteView secretKeyMaterial = asBytes(rt, args[2]);
  ByteView communicationInfo = asBytes(rt, args[3]);
  ByteView parameterRange = asBytes(rt, args[4]);
  ProducePairResponseMessageResult result = produce_pair_response_message(
      channelId, requestProto.ptr, requestProto.len, secretKeyMaterial.ptr,
      secretKeyMaterial.len, communicationInfo.ptr, communicationInfo.len,
      parameterRange.ptr, parameterRange.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> responseBytes = takeBuffer(result.response_wire_bytes);
  std::vector<uint8_t> peerTransportProtocol =
      takeBuffer(result.peer_transport_protocol);
  std::vector<uint8_t> sharedKey = takeBuffer(result.shared_key);
  auto payload = jsi::Object(rt);
  payload.setProperty(rt, "response_wire_bytes",
                      toArrayBuffer(rt, responseBytes.data(), responseBytes.size()));
  payload.setProperty(
      rt, "peer_transport_protocol",
      toArrayBuffer(rt, peerTransportProtocol.data(), peerTransportProtocol.size()));
  payload.setProperty(rt, "shared_key",
                      toArrayBuffer(rt, sharedKey.data(), sharedKey.size()));
  payload.setProperty(rt, "channel_id",
                      jsi::Value(rt, jsi::BigInt::fromUint64(rt, result.channel_id)));
  return jsi::Value(rt, payload);
}

/// `extract_pair_response(response: ArrayBuffer, secretKeyMaterial:
///   ArrayBuffer) -> { channel_id, response_proto_bytes }`
jsi::Value extractPairResponse(jsi::Runtime& rt,
                               const jsi::Value&,
                               const jsi::Value* args,
                               size_t count) {
  requireArgs(rt, "extract_pair_response", count, 2);
  ByteView response = asBytes(rt, args[0]);
  ByteView secretKeyMaterial = asBytes(rt, args[1]);
  ExtractPairResponseResult result = extract_pair_response(
      response.ptr, response.len, secretKeyMaterial.ptr, secretKeyMaterial.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> bytes = takeBuffer(result.response_proto_bytes);
  auto payload = jsi::Object(rt);
  payload.setProperty(rt, "channel_id",
                      jsi::Value(rt, jsi::BigInt::fromUint64(rt, result.channel_id)));
  payload.setProperty(rt, "response_proto_bytes",
                      toArrayBuffer(rt, bytes.data(), bytes.size()));
  return jsi::Value(rt, payload);
}

/// `process_pair_response_message(contactMessage: ArrayBuffer, responseProto:
///   ArrayBuffer, secretKeyMaterial: ArrayBuffer) -> { shared_key,
///   channel_id }`
jsi::Value processPairResponseMessage(jsi::Runtime& rt,
                                      const jsi::Value&,
                                      const jsi::Value* args,
                                      size_t count) {
  requireArgs(rt, "process_pair_response_message", count, 3);
  ByteView contactMessage = asBytes(rt, args[0]);
  ByteView responseProto = asBytes(rt, args[1]);
  ByteView secretKeyMaterial = asBytes(rt, args[2]);
  ProcessPairResponseMessageResult result = process_pair_response_message(
      contactMessage.ptr, contactMessage.len, responseProto.ptr,
      responseProto.len, secretKeyMaterial.ptr, secretKeyMaterial.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> sharedKey = takeBuffer(result.shared_key);
  auto payload = jsi::Object(rt);
  payload.setProperty(rt, "shared_key",
                      toArrayBuffer(rt, sharedKey.data(), sharedKey.size()));
  payload.setProperty(rt, "channel_id",
                      jsi::Value(rt, jsi::BigInt::fromUint64(rt, result.channel_id)));
  return jsi::Value(rt, payload);
}

/// `produce_pre_pair_request_message(transportProtocol: ArrayBuffer,
///   contactMessage: ArrayBuffer) -> ArrayBuffer`
jsi::Value producePrePairRequestMessage(jsi::Runtime& rt,
                                        const jsi::Value&,
                                        const jsi::Value* args,
                                        size_t count) {
  requireArgs(rt, "produce_pre_pair_request_message", count, 2);
  ByteView transportProtocol = asBytes(rt, args[0]);
  ByteView contactMessage = asBytes(rt, args[1]);
  ProducePrePairRequestMessageResult result = produce_pre_pair_request_message(
      transportProtocol.ptr, transportProtocol.len, contactMessage.ptr,
      contactMessage.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> bytes = takeBuffer(result.envelope_wire_bytes);
  return toArrayBuffer(rt, bytes.data(), bytes.size());
}

/// `extract_pre_pair_request(envelope: ArrayBuffer) -> { channel_id,
///   request_proto_bytes }`
jsi::Value extractPrePairRequest(jsi::Runtime& rt,
                                 const jsi::Value&,
                                 const jsi::Value* args,
                                 size_t count) {
  requireArgs(rt, "extract_pre_pair_request", count, 1);
  ByteView envelope = asBytes(rt, args[0]);
  ExtractPrePairRequestResult result =
      extract_pre_pair_request(envelope.ptr, envelope.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> bytes = takeBuffer(result.request_proto_bytes);
  auto payload = jsi::Object(rt);
  payload.setProperty(rt, "channel_id",
                      jsi::Value(rt, jsi::BigInt::fromUint64(rt, result.channel_id)));
  payload.setProperty(rt, "request_proto_bytes",
                      toArrayBuffer(rt, bytes.data(), bytes.size()));
  return jsi::Value(rt, payload);
}

/// `produce_pre_pair_response_message(channelId: bigint, requestProto:
///   ArrayBuffer, secretKeyMaterial: ArrayBuffer) -> ArrayBuffer`
jsi::Value producePrePairResponseMessage(jsi::Runtime& rt,
                                         const jsi::Value&,
                                         const jsi::Value* args,
                                         size_t count) {
  requireArgs(rt, "produce_pre_pair_response_message", count, 3);
  uint64_t channelId = asU64(rt, args[0]);
  ByteView requestProto = asBytes(rt, args[1]);
  ByteView secretKeyMaterial = asBytes(rt, args[2]);
  ProducePrePairResponseMessageResult result = produce_pre_pair_response_message(
      channelId, requestProto.ptr, requestProto.len, secretKeyMaterial.ptr,
      secretKeyMaterial.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> bytes = takeBuffer(result.envelope_wire_bytes);
  return toArrayBuffer(rt, bytes.data(), bytes.size());
}

/// `extract_pre_pair_response(envelope: ArrayBuffer) -> { channel_id,
///   response_proto_bytes }`
jsi::Value extractPrePairResponse(jsi::Runtime& rt,
                                  const jsi::Value&,
                                  const jsi::Value* args,
                                  size_t count) {
  requireArgs(rt, "extract_pre_pair_response", count, 1);
  ByteView envelope = asBytes(rt, args[0]);
  ExtractPrePairResponseResult result =
      extract_pre_pair_response(envelope.ptr, envelope.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> bytes = takeBuffer(result.response_proto_bytes);
  auto payload = jsi::Object(rt);
  payload.setProperty(rt, "channel_id",
                      jsi::Value(rt, jsi::BigInt::fromUint64(rt, result.channel_id)));
  payload.setProperty(rt, "response_proto_bytes",
                      toArrayBuffer(rt, bytes.data(), bytes.size()));
  return jsi::Value(rt, payload);
}

/// `process_pre_pair_response_message(contactMessage: ArrayBuffer,
///   responseProto: ArrayBuffer) -> { mlkem_encapsulation_key,
///   ecies_public_key, nonce }`
jsi::Value processPrePairResponseMessage(jsi::Runtime& rt,
                                         const jsi::Value&,
                                         const jsi::Value* args,
                                         size_t count) {
  requireArgs(rt, "process_pre_pair_response_message", count, 2);
  ByteView contactMessage = asBytes(rt, args[0]);
  ByteView responseProto = asBytes(rt, args[1]);
  ProcessPrePairResponseMessageResult result = process_pre_pair_response_message(
      contactMessage.ptr, contactMessage.len, responseProto.ptr,
      responseProto.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> mlkemKey = takeBuffer(result.mlkem_encapsulation_key);
  std::vector<uint8_t> eciesKey = takeBuffer(result.ecies_public_key);
  auto payload = jsi::Object(rt);
  payload.setProperty(rt, "mlkem_encapsulation_key",
                      toArrayBuffer(rt, mlkemKey.data(), mlkemKey.size()));
  payload.setProperty(rt, "ecies_public_key",
                      toArrayBuffer(rt, eciesKey.data(), eciesKey.size()));
  payload.setProperty(rt, "nonce",
                      jsi::Value(rt, jsi::BigInt::fromUint64(rt, result.nonce)));
  return jsi::Value(rt, payload);
}

/// `produce_get_share_request_message(channelId: bigint, secretId: bigint,
///   version: number, sharedKey: ArrayBuffer, replyTo: ArrayBuffer|null)
///   -> ArrayBuffer`
jsi::Value produceGetShareRequestMessage(jsi::Runtime& rt,
                                         const jsi::Value&,
                                         const jsi::Value* args,
                                         size_t count) {
  requireArgs(rt, "produce_get_share_request_message", count, 5);
  uint64_t channelId = asU64(rt, args[0]);
  uint64_t secretId = asU64(rt, args[1]);
  auto version = static_cast<uint32_t>(args[2].asNumber());
  ByteView sharedKey = asBytes(rt, args[3]);
  ByteView replyTo = asBytes(rt, args[4]);
  ProduceGetShareRequestMessageResult result = produce_get_share_request_message(
      channelId, secretId, version, sharedKey.ptr, sharedKey.len, replyTo.ptr,
      replyTo.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> bytes = takeBuffer(result.request_wire_bytes);
  return toArrayBuffer(rt, bytes.data(), bytes.size());
}

/// `extract_get_share_request(request: ArrayBuffer, sharedKey: ArrayBuffer)
///   -> { channel_id, request_proto_bytes }`
jsi::Value extractGetShareRequest(jsi::Runtime& rt,
                                  const jsi::Value&,
                                  const jsi::Value* args,
                                  size_t count) {
  requireArgs(rt, "extract_get_share_request", count, 2);
  ByteView request = asBytes(rt, args[0]);
  ByteView sharedKey = asBytes(rt, args[1]);
  ExtractGetShareRequestResult result = extract_get_share_request(
      request.ptr, request.len, sharedKey.ptr, sharedKey.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> bytes = takeBuffer(result.request_proto_bytes);
  auto payload = jsi::Object(rt);
  payload.setProperty(rt, "channel_id",
                      jsi::Value(rt, jsi::BigInt::fromUint64(rt, result.channel_id)));
  payload.setProperty(rt, "request_proto_bytes",
                      toArrayBuffer(rt, bytes.data(), bytes.size()));
  return jsi::Value(rt, payload);
}

/// `produce_get_share_response_message(channelId: bigint, requestProto:
///   ArrayBuffer, storedShareProto: ArrayBuffer, sharedKey: ArrayBuffer)
///   -> ArrayBuffer`
jsi::Value produceGetShareResponseMessage(jsi::Runtime& rt,
                                          const jsi::Value&,
                                          const jsi::Value* args,
                                          size_t count) {
  requireArgs(rt, "produce_get_share_response_message", count, 4);
  uint64_t channelId = asU64(rt, args[0]);
  ByteView requestProto = asBytes(rt, args[1]);
  ByteView storedShareProto = asBytes(rt, args[2]);
  ByteView sharedKey = asBytes(rt, args[3]);
  ProduceGetShareResponseMessageResult result = produce_get_share_response_message(
      channelId, requestProto.ptr, requestProto.len, storedShareProto.ptr,
      storedShareProto.len, sharedKey.ptr, sharedKey.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> bytes = takeBuffer(result.response_wire_bytes);
  return toArrayBuffer(rt, bytes.data(), bytes.size());
}

/// `extract_get_share_response(response: ArrayBuffer, sharedKey: ArrayBuffer)
///   -> { channel_id, response_proto_bytes }`
jsi::Value extractGetShareResponse(jsi::Runtime& rt,
                                   const jsi::Value&,
                                   const jsi::Value* args,
                                   size_t count) {
  requireArgs(rt, "extract_get_share_response", count, 2);
  ByteView response = asBytes(rt, args[0]);
  ByteView sharedKey = asBytes(rt, args[1]);
  ExtractGetShareResponseResult result = extract_get_share_response(
      response.ptr, response.len, sharedKey.ptr, sharedKey.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> bytes = takeBuffer(result.response_proto_bytes);
  auto payload = jsi::Object(rt);
  payload.setProperty(rt, "channel_id",
                      jsi::Value(rt, jsi::BigInt::fromUint64(rt, result.channel_id)));
  payload.setProperty(rt, "response_proto_bytes",
                      toArrayBuffer(rt, bytes.data(), bytes.size()));
  return jsi::Value(rt, payload);
}

/// `recover_from_share_responses(responses: ArrayBuffer, secretId: bigint,
///   version: number) -> ArrayBuffer`
jsi::Value recoverFromShareResponses(jsi::Runtime& rt,
                                     const jsi::Value&,
                                     const jsi::Value* args,
                                     size_t count) {
  requireArgs(rt, "recover_from_share_responses", count, 3);
  ByteView responses = asBytes(rt, args[0]);
  uint64_t secretId = asU64(rt, args[1]);
  auto version = static_cast<uint32_t>(args[2].asNumber());
  RecoverFromShareResponsesResult result = recover_from_share_responses(
      responses.ptr, responses.len, secretId, version);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> bytes = takeBuffer(result.secret_data);
  return toArrayBuffer(rt, bytes.data(), bytes.size());
}

/// `protect_secret(secretId: bigint, secretData: ArrayBuffer, channels:
///   (bigint|number)[], threshold: number, version: number) -> ArrayBuffer`
jsi::Value protectSecret(jsi::Runtime& rt,
                         const jsi::Value&,
                         const jsi::Value* args,
                         size_t count) {
  requireArgs(rt, "protect_secret", count, 5);
  uint64_t secretId = asU64(rt, args[0]);
  ByteView secretData = asBytes(rt, args[1]);
  std::vector<uint64_t> channels = asU64Array(rt, args[2]);
  auto threshold = static_cast<size_t>(args[3].asNumber());
  auto version = static_cast<uint32_t>(args[4].asNumber());
  ProtectSecretResult result = protect_secret(
      secretId, secretData.ptr, secretData.len, channels.data(),
      channels.size(), threshold, version);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> bytes = takeBuffer(result.shares_wire_bytes);
  return toArrayBuffer(rt, bytes.data(), bytes.size());
}

/// `produce_store_share_request_message(channelId: bigint, version: number,
///   secretId: bigint, committedShare: ArrayBuffer, keepList: number[],
///   description: ArrayBuffer, sharedKey: ArrayBuffer, replyTo:
///   ArrayBuffer|null) -> ArrayBuffer`
jsi::Value produceStoreShareRequestMessage(jsi::Runtime& rt,
                                          const jsi::Value&,
                                          const jsi::Value* args,
                                          size_t count) {
  requireArgs(rt, "produce_store_share_request_message", count, 8);
  uint64_t channelId = asU64(rt, args[0]);
  auto version = static_cast<uint32_t>(args[1].asNumber());
  uint64_t secretId = asU64(rt, args[2]);
  ByteView committedShare = asBytes(rt, args[3]);
  std::vector<uint32_t> keepList = asU32Array(rt, args[4]);
  ByteView description = asBytes(rt, args[5]);
  ByteView sharedKey = asBytes(rt, args[6]);
  ByteView replyTo = asBytes(rt, args[7]);
  ProduceStoreShareRequestMessageResult result =
      produce_store_share_request_message(
          channelId, version, secretId, committedShare.ptr,
          committedShare.len, keepList.data(), keepList.size(),
          description.ptr, description.len, sharedKey.ptr, sharedKey.len,
          replyTo.ptr, replyTo.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> bytes = takeBuffer(result.wire_bytes);
  return toArrayBuffer(rt, bytes.data(), bytes.size());
}

/// `extract_store_share_request(request: ArrayBuffer, sharedKey:
///   ArrayBuffer) -> { channel_id, request_proto_bytes }`
jsi::Value extractStoreShareRequest(jsi::Runtime& rt,
                                    const jsi::Value&,
                                    const jsi::Value* args,
                                    size_t count) {
  requireArgs(rt, "extract_store_share_request", count, 2);
  ByteView request = asBytes(rt, args[0]);
  ByteView sharedKey = asBytes(rt, args[1]);
  ExtractStoreShareRequestResult result = extract_store_share_request(
      request.ptr, request.len, sharedKey.ptr, sharedKey.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> bytes = takeBuffer(result.request_proto_bytes);
  auto payload = jsi::Object(rt);
  payload.setProperty(rt, "channel_id",
                      jsi::Value(rt, jsi::BigInt::fromUint64(rt, result.channel_id)));
  payload.setProperty(rt, "request_proto_bytes",
                      toArrayBuffer(rt, bytes.data(), bytes.size()));
  return jsi::Value(rt, payload);
}

/// `produce_store_share_response_message(channelId: bigint, requestProto:
///   ArrayBuffer, sharedKey: ArrayBuffer) -> { wire_bytes,
///   committed_share_bytes, secret_id, version }`
jsi::Value produceStoreShareResponseMessage(jsi::Runtime& rt,
                                           const jsi::Value&,
                                           const jsi::Value* args,
                                           size_t count) {
  requireArgs(rt, "produce_store_share_response_message", count, 3);
  uint64_t channelId = asU64(rt, args[0]);
  ByteView requestProto = asBytes(rt, args[1]);
  ByteView sharedKey = asBytes(rt, args[2]);
  ProduceStoreShareResponseMessageResult result =
      produce_store_share_response_message(channelId, requestProto.ptr,
                                            requestProto.len, sharedKey.ptr,
                                            sharedKey.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> wireBytes = takeBuffer(result.wire_bytes);
  std::vector<uint8_t> committedShareBytes =
      takeBuffer(result.committed_share_bytes);
  auto payload = jsi::Object(rt);
  payload.setProperty(rt, "wire_bytes",
                      toArrayBuffer(rt, wireBytes.data(), wireBytes.size()));
  payload.setProperty(
      rt, "committed_share_bytes",
      toArrayBuffer(rt, committedShareBytes.data(), committedShareBytes.size()));
  payload.setProperty(rt, "secret_id",
                      jsi::Value(rt, jsi::BigInt::fromUint64(rt, result.secret_id)));
  payload.setProperty(rt, "version",
                      jsi::Value(static_cast<double>(result.version)));
  return jsi::Value(rt, payload);
}

/// `extract_store_share_response(response: ArrayBuffer, sharedKey:
///   ArrayBuffer) -> { channel_id, response_proto_bytes }`
jsi::Value extractStoreShareResponse(jsi::Runtime& rt,
                                     const jsi::Value&,
                                     const jsi::Value* args,
                                     size_t count) {
  requireArgs(rt, "extract_store_share_response", count, 2);
  ByteView response = asBytes(rt, args[0]);
  ByteView sharedKey = asBytes(rt, args[1]);
  ExtractStoreShareResponseResult result = extract_store_share_response(
      response.ptr, response.len, sharedKey.ptr, sharedKey.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> bytes = takeBuffer(result.response_proto_bytes);
  auto payload = jsi::Object(rt);
  payload.setProperty(rt, "channel_id",
                      jsi::Value(rt, jsi::BigInt::fromUint64(rt, result.channel_id)));
  payload.setProperty(rt, "response_proto_bytes",
                      toArrayBuffer(rt, bytes.data(), bytes.size()));
  return jsi::Value(rt, payload);
}

/// `process_store_share_response_message(version: number, responseProto:
///   ArrayBuffer) -> undefined`
jsi::Value processStoreShareResponseMessage(jsi::Runtime& rt,
                                           const jsi::Value&,
                                           const jsi::Value* args,
                                           size_t count) {
  requireArgs(rt, "process_store_share_response_message", count, 2);
  auto version = static_cast<uint32_t>(args[0].asNumber());
  ByteView responseProto = asBytes(rt, args[1]);
  ProcessStoreShareResponseMessageResult result =
      process_store_share_response_message(version, responseProto.ptr,
                                            responseProto.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  return jsi::Value::undefined();
}

/// `produce_unpair_request_message(channelId: bigint, memo: ArrayBuffer,
///   sharedKey: ArrayBuffer, replyTo: ArrayBuffer|null) -> ArrayBuffer`
jsi::Value produceUnpairRequestMessage(jsi::Runtime& rt,
                                       const jsi::Value&,
                                       const jsi::Value* args,
                                       size_t count) {
  requireArgs(rt, "produce_unpair_request_message", count, 4);
  uint64_t channelId = asU64(rt, args[0]);
  ByteView memo = asBytes(rt, args[1]);
  ByteView sharedKey = asBytes(rt, args[2]);
  ByteView replyTo = asBytes(rt, args[3]);
  ProduceUnpairRequestMessageResult result = produce_unpair_request_message(
      channelId, memo.ptr, memo.len, sharedKey.ptr, sharedKey.len,
      replyTo.ptr, replyTo.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> bytes = takeBuffer(result.request_wire_bytes);
  return toArrayBuffer(rt, bytes.data(), bytes.size());
}

/// `extract_unpair_request(request: ArrayBuffer, sharedKey: ArrayBuffer) ->
///   { channel_id, memo, request_proto_bytes }`
jsi::Value extractUnpairRequest(jsi::Runtime& rt,
                                const jsi::Value&,
                                const jsi::Value* args,
                                size_t count) {
  requireArgs(rt, "extract_unpair_request", count, 2);
  ByteView request = asBytes(rt, args[0]);
  ByteView sharedKey = asBytes(rt, args[1]);
  ExtractUnpairRequestResult result = extract_unpair_request(
      request.ptr, request.len, sharedKey.ptr, sharedKey.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::string memo = takeString(result.memo);
  std::vector<uint8_t> bytes = takeBuffer(result.request_proto_bytes);
  auto payload = jsi::Object(rt);
  payload.setProperty(rt, "channel_id",
                      jsi::Value(rt, jsi::BigInt::fromUint64(rt, result.channel_id)));
  payload.setProperty(rt, "memo", jsi::String::createFromUtf8(rt, memo));
  payload.setProperty(rt, "request_proto_bytes",
                      toArrayBuffer(rt, bytes.data(), bytes.size()));
  return jsi::Value(rt, payload);
}

/// `produce_unpair_response_message(channelId: bigint, sharedKey:
///   ArrayBuffer) -> ArrayBuffer`
jsi::Value produceUnpairResponseMessage(jsi::Runtime& rt,
                                        const jsi::Value&,
                                        const jsi::Value* args,
                                        size_t count) {
  requireArgs(rt, "produce_unpair_response_message", count, 2);
  uint64_t channelId = asU64(rt, args[0]);
  ByteView sharedKey = asBytes(rt, args[1]);
  ProduceUnpairResponseMessageResult result =
      produce_unpair_response_message(channelId, sharedKey.ptr, sharedKey.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> bytes = takeBuffer(result.response_wire_bytes);
  return toArrayBuffer(rt, bytes.data(), bytes.size());
}

/// `extract_unpair_response(response: ArrayBuffer, sharedKey: ArrayBuffer)
///   -> { channel_id, response_proto_bytes }`
jsi::Value extractUnpairResponse(jsi::Runtime& rt,
                                 const jsi::Value&,
                                 const jsi::Value* args,
                                 size_t count) {
  requireArgs(rt, "extract_unpair_response", count, 2);
  ByteView response = asBytes(rt, args[0]);
  ByteView sharedKey = asBytes(rt, args[1]);
  ExtractUnpairResponseResult result = extract_unpair_response(
      response.ptr, response.len, sharedKey.ptr, sharedKey.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> bytes = takeBuffer(result.response_proto_bytes);
  auto payload = jsi::Object(rt);
  payload.setProperty(rt, "channel_id",
                      jsi::Value(rt, jsi::BigInt::fromUint64(rt, result.channel_id)));
  payload.setProperty(rt, "response_proto_bytes",
                      toArrayBuffer(rt, bytes.data(), bytes.size()));
  return jsi::Value(rt, payload);
}

/// `process_unpair_response_message(responseProto: ArrayBuffer) ->
///   undefined`
jsi::Value processUnpairResponseMessage(jsi::Runtime& rt,
                                       const jsi::Value&,
                                       const jsi::Value* args,
                                       size_t count) {
  requireArgs(rt, "process_unpair_response_message", count, 1);
  ByteView responseProto = asBytes(rt, args[0]);
  ProcessUnpairResponseResult result = process_unpair_response_message(
      responseProto.ptr, responseProto.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  return jsi::Value::undefined();
}

/// `produce_verify_share_request_message(channelId: bigint, secretId:
///   bigint, version: number, sharedKey: ArrayBuffer, replyTo:
///   ArrayBuffer|null) -> ArrayBuffer`
jsi::Value produceVerifyShareRequestMessage(jsi::Runtime& rt,
                                           const jsi::Value&,
                                           const jsi::Value* args,
                                           size_t count) {
  requireArgs(rt, "produce_verify_share_request_message", count, 5);
  uint64_t channelId = asU64(rt, args[0]);
  uint64_t secretId = asU64(rt, args[1]);
  auto version = static_cast<uint32_t>(args[2].asNumber());
  ByteView sharedKey = asBytes(rt, args[3]);
  ByteView replyTo = asBytes(rt, args[4]);
  ProduceVerifyShareRequestMessageResult result =
      produce_verify_share_request_message(channelId, secretId, version,
                                            sharedKey.ptr, sharedKey.len,
                                            replyTo.ptr, replyTo.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> bytes = takeBuffer(result.request_wire_bytes);
  return toArrayBuffer(rt, bytes.data(), bytes.size());
}

/// `extract_verify_share_request(request: ArrayBuffer, sharedKey:
///   ArrayBuffer) -> { channel_id, request_proto_bytes }`
jsi::Value extractVerifyShareRequest(jsi::Runtime& rt,
                                     const jsi::Value&,
                                     const jsi::Value* args,
                                     size_t count) {
  requireArgs(rt, "extract_verify_share_request", count, 2);
  ByteView request = asBytes(rt, args[0]);
  ByteView sharedKey = asBytes(rt, args[1]);
  ExtractVerifyShareRequestResult result = extract_verify_share_request(
      request.ptr, request.len, sharedKey.ptr, sharedKey.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> bytes = takeBuffer(result.request_proto_bytes);
  auto payload = jsi::Object(rt);
  payload.setProperty(rt, "channel_id",
                      jsi::Value(rt, jsi::BigInt::fromUint64(rt, result.channel_id)));
  payload.setProperty(rt, "request_proto_bytes",
                      toArrayBuffer(rt, bytes.data(), bytes.size()));
  return jsi::Value(rt, payload);
}

/// `produce_verify_share_response_message(channelId: bigint, requestProto:
///   ArrayBuffer, sharedKey: ArrayBuffer, shareContent: ArrayBuffer) ->
///   ArrayBuffer`
jsi::Value produceVerifyShareResponseMessage(jsi::Runtime& rt,
                                            const jsi::Value&,
                                            const jsi::Value* args,
                                            size_t count) {
  requireArgs(rt, "produce_verify_share_response_message", count, 4);
  uint64_t channelId = asU64(rt, args[0]);
  ByteView requestProto = asBytes(rt, args[1]);
  ByteView sharedKey = asBytes(rt, args[2]);
  ByteView shareContent = asBytes(rt, args[3]);
  ProduceVerifyShareResponseMessageResult result =
      produce_verify_share_response_message(
          channelId, requestProto.ptr, requestProto.len, sharedKey.ptr,
          sharedKey.len, shareContent.ptr, shareContent.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> bytes = takeBuffer(result.response_wire_bytes);
  return toArrayBuffer(rt, bytes.data(), bytes.size());
}

/// `extract_verify_share_response(response: ArrayBuffer, sharedKey:
///   ArrayBuffer) -> { channel_id, response_proto_bytes }`
jsi::Value extractVerifyShareResponse(jsi::Runtime& rt,
                                      const jsi::Value&,
                                      const jsi::Value* args,
                                      size_t count) {
  requireArgs(rt, "extract_verify_share_response", count, 2);
  ByteView response = asBytes(rt, args[0]);
  ByteView sharedKey = asBytes(rt, args[1]);
  ExtractVerifyShareResponseResult result = extract_verify_share_response(
      response.ptr, response.len, sharedKey.ptr, sharedKey.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  std::vector<uint8_t> bytes = takeBuffer(result.response_proto_bytes);
  auto payload = jsi::Object(rt);
  payload.setProperty(rt, "channel_id",
                      jsi::Value(rt, jsi::BigInt::fromUint64(rt, result.channel_id)));
  payload.setProperty(rt, "response_proto_bytes",
                      toArrayBuffer(rt, bytes.data(), bytes.size()));
  return jsi::Value(rt, payload);
}

/// `process_verify_share_response_message(requestProto: ArrayBuffer,
///   responseProto: ArrayBuffer, shareContent: ArrayBuffer) -> boolean`
jsi::Value processVerifyShareResponseMessage(jsi::Runtime& rt,
                                            const jsi::Value&,
                                            const jsi::Value* args,
                                            size_t count) {
  requireArgs(rt, "process_verify_share_response_message", count, 3);
  ByteView requestProto = asBytes(rt, args[0]);
  ByteView responseProto = asBytes(rt, args[1]);
  ByteView shareContent = asBytes(rt, args[2]);
  VerifyShareResponseResult result = process_verify_share_response_message(
      requestProto.ptr, requestProto.len, responseProto.ptr,
      responseProto.len, shareContent.ptr, shareContent.len);
  if (result.error.code != 0) {
    throwDeRecError(rt, result.error);
  }
  return jsi::Value(static_cast<bool>(result.is_valid));
}

void bind(jsi::Runtime& rt,
          jsi::Object& host,
          const char* name,
          size_t argCount,
          jsi::HostFunctionType body) {
  host.setProperty(rt, name,
                   jsi::Function::createFromHostFunction(
                       rt, jsi::PropNameID::forAscii(rt, name), argCount,
                       std::move(body)));
}

}  // namespace

void installPrimitives(jsi::Runtime& rt, jsi::Object& host) {
  bind(rt, host, "produce_get_secret_ids_versions_request_message", 3,
       produceGetSecretIdsVersionsRequestMessage);
  bind(rt, host, "extract_get_secret_ids_versions_request", 2,
       extractGetSecretIdsVersionsRequest);
  bind(rt, host, "produce_get_secret_ids_versions_response_message", 3,
       produceGetSecretIdsVersionsResponseMessage);
  bind(rt, host, "extract_get_secret_ids_versions_response", 2,
       extractGetSecretIdsVersionsResponse);
  bind(rt, host, "process_get_secret_ids_versions_response_message", 1,
       processGetSecretIdsVersionsResponseMessage);
  bind(rt, host, "apply_trace_id_to_envelope", 2, applyTraceId);
  bind(rt, host, "read_trace_id_from_envelope", 1, readTraceId);
  bind(rt, host, "create_contact_message", 5, createContactMessage);
  bind(rt, host, "validate_contact_message", 1, validateContactMessage);
  bind(rt, host, "encode_contact_message", 1, encodeContactMessage);
  bind(rt, host, "decode_contact_message", 1, decodeContactMessage);
  bind(rt, host, "decode_message_json", 2, decodeMessageJson);
  bind(rt, host, "encode_message_json", 2, encodeMessageJson);
  bind(rt, host, "produce_pair_request_message", 5, producePairRequestMessage);
  bind(rt, host, "extract_pair_request", 2, extractPairRequest);
  bind(rt, host, "produce_pair_response_message", 5, producePairResponseMessage);
  bind(rt, host, "extract_pair_response", 2, extractPairResponse);
  bind(rt, host, "process_pair_response_message", 3, processPairResponseMessage);
  bind(rt, host, "produce_pre_pair_request_message", 2,
       producePrePairRequestMessage);
  bind(rt, host, "extract_pre_pair_request", 1, extractPrePairRequest);
  bind(rt, host, "produce_pre_pair_response_message", 3,
       producePrePairResponseMessage);
  bind(rt, host, "extract_pre_pair_response", 1, extractPrePairResponse);
  bind(rt, host, "process_pre_pair_response_message", 2,
       processPrePairResponseMessage);
  bind(rt, host, "produce_get_share_request_message", 5,
       produceGetShareRequestMessage);
  bind(rt, host, "extract_get_share_request", 2, extractGetShareRequest);
  bind(rt, host, "produce_get_share_response_message", 4,
       produceGetShareResponseMessage);
  bind(rt, host, "extract_get_share_response", 2, extractGetShareResponse);
  bind(rt, host, "recover_from_share_responses", 3, recoverFromShareResponses);
  bind(rt, host, "protect_secret", 5, protectSecret);
  bind(rt, host, "produce_store_share_request_message", 8,
       produceStoreShareRequestMessage);
  bind(rt, host, "extract_store_share_request", 2, extractStoreShareRequest);
  bind(rt, host, "produce_store_share_response_message", 3,
       produceStoreShareResponseMessage);
  bind(rt, host, "extract_store_share_response", 2, extractStoreShareResponse);
  bind(rt, host, "process_store_share_response_message", 2,
       processStoreShareResponseMessage);
  bind(rt, host, "produce_unpair_request_message", 4,
       produceUnpairRequestMessage);
  bind(rt, host, "extract_unpair_request", 2, extractUnpairRequest);
  bind(rt, host, "produce_unpair_response_message", 2,
       produceUnpairResponseMessage);
  bind(rt, host, "extract_unpair_response", 2, extractUnpairResponse);
  bind(rt, host, "process_unpair_response_message", 1,
       processUnpairResponseMessage);
  bind(rt, host, "produce_verify_share_request_message", 5,
       produceVerifyShareRequestMessage);
  bind(rt, host, "extract_verify_share_request", 2, extractVerifyShareRequest);
  bind(rt, host, "produce_verify_share_response_message", 4,
       produceVerifyShareResponseMessage);
  bind(rt, host, "extract_verify_share_response", 2, extractVerifyShareResponse);
  bind(rt, host, "process_verify_share_response_message", 3,
       processVerifyShareResponseMessage);
}

}  // namespace derec
