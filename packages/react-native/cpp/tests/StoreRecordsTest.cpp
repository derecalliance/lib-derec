// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.
//
// Exercises the decoders behind the share-save and transport-send callbacks,
// and the crate's transport protocol name accessors, across the real C ABI.

#include "../Convert.h"
#include "TestMain.h"

#include <cstring>
#include <string>
#include <vector>

using namespace derec;
using derec::testing::expect;

namespace {

std::vector<uint8_t> bytesOf(const std::string& text) {
  return std::vector<uint8_t>(text.begin(), text.end());
}

/// One encoded `TransportProtocol`: field 1 the URI, field 2 the
/// discriminant (omitted when zero, as proto3 does).
std::vector<uint8_t> encodeEndpoint(const std::string& uri, uint8_t protocol) {
  std::vector<uint8_t> out{0x0A, static_cast<uint8_t>(uri.size())};
  out.insert(out.end(), uri.begin(), uri.end());
  if (protocol != 0) {
    out.push_back(0x10);
    out.push_back(protocol);
  }
  return out;
}

/// The framing the transport callback receives: each entry preceded by its
/// varint length.
std::vector<uint8_t> frame(const std::vector<std::vector<uint8_t>>& entries) {
  std::vector<uint8_t> out;
  for (const auto& entry : entries) {
    out.push_back(static_cast<uint8_t>(entry.size()));
    out.insert(out.end(), entry.begin(), entry.end());
  }
  return out;
}

int32_t discriminant(const std::string& name) {
  return derec_transport_protocol_discriminant(reinterpret_cast<const uint8_t*>(name.data()),
                                               name.size());
}

/// `derec_protocol_new`'s error code for a config advertising one endpoint.
/// The callback pointers are null: transport validation runs before they are
/// read, so a config that passes it fails on them instead.
int32_t protocolNewCode(const std::string& uri, int32_t protocol) {
  std::string config = "{\"secret_id\":\"7\",\"own_transports\":[{\"uri\":\"" + uri +
                       "\",\"protocol\":" + std::to_string(protocol) + "}]}";
  DeRecProtocolNewResult result =
      derec_protocol_new(reinterpret_cast<const uint8_t*>(config.data()), config.size(), nullptr,
                         0, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
  int32_t code = result.error.code;
  derec_free_error(&result.error);
  if (result.handle != nullptr) {
    derec_protocol_free(result.handle);
  }
  return code;
}

}  // namespace

static void shareRecordKeepsItsOwnSecretId() {
  // On a helper the partition id and the share's `secret_id` differ; the
  // record's own value must be what the JavaScript store receives.
  auto json = bytesOf(
      "{\"secret_id\":\"18446744073709551615\",\"version\":3,\"bytes\":[1,2,255]}");
  auto decoded = decodeShareRecord(json.data(), json.size());
  expect(decoded.has_value(), "a complete share record decodes");
  if (!decoded) return;
  expect(decoded->secretId == "18446744073709551615",
         "share secretId is the record's secret_id, verbatim");
  expect(decoded->version == 3, "share version decodes");
  expect(decoded->bytes == std::vector<uint8_t>({1, 2, 255}), "share bytes decode");
}

static void shareRecordWithoutSecretIdIsRejected() {
  auto json = bytesOf("{\"version\":3,\"bytes\":[1]}");
  expect(!decodeShareRecord(json.data(), json.size()).has_value(),
         "a share record missing secret_id does not decode");
}

static void grpcEndpointIsNamedGrpc() {
  auto framed = frame({encodeEndpoint("grpcs://helper.example:443", 1)});
  auto endpoints = decodeTransportEndpoints(framed.data(), framed.size());
  expect(endpoints.has_value(), "a gRPC endpoint decodes");
  if (!endpoints) return;
  expect(endpoints->size() == 1, "one endpoint");
  expect((*endpoints)[0].protocol == "grpc", "discriminant 1 reaches Transport.send as \"grpc\"");
  expect((*endpoints)[0].uri == "grpcs://helper.example:443", "uri passes through");
}

static void endpointsKeepPeerOrderAndNames() {
  auto framed = frame({encodeEndpoint("https://helper.example/derec", 0),
                       encodeEndpoint("grpcs://helper.example:443", 1)});
  auto endpoints = decodeTransportEndpoints(framed.data(), framed.size());
  expect(endpoints.has_value() && endpoints->size() == 2, "both endpoints decode");
  if (!endpoints || endpoints->size() != 2) return;
  expect((*endpoints)[0].protocol == "https", "discriminant 0 is \"https\"");
  expect((*endpoints)[1].protocol == "grpc", "discriminant 1 is \"grpc\"");
}

static void undefinedDiscriminantFailsTheSend() {
  auto framed = frame({encodeEndpoint("https://helper.example/derec", 0),
                       encodeEndpoint("x://helper.example", 7)});
  expect(!decodeTransportEndpoints(framed.data(), framed.size()).has_value(),
         "an undefined discriminant fails decoding rather than reaching Transport.send");
}

static void protocolNamesComeFromRust() {
  expect(std::strcmp(derec_transport_protocol_name(0), "https") == 0, "0 is https");
  expect(std::strcmp(derec_transport_protocol_name(1), "grpc") == 0, "1 is grpc");
  expect(derec_transport_protocol_name(7) == nullptr, "7 has no name");
  expect(discriminant("grpc") == 1, "grpc is 1");
  expect(discriminant("GRPC") == 1, "GRPC is 1");
  expect(discriminant("https") == 0, "https is 0");
  expect(discriminant("bogus") == -1, "an unknown name is -1");
}

static void rustRejectsTheUnknownDiscriminant() {
  expect(protocolNewCode("grpcs://helper.example:443", discriminant("bogus")) ==
             DEREC_CODE_TRANSPORT_INVALID,
         "own_transports with an unknown protocol name is rejected by Rust");
  expect(protocolNewCode("grpcs://helper.example:443", discriminant("GRPC")) ==
             DEREC_CODE_FFI_NULL_PTR,
         "own_transports with GRPC passes Rust's transport validation");
}

int main() {
  derec::testing::run("shareRecordKeepsItsOwnSecretId", shareRecordKeepsItsOwnSecretId);
  derec::testing::run("shareRecordWithoutSecretIdIsRejected",
                      shareRecordWithoutSecretIdIsRejected);
  derec::testing::run("grpcEndpointIsNamedGrpc", grpcEndpointIsNamedGrpc);
  derec::testing::run("endpointsKeepPeerOrderAndNames", endpointsKeepPeerOrderAndNames);
  derec::testing::run("undefinedDiscriminantFailsTheSend", undefinedDiscriminantFailsTheSend);
  derec::testing::run("protocolNamesComeFromRust", protocolNamesComeFromRust);
  derec::testing::run("rustRejectsTheUnknownDiscriminant", rustRejectsTheUnknownDiscriminant);
  return derec::testing::summary();
}
