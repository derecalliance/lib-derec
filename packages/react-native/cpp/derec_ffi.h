// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.
//
// GENERATED FILE - DO NOT EDIT.
// Regenerate with: scripts/prepare-react-native-package.sh

#ifndef DEREC_FFI_H
#define DEREC_FFI_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * `share` bytes carry a **full `Secret` payload** (`DeRecSecret` proto)
 * instead of a single VSS share fragment. Used on replica channels —
 * every replica holds an identical copy of the secret rather than a
 * reconstructable fragment of it.
 *
 * Disambiguates the payload semantics on the wire; the receiver's
 * `Channel.peer_role` is the authoritative source of truth, but a distinct
 * `share_algorithm` value lets wire dumps and middle-boxes tell the two
 * payload shapes apart without channel-state context.
 */
#define SHARE_ALGORITHM_REPLICA_SECRET 1

/**
 * Latest encoding major version, used for all new encodes. Bump only on a
 * breaking format change, adding the matching `vN` module and match arm.
 */
#define LATEST 2

/**
 * Minimum number of shares required to reconstruct the secret, absent an
 * explicit [`DeRecProtocolBuilder::with_threshold`] call. This is the sole
 * definition of the value — [`DeRecProtocolBuilder::new`] and the FFI
 * config's serde default both read it rather than each hardcoding `3`.
 */
#define DEFAULT_THRESHOLD 3

/**
 * Number of recent share versions each helper retains, absent an explicit
 * [`DeRecProtocolBuilder::with_keep_versions_count`] call. Sole definition
 * of the value; see [`DEFAULT_THRESHOLD`].
 */
#define DEFAULT_KEEP_VERSIONS_COUNT 3

/**
 * Maximum accepted transport URI length, in bytes.
 *
 * Matches the de-facto 2048-byte limit most HTTP stacks enforce
 * for request URIs. Pairing payloads embed the URI verbatim, so
 * capping it also bounds the propagated blob size.
 */
#define MAX_TRANSPORT_URI_LEN 2048

#define DEREC_CATEGORY_OK 0

#define DEREC_CATEGORY_FFI 1

#define DEREC_CATEGORY_PAIRING 2

#define DEREC_CATEGORY_SHARING 3

#define DEREC_CATEGORY_RECOVERY 4

#define DEREC_CATEGORY_VERIFICATION 5

#define DEREC_CATEGORY_DISCOVERY 6

#define DEREC_CATEGORY_UNPAIRING 7

#define DEREC_CATEGORY_DEREC_MESSAGE 8

#define DEREC_CATEGORY_SECRET_STORE 9

#define DEREC_CATEGORY_CHANNEL_STORE 10

#define DEREC_CATEGORY_SHARE_STORE 11

#define DEREC_CATEGORY_INVALID_INPUT 12

#define DEREC_CATEGORY_PROTOBUF 13

#define DEREC_CATEGORY_INVARIANT 14

#define DEREC_CATEGORY_STATE_STORE 15

#define DEREC_CODE_OK 0

#define DEREC_CODE_NON_OK_STATUS 1

#define DEREC_CODE_VERSION_MISMATCH 2

#define DEREC_CODE_INVARIANT 3

#define DEREC_CODE_INVALID_INPUT 4

#define DEREC_CODE_PROTOBUF_DECODE 5

#define DEREC_CODE_PROTOBUF_ENCODE 6

#define DEREC_CODE_PROTOCOL_VIOLATION 7

#define DEREC_CODE_STORE_ERROR 8

#define DEREC_CODE_BUILDER_ERROR 9

/**
 * `SecretStore::load_many(.., MissingPolicy::Fail)` returned because one or
 * more channels had no `SharedKey` entry. The formatted `message` carries
 * the missing channel ids (e.g. `"secret store: missing SharedKey entries
 * for channel(s): [42, 7]"`). `category` is
 * [`DEREC_CATEGORY_SECRET_STORE`].
 */
#define DEREC_CODE_MISSING_SHARED_KEY 10

/**
 * Flow or inbound message attempted against a channel where this node holds
 * the wrong [`derec_proto::SenderKind`]. Surfaced as
 * [`DEREC_CATEGORY_INVALID_INPUT`].
 */
#define DEREC_CODE_ROLE_MISMATCH 11

/**
 * The protocol was constructed without `with_replica_id(..)` but a
 * replica-mode flow was attempted. Returned by every entry point that
 * requires local replica identity. `DEREC_CATEGORY_INVALID_INPUT`.
 */
#define DEREC_CODE_REPLICA_ID_NOT_CONFIGURED 12

/**
 * `start(Pairing)` was called for a `channel_id` that already has a
 * `Paired` channel record. Returned by both the inline-keys and
 * hashed-keys branches of `start`. `DEREC_CATEGORY_INVALID_INPUT`.
 */
#define DEREC_CODE_CHANNEL_ALREADY_PAIRED 13

/**
 * `derec_protocol_restore` precondition: a `UserSecrets` snapshot
 * already exists for the protocol's `secret_id`. The application must
 * clear it before retrying. `DEREC_CATEGORY_INVALID_INPUT`.
 */
#define DEREC_CODE_ALREADY_RESTORED 14

/**
 * `derec_protocol_restore` precondition: one or more channels live at
 * canonical helper / replica ids carried by the recovered `Secret`.
 * `DeRecError::message` formats the collision list as
 * `"restore conflict: channel(s) [a, b, ...]"`.
 * `DEREC_CATEGORY_INVALID_INPUT`.
 */
#define DEREC_CODE_RESTORE_CONFLICT 15

/**
 * A replica pairing named a `replica_id` already held by another member of
 * the group, this device included. Assignment is the application's, so this
 * is a configuration fault: assign a distinct id and pair again.
 * `DEREC_CATEGORY_INVALID_INPUT`.
 */
#define DEREC_CODE_REPLICA_ID_CONFLICT 16

#define DEREC_CODE_ENCRYPTION 20

#define DEREC_CODE_KEYGEN 21

#define DEREC_CODE_FINISH_PAIRING_INITIATOR 22

#define DEREC_CODE_FINISH_PAIRING_RESPONDER 23

#define DEREC_CODE_EMPTY_TRANSPORT_URI 40

#define DEREC_CODE_INVALID_CONTACT_MESSAGE 41

#define DEREC_CODE_INVALID_PAIR_REQUEST_MESSAGE 42

#define DEREC_CODE_INVALID_PAIR_RESPONSE_MESSAGE 43

/**
 * `HashedKeys` pairing — the scanner recomputed the SHA-384 binding hash
 * over the public keys published in `PrePairResponseMessage` and got a
 * digest that doesn't match `ContactMessage.contactBindingHash`. Surfaced
 * as [`DEREC_CATEGORY_PAIRING`]. Distinct from a generic
 * [`DEREC_CODE_PROTOCOL_VIOLATION`] so applications can flag this with
 * the security-relevant framing it deserves (the contact the user
 * scanned does not match the keys they would pair with).
 */
#define DEREC_CODE_PREPAIR_HASH_MISMATCH 44

/**
 * A replica-mode pairing arrived without the reserved
 * `derec.replica_id` key in `CommunicationInfo`.
 * `DEREC_CATEGORY_PAIRING`.
 */
#define DEREC_CODE_MISSING_REPLICA_ID 45

/**
 * A non-replica pairing carried the reserved `derec.replica_id` key in
 * `CommunicationInfo`. `DEREC_CATEGORY_PAIRING`.
 */
#define DEREC_CODE_UNEXPECTED_REPLICA_ID 46

/**
 * The peer's [`derec_proto::ParameterRange`] does not overlap the
 * locally-configured one on some field (e.g. `local.minShareSize >
 * peer.maxShareSize`). `DEREC_CATEGORY_PAIRING`. The
 * [`DeRecError::message`](DeRecError) carries the field name and
 * both `(min, max)` pairs.
 */
#define DEREC_CODE_INCOMPATIBLE_PARAMETER_RANGE 47

#define DEREC_CODE_EMPTY_CHANNELS 60

#define DEREC_CODE_DUPLICATE_CHANNEL_ID 61

#define DEREC_CODE_INVALID_THRESHOLD 62

#define DEREC_CODE_EMPTY_SECRET_DATA 63

#define DEREC_CODE_VSS_SHARE_FAILED 64

#define DEREC_CODE_EMPTY_RESPONSES 80

#define DEREC_CODE_EMPTY_COMMITTED_DEREC_SHARE 81

#define DEREC_CODE_DECODE_COMMITTED_DEREC_SHARE 82

#define DEREC_CODE_DECODE_DEREC_SHARE 83

#define DEREC_CODE_SECRET_ID_MISMATCH 84

#define DEREC_CODE_RECONSTRUCTION_FAILED 85

/**
 * VSS reconstruction succeeded but the resulting bytes did not decode as
 * the canonical `DeRecSecret` / `Secret` protobuf. Almost always a sign
 * of share corruption.
 */
#define DEREC_CODE_MALFORMED_RECOVERED_SECRET 86

#define DEREC_CODE_FFI_NULL_PTR 100

#define DEREC_CODE_FFI_BAD_LENGTH 101

#define DEREC_CODE_FFI_BAD_UTF8 102

#define DEREC_CODE_FFI_BAD_PROTO 103

#define DEREC_CODE_FFI_INVALID_ENUM 104

#define DEREC_CODE_FFI_BAD_SHARED_KEY 105

#define DEREC_CODE_FFI_NUL_IN_STRING 106

/**
 * Transport URI/protocol pair failed [`crate::transport::validate`]:
 * length cap, control character, unknown protocol discriminant, or
 * URI scheme that doesn't match the declared `Protocol`. Surfaced
 * as [`DEREC_CATEGORY_INVALID_INPUT`]. The
 * [`DeRecError::message`](DeRecError) carries the specific reason.
 */
#define DEREC_CODE_TRANSPORT_INVALID 120

/**
 * Discriminants selecting which message [`derec_decode_message_json`] and
 * [`derec_encode_message_json`] operate on.
 *
 * Mirrored in the shared enum fixture, which every SDK asserts against, so a
 * message added here cannot reach a binding as a silently unhandled value.
 */
#define DEREC_MESSAGE_KIND_PAIR_REQUEST 0

#define DEREC_MESSAGE_KIND_PAIR_RESPONSE 1

#define DEREC_MESSAGE_KIND_PRE_PAIR_REQUEST 2

#define DEREC_MESSAGE_KIND_PRE_PAIR_RESPONSE 3

#define DEREC_MESSAGE_KIND_GET_SECRET_IDS_VERSIONS_REQUEST 4

#define DEREC_MESSAGE_KIND_GET_SECRET_IDS_VERSIONS_RESPONSE 5

#define DEREC_MESSAGE_KIND_GET_SHARE_REQUEST 6

#define DEREC_MESSAGE_KIND_GET_SHARE_RESPONSE 7

#define DEREC_MESSAGE_KIND_STORE_SHARE_REQUEST 8

#define DEREC_MESSAGE_KIND_STORE_SHARE_RESPONSE 9

#define DEREC_MESSAGE_KIND_UNPAIR_REQUEST 10

#define DEREC_MESSAGE_KIND_UNPAIR_RESPONSE 11

#define DEREC_MESSAGE_KIND_VERIFY_SHARE_REQUEST 12

#define DEREC_MESSAGE_KIND_VERIFY_SHARE_RESPONSE 13

/**
 * Not a standalone message on the wire, but it crosses this FFI on its own
 * as the `transport_protocol` argument of `create_contact_message` and the
 * `peer_transport_protocol` result of `produce_pair_response_message`.
 */
#define DEREC_MESSAGE_KIND_TRANSPORT_PROTOCOL 14

/**
 * Crosses on its own as the `communication_info` argument of the pairing
 * produce calls. See [`DEREC_MESSAGE_KIND_TRANSPORT_PROTOCOL`].
 */
#define DEREC_MESSAGE_KIND_COMMUNICATION_INFO 15

/**
 * Crosses on its own as the `parameter_range` argument of the pairing
 * produce calls. See [`DEREC_MESSAGE_KIND_TRANSPORT_PROTOCOL`].
 */
#define DEREC_MESSAGE_KIND_PARAMETER_RANGE 16

/**
 * Crosses on its own as the `committed_share` argument of
 * `produce_store_share_request_message` and as the `committed_share_bytes`
 * result of `produce_store_share_response_message`.
 */
#define DEREC_MESSAGE_KIND_COMMITTED_DEREC_SHARE 17

/**
 * Numeric flow-kind identifiers — must match the dotnet `FlowKind` enum.
 */
#define FLOW_KIND_PAIRING 0

#define FLOW_KIND_DISCOVERY 1

#define FLOW_KIND_PROTECT_SECRET 2

#define FLOW_KIND_VERIFY_SHARES 3

#define FLOW_KIND_RECOVER_SECRET 4

#define FLOW_KIND_UNPAIR 5

#define FLOW_KIND_UPDATE_CHANNEL_INFO 6

/**
 * Replica catch-up. Takes no parameters: the group and this device's own
 * version are both read from the stores.
 */
#define FLOW_KIND_SYNC_CHECK 7

/**
 * Remove a member from the replica group. Params:
 * `{ "replica_id": "<decimal>", "memo": "<optional>" }`.
 */
#define FLOW_KIND_REMOVE_REPLICA 8

/**
 * Opaque handle returned by [`derec_protocol_new`] and consumed by
 * every other entry point in this module. Holds the protocol instance + the
 * per-handle tokio runtime used to drive the async core synchronously.
 *
 * The `inner` protocol is wrapped in [`std::sync::Mutex`] so concurrent
 * FFI calls from different host threads (.NET worker pool, Node.js
 * worker_threads, etc.) are safe by construction. Each entry point
 * locks the mutex for the duration of its call, serializing access to
 * the protocol state — no `&mut DeRecProtocolHandle` is ever
 * materialized, so aliased `&mut` references (which would be immediate
 * undefined behavior) cannot arise even under contention. The tokio
 * `Runtime` itself is `Sync` and accepts `&self` `block_on`, but
 * holding the protocol lock across `block_on` also serializes runtime
 * invocations on the current-thread executor.
 */
typedef struct DeRecProtocolHandle DeRecProtocolHandle;

/**
 * DeRec protocol version supported by this SDK.
 *
 * This type represents the protocol-level version carried in the
 * [`DeRecMessage`](derec_proto::DeRecMessage) envelope:
 *
 * - `protocolVersionMajor`
 * - `protocolVersionMinor`
 *
 * This is **not** the same as the Rust crate version, npm package version,
 * or NuGet package version. Package versions identify SDK releases, while
 * `ProtocolVersion` identifies the DeRec wire protocol version expected by
 * protocol messages.
 *
 * # Fields
 *
 * * `major` - Protocol major version.
 * * `minor` - Protocol minor version.
 *
 * # Compatibility
 *
 * The compatibility policy associated with protocol major/minor versions is
 * defined by the DeRec protocol specification, not by this helper type.
 *
 * # Example
 *
 * ```rust
 * use derec_library::protocol_version::ProtocolVersion;
 *
 * let version = ProtocolVersion::current();
 *
 * assert!(version.major >= 0);
 * assert!(version.minor >= 0);
 * ```
 */
typedef struct ProtocolVersion ProtocolVersion;

typedef struct DeRecError {
  int32_t category;
  int32_t code;
  /**
   * Owned C string. Null on success. Released by [`derec_free_error`].
   */
  char *message;
  /**
   * Valid when `code == DEREC_CODE_NON_OK_STATUS`.
   */
  int32_t peer_status;
  /**
   * Owned C string. Null when not applicable. Released by [`derec_free_error`].
   */
  char *peer_memo;
  /**
   * Valid when `code == DEREC_CODE_VERSION_MISMATCH`.
   */
  uint32_t expected;
  /**
   * Valid when `code == DEREC_CODE_VERSION_MISMATCH`.
   */
  uint32_t got;
} DeRecError;

typedef struct DeRecBuffer {
  uint8_t *ptr;
  size_t len;
} DeRecBuffer;

typedef struct ProduceGetSecretIdsVersionsRequestMessageResult {
  struct DeRecError error;
  struct DeRecBuffer envelope_wire_bytes;
} ProduceGetSecretIdsVersionsRequestMessageResult;

typedef struct ExtractGetSecretIdsVersionsRequestResult {
  struct DeRecError error;
  uint64_t channel_id;
  /**
   * prost-encoded inner `GetSecretIdsVersionsRequestMessage` bytes.
   * Empty buffer when extraction fails. SDK consumers decode this
   * to inspect optional fields such as `reply_to`.
   */
  struct DeRecBuffer request_proto_bytes;
} ExtractGetSecretIdsVersionsRequestResult;

typedef struct ProduceGetSecretIdsVersionsResponseMessageResult {
  struct DeRecError error;
  struct DeRecBuffer envelope_wire_bytes;
} ProduceGetSecretIdsVersionsResponseMessageResult;

typedef struct ExtractGetSecretIdsVersionsResponseResult {
  struct DeRecError error;
  uint64_t channel_id;
  /**
   * Inner `GetSecretIdsVersionsResponseMessage` proto bytes for chaining
   * into [`process_get_secret_ids_versions_response_message`].
   */
  struct DeRecBuffer response_proto_bytes;
} ExtractGetSecretIdsVersionsResponseResult;

typedef struct ProcessGetSecretIdsVersionsResponseMessageResult {
  struct DeRecError error;
  /**
   * Validated secret list in the format documented at the module level.
   */
  struct DeRecBuffer secret_list_bytes;
} ProcessGetSecretIdsVersionsResponseMessageResult;

typedef struct ApplyTraceIdResult {
  struct DeRecError error;
  /**
   * Re-encoded envelope bytes with `trace_id` overwritten. Empty on error.
   */
  struct DeRecBuffer wire_bytes;
} ApplyTraceIdResult;

typedef struct ReadTraceIdResult {
  struct DeRecError error;
  /**
   * Trace id read off the envelope. Zero on error (also zero if the
   * sender did not set one — the protobuf default is indistinguishable).
   */
  uint64_t trace_id;
} ReadTraceIdResult;

/**
 * Result of a message JSON codec call. `bytes` is UTF-8 JSON for
 * [`derec_decode_message_json`] and protobuf wire bytes for
 * [`derec_encode_message_json`]; it is empty when `error` is non-zero.
 */
typedef struct DeRecMessageJsonResult {
  struct DeRecError error;
  struct DeRecBuffer bytes;
} DeRecMessageJsonResult;

typedef struct CreateContactMessageResult {
  struct DeRecError error;
  struct DeRecBuffer contact_wire_bytes;
  /**
   * Opaque pairing secret key material. See module docs.
   */
  struct DeRecBuffer secret_key_material;
} CreateContactMessageResult;

typedef struct EncodeContactMessageResult {
  struct DeRecError error;
  /**
   * Proto-encoded `ContactMessage`, ready to publish out of band.
   */
  struct DeRecBuffer wire_bytes;
} EncodeContactMessageResult;

typedef struct DecodeContactMessageResult {
  struct DeRecError error;
  /**
   * UTF-8 JSON object. See [`encode_contact_message`] for the shape.
   */
  struct DeRecBuffer contact_json;
} DecodeContactMessageResult;

typedef struct ProducePairRequestMessageResult {
  struct DeRecError error;
  struct DeRecBuffer request_wire_bytes;
  struct DeRecBuffer initiator_contact_message_wire_bytes;
  /**
   * Opaque pairing secret key material. See module docs.
   */
  struct DeRecBuffer secret_key_material;
} ProducePairRequestMessageResult;

typedef struct ExtractPairRequestResult {
  struct DeRecError error;
  uint64_t channel_id;
  /**
   * Inner `PairRequestMessage` proto bytes for chaining into
   * [`produce_pair_response_message`].
   */
  struct DeRecBuffer request_proto_bytes;
} ExtractPairRequestResult;

typedef struct ProducePairResponseMessageResult {
  struct DeRecError error;
  struct DeRecBuffer response_wire_bytes;
  struct DeRecBuffer peer_transport_protocol;
  struct DeRecBuffer shared_key;
  /**
   * Post-handshake rekey channel id the responder is committing to.
   * Callers MUST atomically rename their local channel record from the
   * pre-rekey id (the one passed to `produce_pair_response_message`) to
   * this value as part of accepting the response. Zero on error.
   */
  uint64_t channel_id;
} ProducePairResponseMessageResult;

typedef struct ExtractPairResponseResult {
  struct DeRecError error;
  uint64_t channel_id;
  /**
   * Inner `PairResponseMessage` proto bytes for chaining into
   * [`process_pair_response_message`].
   */
  struct DeRecBuffer response_proto_bytes;
} ExtractPairResponseResult;

/**
 * `shared_key` is populated only on success; empty on peer rejection (see
 * [`crate::interop::ffi::error`]).
 */
typedef struct ProcessPairResponseMessageResult {
  struct DeRecError error;
  struct DeRecBuffer shared_key;
  /**
   * Post-handshake rekey channel id — already validated against the
   * caller's own derivation. Callers MUST atomically rename their local
   * channel record from the pre-rekey id (the one in the contact) to
   * this value. Zero on error.
   */
  uint64_t channel_id;
} ProcessPairResponseMessageResult;

typedef struct ProducePrePairRequestMessageResult {
  struct DeRecError error;
  /**
   * Serialized outer plaintext `DeRecMessage` envelope carrying a
   * `PrePairRequestMessage`. Ready to send over transport.
   */
  struct DeRecBuffer envelope_wire_bytes;
} ProducePrePairRequestMessageResult;

typedef struct ExtractPrePairRequestResult {
  struct DeRecError error;
  /**
   * Channel identifier decoded from the outer envelope's routing field.
   */
  uint64_t channel_id;
  /**
   * Inner `PrePairRequestMessage` proto bytes for chaining into
   * [`produce_pre_pair_response_message`].
   */
  struct DeRecBuffer request_proto_bytes;
} ExtractPrePairRequestResult;

typedef struct ProducePrePairResponseMessageResult {
  struct DeRecError error;
  /**
   * Serialized outer plaintext `DeRecMessage` envelope carrying a
   * `PrePairResponseMessage`. Ready to send over transport.
   */
  struct DeRecBuffer envelope_wire_bytes;
} ProducePrePairResponseMessageResult;

typedef struct ExtractPrePairResponseResult {
  struct DeRecError error;
  /**
   * Channel identifier decoded from the outer envelope's routing field.
   */
  uint64_t channel_id;
  /**
   * Inner `PrePairResponseMessage` proto bytes for chaining into
   * [`process_pre_pair_response_message`].
   */
  struct DeRecBuffer response_proto_bytes;
} ExtractPrePairResponseResult;

/**
 * On success the two key buffers hold the validated public keys republished
 * by the contact creator. On failure (status non-Ok, hash mismatch, etc.)
 * both buffers are empty; consult `error`.
 */
typedef struct ProcessPrePairResponseMessageResult {
  struct DeRecError error;
  struct DeRecBuffer mlkem_encapsulation_key;
  struct DeRecBuffer ecies_public_key;
  /**
   * Nonce echoed from the original `ContactMessage`. Zero on failure.
   */
  uint64_t nonce;
} ProcessPrePairResponseMessageResult;

/**
 * Result type for [`derec_protocol_new`].
 */
typedef struct DeRecProtocolNewResult {
  struct DeRecError error;
  /**
   * On success, the opaque handle. On error, null.
   */
  struct DeRecProtocolHandle *handle;
} DeRecProtocolNewResult;

/**
 * Caller-supplied callbacks for channel persistence.
 *
 * All function pointers are invoked synchronously from the protocol's
 * async core (the FFI shim drives futures with `block_on`). Buffer
 * ownership for any byte payload returned via out-parameters belongs
 * to the caller; the shim copies into a Rust `Vec` and then calls
 * [`Self::free_buffer`] to release the original allocation.
 *
 * Return code convention:
 * - `0` on success
 * - `1` on "not found" (only meaningful for `load`)
 * - any other value indicates a backend failure; the shim wraps it as
 *   [`ChannelStoreError::Backend`]
 *
 * # Addressing a record
 *
 * `load`, `save` and `remove` take a `(channel_id, replica_id)` pair. A
 * `replica_id` of `0` — the value [`crate::types::ReplicaId`] reserves as
 * "absent" — addresses the helper channel at `channel_id`.
 *
 * Any other value addresses that member of the replica group, and the member
 * is keyed by **`replica_id` alone**. The accompanying `channel_id` is
 * context, not part of the key: a member moves between channels during an
 * admission handover while remaining the same member, and a lookup that
 * required both to match would miss it exactly when the move needs to be
 * observed. Backends therefore keep two maps — helpers by `channel_id`,
 * members by `replica_id` — not one keyed by the pair.
 *
 * The `bytes` payload of `save`, and the buffer `load` returns, are a
 * JSON-encoded [`crate::protocol::types::ChannelRecord`]. `list_helpers` and
 * `list_replicas` return a JSON array of
 * [`crate::protocol::types::HelperChannel`] and
 * [`crate::protocol::types::ReplicaMember`] respectively.
 *
 * The order `list_replicas` returns is significant in exactly one situation —
 * it selects the successor when the group's source is removed. See
 * [`crate::protocol::DeRecChannelStore::replicas`] for the full contract.
 */
typedef struct ChannelStoreCallbacks {
  void *user_data;
  int32_t (*load)(void *user_data,
                  uint64_t secret_id,
                  uint64_t channel_id,
                  uint64_t replica_id,
                  uint8_t **out_ptr,
                  size_t *out_len);
  int32_t (*save)(void *user_data,
                  uint64_t secret_id,
                  uint64_t channel_id,
                  uint64_t replica_id,
                  const uint8_t *bytes,
                  size_t len);
  int32_t (*remove)(void *user_data,
                    uint64_t secret_id,
                    uint64_t channel_id,
                    uint64_t replica_id,
                    uint32_t *out_existed);
  int32_t (*list_helpers)(void *user_data, uint64_t secret_id, uint8_t **out_ptr, size_t *out_len);
  int32_t (*list_replicas)(void *user_data, uint64_t secret_id, uint8_t **out_ptr, size_t *out_len);
  int32_t (*link_channel)(void *user_data, uint64_t secret_id, uint64_t a, uint64_t b);
  int32_t (*linked_channels)(void *user_data,
                             uint64_t secret_id,
                             uint64_t channel_id,
                             uint8_t **out_ptr,
                             size_t *out_len);
  void (*free_buffer)(void *user_data, uint8_t *ptr, size_t len);
} ChannelStoreCallbacks;

/**
 * Caller-supplied callbacks for secret persistence.
 */
typedef struct SecretStoreCallbacks {
  void *user_data;
  int32_t (*load)(void *user_data,
                  uint64_t secret_id,
                  uint64_t channel_id,
                  uint32_t kind,
                  uint8_t **out_ptr,
                  size_t *out_len);
  int32_t (*save)(void *user_data,
                  uint64_t secret_id,
                  uint64_t channel_id,
                  uint32_t kind,
                  const uint8_t *bytes,
                  size_t len);
  int32_t (*remove)(void *user_data, uint64_t secret_id, uint64_t channel_id, uint32_t kind);
  void (*free_buffer)(void *user_data, uint8_t *ptr, size_t len);
} SecretStoreCallbacks;

/**
 * Caller-supplied callbacks for share persistence. Variable-length
 * arrays (`channel_ids[]`, `versions[]`) cross the FFI as JSON
 * strings, matching the `Vec<u8>` ↔ JSON-array convention used for
 * every other wire-format buffer in this module.
 */
typedef struct ShareStoreCallbacks {
  void *user_data;
  int32_t (*load)(void *user_data,
                  uint64_t secret_id,
                  uint64_t channel_id,
                  const uint8_t *versions_json_ptr,
                  size_t versions_json_len,
                  uint8_t **out_ptr,
                  size_t *out_len);
  int32_t (*load_many)(void *user_data,
                       uint64_t secret_id,
                       const uint8_t *channel_ids_json_ptr,
                       size_t channel_ids_json_len,
                       const uint8_t *versions_json_ptr,
                       size_t versions_json_len,
                       uint8_t **out_ptr,
                       size_t *out_len);
  int32_t (*load_all)(void *user_data,
                      uint64_t secret_id,
                      const uint8_t *channel_ids_json_ptr,
                      size_t channel_ids_json_len,
                      uint8_t **out_ptr,
                      size_t *out_len);
  int32_t (*latest_version)(void *user_data,
                            uint64_t secret_id,
                            uint32_t *out_has_version,
                            uint32_t *out_version);
  int32_t (*save)(void *user_data,
                  uint64_t secret_id,
                  uint64_t channel_id,
                  const uint8_t *share_json_ptr,
                  size_t share_json_len);
  int32_t (*remove_channel)(void *user_data, uint64_t secret_id, uint64_t channel_id);
  void (*free_buffer)(void *user_data, uint8_t *ptr, size_t len);
} ShareStoreCallbacks;

/**
 * Caller-supplied callbacks for the user-secret store. Methods cross
 * the FFI keyed by `secret_id`; the `UserSecrets` payload travels as a
 * JSON buffer matching [`UserSecretsRecord`].
 */
typedef struct UserSecretStoreCallbacks {
  void *user_data;
  /**
   * `load_latest(secret_id, out_ptr, out_len)` — writes the JSON
   * payload (or `out_len = 0` if absent). Caller releases the buffer
   * via `free_buffer`.
   */
  int32_t (*load_latest)(void *user_data, uint64_t secret_id, uint8_t **out_ptr, size_t *out_len);
  /**
   * `save_latest(secret_id, value_json_ptr, value_json_len)`.
   */
  int32_t (*save_latest)(void *user_data,
                         uint64_t secret_id,
                         const uint8_t *value_json_ptr,
                         size_t value_json_len);
  /**
   * `remove(secret_id)` — idempotent.
   */
  int32_t (*remove)(void *user_data, uint64_t secret_id);
  void (*free_buffer)(void *user_data, uint8_t *ptr, size_t len);
} UserSecretStoreCallbacks;

/**
 * Caller-supplied callbacks for orchestrator in-flight state
 * ([`DeRecStateStore`]). The item and key travel as JSON buffers
 * matching [`StateItemRecord`] / [`StateKeyRecord`].
 *
 * # Return codes
 *
 * - `load`: `0` = found (record written), `1` = not found (empty
 *   payload), other = backend failure.
 * - `remove`: `0` = ok (`*out_removed` set to `0` or `1`), other =
 *   backend failure.
 * - `save` / `load_all`: `0` = ok, other = backend failure.
 */
typedef struct StateStoreCallbacks {
  void *user_data;
  int32_t (*save)(void *user_data,
                  uint64_t secret_id,
                  const uint8_t *item_json_ptr,
                  size_t item_json_len);
  int32_t (*load)(void *user_data,
                  uint64_t secret_id,
                  const uint8_t *key_json_ptr,
                  size_t key_json_len,
                  uint8_t **out_ptr,
                  size_t *out_len);
  int32_t (*remove)(void *user_data,
                    uint64_t secret_id,
                    const uint8_t *key_json_ptr,
                    size_t key_json_len,
                    uint32_t *out_removed);
  int32_t (*load_all)(void *user_data,
                      uint64_t secret_id,
                      uint32_t kind,
                      uint8_t **out_ptr,
                      size_t *out_len);
  void (*free_buffer)(void *user_data, uint8_t *ptr, size_t len);
} StateStoreCallbacks;

/**
 * Caller-supplied transport callback.
 */
typedef struct TransportCallbacks {
  void *user_data;
  int32_t (*send)(void *user_data,
                  const uint8_t *uri_ptr,
                  size_t uri_len,
                  int32_t protocol,
                  const uint8_t *bytes,
                  size_t len);
} TransportCallbacks;

/**
 * Result type for [`derec_protocol_remove_expired_channels`].
 */
typedef struct DeRecRemovedChannelsResult {
  struct DeRecError error;
  /**
   * On success, a heap-owned UTF-8 JSON array of removed channel ids as
   * decimal strings — e.g. `["12","4096"]`. Decimal strings rather than
   * JSON numbers because `u64` ids exceed `Number.MAX_SAFE_INTEGER`;
   * this matches every other id crossing this boundary. Caller releases
   * via [`crate::interop::ffi::common::derec_free_buffer`].
   */
  struct DeRecBuffer channels;
} DeRecRemovedChannelsResult;

/**
 * Result type for entry points that return a `Vec<DeRecEvent>`.
 */
typedef struct DeRecProtocolEventsResult {
  struct DeRecError error;
  /**
   * UTF-8 JSON array of events. See [`crate::interop::ffi::protocol::events`]
   * for the per-variant shape. Caller releases via
   * [`crate::interop::ffi::derec_free_buffer`].
   */
  struct DeRecBuffer events_json;
} DeRecProtocolEventsResult;

/**
 * Result type for fingerprint accessors.
 */
typedef struct DeRecProtocolFingerprintResult {
  struct DeRecError error;
  /**
   * On success, owned C string (heap-allocated). Caller releases via
   * [`crate::interop::ffi::common::derec_free_string`].
   */
  char *fingerprint;
} DeRecProtocolFingerprintResult;

/**
 * Result type for [`derec_protocol_create_contact`].
 */
typedef struct DeRecProtocolCreateContactResult {
  struct DeRecError error;
  /**
   * prost-encoded [`derec_proto::ContactMessage`] on success.
   * Caller releases via [`crate::interop::ffi::derec_free_buffer`].
   */
  struct DeRecBuffer contact_wire_bytes;
} DeRecProtocolCreateContactResult;

typedef struct DeRecProtocolVersion {
  uint32_t major;
  uint32_t minor;
} DeRecProtocolVersion;

typedef struct ProduceGetShareRequestMessageResult {
  struct DeRecError error;
  struct DeRecBuffer request_wire_bytes;
} ProduceGetShareRequestMessageResult;

typedef struct ExtractGetShareRequestResult {
  struct DeRecError error;
  uint64_t channel_id;
  /**
   * Inner `GetShareRequestMessage` proto bytes for chaining into
   * [`produce_get_share_response_message`].
   */
  struct DeRecBuffer request_proto_bytes;
} ExtractGetShareRequestResult;

typedef struct ProduceGetShareResponseMessageResult {
  struct DeRecError error;
  struct DeRecBuffer response_wire_bytes;
} ProduceGetShareResponseMessageResult;

typedef struct ExtractGetShareResponseResult {
  struct DeRecError error;
  uint64_t channel_id;
  /**
   * Inner `GetShareResponseMessage` proto bytes. Accumulate across helpers
   * and pass to [`recover_from_share_responses`].
   */
  struct DeRecBuffer response_proto_bytes;
} ExtractGetShareResponseResult;

typedef struct RecoverFromShareResponsesResult {
  struct DeRecError error;
  struct DeRecBuffer secret_data;
} RecoverFromShareResponsesResult;

typedef struct ProtectSecretResult {
  struct DeRecError error;
  /**
   * Committed shares in the format documented at the module level.
   */
  struct DeRecBuffer shares_wire_bytes;
} ProtectSecretResult;

typedef struct ProduceStoreShareRequestMessageResult {
  struct DeRecError error;
  struct DeRecBuffer wire_bytes;
} ProduceStoreShareRequestMessageResult;

typedef struct ExtractStoreShareRequestResult {
  struct DeRecError error;
  uint64_t channel_id;
  /**
   * Inner `StoreShareRequestMessage` proto bytes for chaining into
   * [`produce_store_share_response_message`].
   */
  struct DeRecBuffer request_proto_bytes;
} ExtractStoreShareRequestResult;

/**
 * `committed_share_bytes` is the serialized [`CommittedDeRecShare`] the
 * helper should persist locally for later recovery responses.
 */
typedef struct ProduceStoreShareResponseMessageResult {
  struct DeRecError error;
  struct DeRecBuffer wire_bytes;
  struct DeRecBuffer committed_share_bytes;
  uint64_t secret_id;
  uint32_t version;
} ProduceStoreShareResponseMessageResult;

typedef struct ExtractStoreShareResponseResult {
  struct DeRecError error;
  uint64_t channel_id;
  /**
   * Inner `StoreShareResponseMessage` proto bytes for chaining into
   * [`process_store_share_response_message`].
   */
  struct DeRecBuffer response_proto_bytes;
} ExtractStoreShareResponseResult;

typedef struct ProcessStoreShareResponseMessageResult {
  struct DeRecError error;
} ProcessStoreShareResponseMessageResult;

typedef struct ProduceUnpairRequestMessageResult {
  struct DeRecError error;
  struct DeRecBuffer request_wire_bytes;
} ProduceUnpairRequestMessageResult;

typedef struct ExtractUnpairRequestResult {
  struct DeRecError error;
  uint64_t channel_id;
  /**
   * Decrypted memo. Release with `derec_free_string`.
   */
  char *memo;
  /**
   * prost-encoded inner `UnpairRequestMessage` bytes. SDK consumers
   * decode this to inspect optional fields such as `reply_to`.
   */
  struct DeRecBuffer request_proto_bytes;
} ExtractUnpairRequestResult;

typedef struct ProduceUnpairResponseMessageResult {
  struct DeRecError error;
  struct DeRecBuffer response_wire_bytes;
} ProduceUnpairResponseMessageResult;

typedef struct ExtractUnpairResponseResult {
  struct DeRecError error;
  uint64_t channel_id;
  /**
   * Inner `UnpairResponseMessage` proto bytes for chaining into
   * [`process_unpair_response_message`].
   */
  struct DeRecBuffer response_proto_bytes;
} ExtractUnpairResponseResult;

typedef struct ProcessUnpairResponseResult {
  struct DeRecError error;
} ProcessUnpairResponseResult;

typedef struct ProduceVerifyShareRequestMessageResult {
  struct DeRecError error;
  struct DeRecBuffer request_wire_bytes;
} ProduceVerifyShareRequestMessageResult;

typedef struct ExtractVerifyShareRequestResult {
  struct DeRecError error;
  uint64_t channel_id;
  /**
   * Inner `VerifyShareRequestMessage` proto bytes for chaining into
   * [`produce_verify_share_response_message`].
   */
  struct DeRecBuffer request_proto_bytes;
} ExtractVerifyShareRequestResult;

typedef struct ProduceVerifyShareResponseMessageResult {
  struct DeRecError error;
  struct DeRecBuffer response_wire_bytes;
} ProduceVerifyShareResponseMessageResult;

typedef struct ExtractVerifyShareResponseResult {
  struct DeRecError error;
  uint64_t channel_id;
  /**
   * Inner `VerifyShareResponseMessage` proto bytes for chaining into
   * [`process_verify_share_response_message`].
   */
  struct DeRecBuffer response_proto_bytes;
} ExtractVerifyShareResponseResult;

/**
 * `is_valid` is meaningful only on success. Peer rejection surfaces on
 * `error` (see [`crate::interop::ffi::error`]).
 */
typedef struct VerifyShareResponseResult {
  struct DeRecError error;
  bool is_valid;
} VerifyShareResponseResult;



#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Releases a [`DeRecBuffer`] previously returned by the SDK.
 *
 * Safe to call with a null pointer.
 *
 * # Safety
 *
 * `ptr` must have been allocated by the DeRec SDK and `len` must match the
 * original allocation length.
 */
void derec_free_buffer(uint8_t *ptr, size_t len);

/**
 * Releases a standalone C string previously returned by the SDK.
 *
 * For strings owned by a [`crate::interop::ffi::error::DeRecError`], use
 * [`crate::interop::ffi::error::derec_free_error`] which releases both owned strings
 * in one call. Safe to call with a null pointer.
 *
 * # Safety
 *
 * `ptr` must have been allocated by the DeRec SDK.
 */
void derec_free_string(char *ptr);

/**
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct ProduceGetSecretIdsVersionsRequestMessageResult produce_get_secret_ids_versions_request_message(uint64_t channel_id,
                                                                                                       const uint8_t *shared_key_ptr,
                                                                                                       size_t shared_key_len,
                                                                                                       const uint8_t *reply_to_ptr,
                                                                                                       size_t reply_to_len);

/**
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct ExtractGetSecretIdsVersionsRequestResult extract_get_secret_ids_versions_request(const uint8_t *request_ptr,
                                                                                        size_t request_len,
                                                                                        const uint8_t *shared_key_ptr,
                                                                                        size_t shared_key_len);

/**
 * `secret_list_ptr` / `secret_list_len` must follow the binary format
 * documented at the module level.
 *
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct ProduceGetSecretIdsVersionsResponseMessageResult produce_get_secret_ids_versions_response_message(uint64_t channel_id,
                                                                                                         const uint8_t *secret_list_ptr,
                                                                                                         size_t secret_list_len,
                                                                                                         const uint8_t *shared_key_ptr,
                                                                                                         size_t shared_key_len);

/**
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct ExtractGetSecretIdsVersionsResponseResult extract_get_secret_ids_versions_response(const uint8_t *response_ptr,
                                                                                          size_t response_len,
                                                                                          const uint8_t *shared_key_ptr,
                                                                                          size_t shared_key_len);

/**
 * `response_proto_ptr` / `response_proto_len` must be the
 * `response_proto_bytes` returned by
 * [`extract_get_secret_ids_versions_response`].
 *
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct ProcessGetSecretIdsVersionsResponseMessageResult process_get_secret_ids_versions_response_message(const uint8_t *response_proto_ptr,
                                                                                                         size_t response_proto_len);

/**
 * Overwrite `trace_id` on an already-produced envelope and return the
 * re-encoded bytes.
 *
 * Mirrors [`crate::derec_message::apply_trace_id`]. Useful for FFI consumers
 * using primitives directly: the `produce_*_request_message` family emits
 * envelopes with `trace_id = 0`, so callers who want correlation produce +
 * then call this. The orchestrator does this automatically end-to-end.
 *
 * # Safety
 *
 * `envelope_ptr` must point to a readable byte range of length `envelope_len`.
 */
struct ApplyTraceIdResult apply_trace_id_to_envelope(const uint8_t *envelope_ptr,
                                                     size_t envelope_len,
                                                     uint64_t trace_id);

/**
 * Read `trace_id` off an envelope without touching the encrypted inner
 * payload. Pair with [`apply_trace_id_to_envelope`] for primitive-level
 * request/response correlation.
 *
 * # Safety
 *
 * `envelope_ptr` must point to a readable byte range of length `envelope_len`.
 */
struct ReadTraceIdResult read_trace_id_from_envelope(const uint8_t *envelope_ptr,
                                                     size_t envelope_len);

/**
 * Releases the owned strings carried by a [`DeRecError`]. After
 * returning, `error.message` and `error.peer_memo` are both null —
 * an accidental second call is a safe no-op.
 *
 * # Safety
 *
 * `error` must either be null (in which case this function is a
 * no-op) or point to a fully-initialized [`DeRecError`] produced by
 * the DeRec SDK. The function takes the value by pointer so it can
 * null out `message` and `peer_memo` after freeing them, neutralizing
 * the obvious double-free vector that a by-value signature creates
 * — callers that re-invoke `derec_free_error` on the same struct
 * then see a null-pointer no-op instead of corrupting the heap.
 */
void derec_free_error(struct DeRecError *error);

/**
 * Static NUL-terminated name for a `DEREC_CATEGORY_*` value.
 *
 * Returns `"unknown"` for unrecognized values. The returned pointer has
 * static lifetime and must **not** be freed.
 */
const char *derec_error_category_name(int32_t category);

/**
 * Static NUL-terminated name for a `DEREC_CODE_*` value.
 *
 * Returns `"unknown"` for unrecognized values. The returned pointer has
 * static lifetime and must **not** be freed.
 */
const char *derec_error_code_name(int32_t code);

/**
 * Decodes protobuf wire bytes into the JSON mirror of `kind`.
 *
 * The returned buffer is UTF-8 JSON and must be released with
 * `derec_free_buffer`.
 *
 * # Safety
 *
 * `proto_ptr` must point to `proto_len` readable bytes, or be null with
 * `proto_len` zero.
 */
struct DeRecMessageJsonResult derec_decode_message_json(int32_t kind,
                                                        const uint8_t *proto_ptr,
                                                        size_t proto_len);

/**
 * Encodes the JSON mirror of `kind` into protobuf wire bytes.
 *
 * The returned buffer must be released with `derec_free_buffer`.
 *
 * # Safety
 *
 * `json_ptr` must point to `json_len` readable bytes, or be null with
 * `json_len` zero.
 */
struct DeRecMessageJsonResult derec_encode_message_json(int32_t kind,
                                                        const uint8_t *json_ptr,
                                                        size_t json_len);

/**
 * Single entry point for all three modes:
 * - `contact_mode == 0` (`INLINE_KEYS`) — keys inlined in contact.
 * - `contact_mode == 1` (`HASHED_KEYS`) — binding hash inlined; keys via PrePair.
 * - `contact_mode == 2` (`NO_KEYS`) — no key material; keys generated on the
 *   fly by the responder when the `PrePairRequest` arrives.
 *
 * `has_nonce == 0` lets the library generate a fresh random `u64`.
 * `has_nonce == 1` uses the supplied `nonce` value verbatim; required for
 * `NO_KEYS` where callers typically pick a small human-typable value.
 *
 * On success `secret_key_material` is populated for `INLINE_KEYS` and
 * `HASHED_KEYS`; it is empty for `NO_KEYS` (no keys exist at
 * contact-creation time).
 *
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct CreateContactMessageResult create_contact_message(uint64_t channel_id,
                                                         int32_t contact_mode,
                                                         const uint8_t *transport_protocol_ptr,
                                                         size_t transport_protocol_len,
                                                         uint32_t has_nonce,
                                                         uint64_t nonce);

/**
 * Structurally validate a proto-encoded `ContactMessage`. Returns a
 * successful [`DeRecError`] iff the contact's `(contact_mode, inline keys,
 * binding hash)` tuple satisfies the per-mode invariants enforced by the
 * pairing primitives. Intended for bindings to call at their parse
 * boundary (e.g. `FromProtoBytes`) so that the decoded value handed to
 * application code is guaranteed well-formed.
 *
 * Failure codes:
 * - [`DEREC_CODE_FFI_BAD_PROTO`] if the bytes do not decode as a
 *   `ContactMessage`.
 * - The library's `InvalidContactMessage` error code on any structural
 *   violation (unknown `contact_mode`, mode/field mismatch, wrong
 *   binding-hash length).
 *
 * # Safety
 *
 * `contact_message_ptr` must point to a readable range of
 * `contact_message_len` bytes (or be null with `len == 0`).
 */
struct DeRecError validate_contact_message(const uint8_t *contact_message_ptr,
                                           size_t contact_message_len);

/**
 * Encodes a JSON [`ContactMessageDto`] to `ContactMessage` proto wire bytes.
 * Structurally validates the input first so a locally-constructed contact
 * that violates the mode/field invariant is rejected at the boundary rather
 * than silently serialized.
 *
 * The JSON shape is [`ContactMessageDto`]'s serde representation with one
 * adjustment applied at this seam: `channel_id` and `nonce` are decimal
 * strings, matching the `u64`-as-decimal-string convention every other FFI
 * JSON payload uses (see [`crate::interop::ffi::protocol::flow`]) because a host
 * whose numbers are IEEE-754 doubles cannot round-trip a full-width `u64`.
 * A plain JSON number is also accepted for either field.
 *
 * # Safety
 *
 * `contact_json_ptr` must point to a readable range of `contact_json_len`
 * bytes (or be null with `len == 0`).
 */
struct EncodeContactMessageResult encode_contact_message(const uint8_t *contact_json_ptr,
                                                         size_t contact_json_len);

/**
 * Decodes proto-encoded `ContactMessage` wire bytes into the JSON
 * [`ContactMessageDto`] shape described on [`encode_contact_message`].
 * Structurally validates the decoded value before returning it to
 * application code so consumers can trust the mode/field invariants
 * documented on the wire format.
 *
 * # Safety
 *
 * `contact_wire_ptr` must point to a readable range of `contact_wire_len`
 * bytes (or be null with `len == 0`).
 */
struct DecodeContactMessageResult decode_contact_message(const uint8_t *contact_wire_ptr,
                                                         size_t contact_wire_len);

/**
 * `communication_info_ptr` may be null / zero-length to indicate no
 * communication info; otherwise it must be serialized [`CommunicationInfo`]
 * proto bytes. `parameter_range_ptr` follows the same convention and
 * carries serialized [`derec_proto::ParameterRange`] bytes.
 *
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct ProducePairRequestMessageResult produce_pair_request_message(int32_t sender_kind,
                                                                    const uint8_t *transport_protocol_ptr,
                                                                    size_t transport_protocol_len,
                                                                    const uint8_t *contact_message_ptr,
                                                                    size_t contact_message_len,
                                                                    const uint8_t *communication_info_ptr,
                                                                    size_t communication_info_len,
                                                                    const uint8_t *parameter_range_ptr,
                                                                    size_t parameter_range_len);

/**
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct ExtractPairRequestResult extract_pair_request(const uint8_t *request_ptr,
                                                     size_t request_len,
                                                     const uint8_t *secret_key_material_ptr,
                                                     size_t secret_key_material_len);

/**
 * `request_proto_ptr` / `request_proto_len` must be the `request_proto_bytes`
 * returned by [`extract_pair_request`]. `communication_info_ptr` may be null /
 * zero-length to indicate no communication info.
 *
 * `parameter_range_ptr` may be null / zero-length to indicate no
 * parameter range; otherwise it must be serialized
 * [`derec_proto::ParameterRange`] proto bytes.
 *
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct ProducePairResponseMessageResult produce_pair_response_message(uint64_t channel_id,
                                                                      const uint8_t *request_proto_ptr,
                                                                      size_t request_proto_len,
                                                                      const uint8_t *secret_key_material_ptr,
                                                                      size_t secret_key_material_len,
                                                                      const uint8_t *communication_info_ptr,
                                                                      size_t communication_info_len,
                                                                      const uint8_t *parameter_range_ptr,
                                                                      size_t parameter_range_len);

/**
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct ExtractPairResponseResult extract_pair_response(const uint8_t *response_ptr,
                                                       size_t response_len,
                                                       const uint8_t *secret_key_material_ptr,
                                                       size_t secret_key_material_len);

/**
 * `response_proto_ptr` / `response_proto_len` must be the
 * `response_proto_bytes` returned by [`extract_pair_response`].
 *
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct ProcessPairResponseMessageResult process_pair_response_message(const uint8_t *contact_message_ptr,
                                                                      size_t contact_message_len,
                                                                      const uint8_t *response_proto_ptr,
                                                                      size_t response_proto_len,
                                                                      const uint8_t *secret_key_material_ptr,
                                                                      size_t secret_key_material_len);

/**
 * Builds a plaintext `PrePairRequestMessage` envelope. Used by the scanner
 * when the contact was sent with `contact_mode == HASHED_KEYS`. The envelope
 * is unencrypted — no shared key exists yet — so the caller does not pass
 * secret key material here.
 *
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct ProducePrePairRequestMessageResult produce_pre_pair_request_message(const uint8_t *transport_protocol_ptr,
                                                                           size_t transport_protocol_len,
                                                                           const uint8_t *contact_message_ptr,
                                                                           size_t contact_message_len);

/**
 * Decodes a plaintext `PrePairRequestMessage` envelope.
 *
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct ExtractPrePairRequestResult extract_pre_pair_request(const uint8_t *envelope_ptr,
                                                            size_t envelope_len);

/**
 * Builds a plaintext `PrePairResponseMessage` envelope republishing the
 * initiator's public keys. The keys come from `secret_key_material` (which
 * retains them alongside the secrets in `HASHED_KEYS` flows).
 *
 * `request_proto_ptr` / `request_proto_len` must be the `request_proto_bytes`
 * returned by [`extract_pre_pair_request`].
 *
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct ProducePrePairResponseMessageResult produce_pre_pair_response_message(uint64_t channel_id,
                                                                             const uint8_t *request_proto_ptr,
                                                                             size_t request_proto_len,
                                                                             const uint8_t *secret_key_material_ptr,
                                                                             size_t secret_key_material_len);

/**
 * Decodes a plaintext `PrePairResponseMessage` envelope.
 *
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct ExtractPrePairResponseResult extract_pre_pair_response(const uint8_t *envelope_ptr,
                                                              size_t envelope_len);

/**
 * Scanner-side: validates a decoded `PrePairResponseMessage` against the
 * original `ContactMessage`'s SHA-384 binding hash. On success returns the
 * validated public keys and echoed nonce. On any failure (non-Ok status,
 * hash mismatch, nonce mismatch, missing fields) returns an error and
 * empty buffers.
 *
 * `response_proto_ptr` / `response_proto_len` must be the
 * `response_proto_bytes` returned by [`extract_pre_pair_response`].
 *
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct ProcessPrePairResponseMessageResult process_pre_pair_response_message(const uint8_t *contact_message_ptr,
                                                                             size_t contact_message_len,
                                                                             const uint8_t *response_proto_ptr,
                                                                             size_t response_proto_len);

/**
 * Constructs a [`crate::protocol::DeRecProtocol`] with scalar config
 * bundled as JSON, for FFI callers that cannot pass many native
 * arguments in a single call — e.g. Go via `purego` (no cgo), which
 * panics with "too many stack arguments" past a handful of
 * parameters. Scalar configuration is bundled into a single JSON
 * buffer; `communication_info` stays a separate proto-encoded
 * `CommunicationInfo` buffer; the 6 store/transport callback structs
 * are still passed as individual pointers, since purego marshals
 * pointer-sized arguments natively.
 *
 * `config_json` must deserialize to the following shape — all field
 * names `snake_case`. `secret_id`, `own_transport_uri` and
 * `own_transport_protocol` are the only genuinely required fields;
 * `threshold`, `keep_versions_count`, `auto_respond_on_failure`,
 * `unpair_ack`, `auto_reply_to` and `auto_accept` may each be omitted, in
 * which case the value matches
 * [`crate::protocol::DeRecProtocolBuilder::new`]'s own default for that
 * setting — see [`ProtocolConfig`]'s field-level `#[serde(default)]`
 * attributes, which read the same constants the builder does:
 *
 * ```json
 * {
 *   "secret_id": "12345678901234567890",
 *   "own_transport_uri": "https://example.com/derec",
 *   "own_transport_protocol": 1,
 *   "threshold": 3,
 *   "keep_versions_count": 2,
 *   "timeout_in_secs": 30,
 *   "auto_respond_on_failure": false,
 *   "unpair_ack": 0,
 *   "auto_reply_to": false,
 *   "auto_accept": {
 *     "pairing": false,
 *     "pre_pair": false,
 *     "store_share": false,
 *     "verify_share": false,
 *     "discovery": false,
 *     "get_share": false,
 *     "unpair": false,
 *     "update_channel_info": false
 *   },
 *   "remove_expired_channels": { "enabled": true, "timeout_in_secs": 300 },
 *   "replica_id": null
 * }
 * ```
 *
 * - `secret_id`: decimal-string `u64`.
 * - `own_transport_uri`: may be `""` for the deferred-config path;
 *   `derec_protocol_set_own_transport` must be called before pairing
 *   in that case.
 * - `own_transport_protocol`: [`derec_proto::Protocol`] discriminant.
 * - `threshold` / `keep_versions_count`: optional; omitted means
 *   [`crate::protocol::DEFAULT_THRESHOLD`] /
 *   [`crate::protocol::DEFAULT_KEEP_VERSIONS_COUNT`].
 * - `unpair_ack`: `0` = Required, `1` = NotRequired; optional, omitted
 *   means `0`.
 * - `auto_respond_on_failure` / `auto_reply_to`: optional, omitted means
 *   `false`.
 * - `auto_accept`: one boolean per flow; the whole object is optional,
 *   omitted means every flow `false`.
 * - `remove_expired_channels`: automatic removal of expired `Pending`
 *   channels. Optional — omitted means `{ "enabled": true,
 *   "timeout_in_secs": 300 }`. Both fields are always sent; when
 *   `enabled` is `false` the timeout is ignored by the library.
 * - `replica_id`: decimal-string `u64`, or absent/`null` for "no
 *   replica id".
 *
 * # Safety
 *
 * - `config_json_ptr` must be valid for reads of `config_json_len`
 *   bytes.
 * - `communication_info_ptr` must be valid for reads of
 *   `communication_info_len` bytes when the length is non-zero.
 * - All 6 callback pointers must be valid for reads of their pointee
 *   struct, and must outlive the returned handle.
 * - The caller must invoke [`derec_protocol_free`] exactly once to
 *   release the returned handle.
 */
struct DeRecProtocolNewResult derec_protocol_new(const uint8_t *config_json_ptr,
                                                 size_t config_json_len,
                                                 const uint8_t *communication_info_ptr,
                                                 size_t communication_info_len,
                                                 const struct ChannelStoreCallbacks *channel_store_cb,
                                                 const struct SecretStoreCallbacks *secret_store_cb,
                                                 const struct ShareStoreCallbacks *share_store_cb,
                                                 const struct UserSecretStoreCallbacks *user_secret_store_cb,
                                                 const struct StateStoreCallbacks *state_store_cb,
                                                 const struct TransportCallbacks *transport_cb);

/**
 * Release a handle previously returned by [`derec_protocol_new`].
 * Safe to call with a null pointer.
 *
 * # Safety
 *
 * `handle` must satisfy ALL of:
 *
 * - It is a pointer previously returned by [`derec_protocol_new`],
 *   or it is null.
 * - It has not already been freed (no double-free).
 * - **No other thread is executing any `derec_protocol_*` function on
 *   this handle while this call is in flight.** The interior
 *   [`std::sync::Mutex`] protects against aliased `&mut` references
 *   *within* the live allocation, but it cannot protect the
 *   allocation itself from being dropped — a concurrent
 *   `derec_protocol_process` / `accept` / `set_*` call that holds
 *   the lock would be reading freed memory the moment this function
 *   returns. Host bindings (.NET `Dispose`, Node.js / WASM
 *   teardown) are responsible for draining or cancelling in-flight
 *   calls before invoking `derec_protocol_free`.
 */
void derec_protocol_free(struct DeRecProtocolHandle *handle);

/**
 * Replace this node's local `communication_info` map. Does not contact
 * peers — follow up with `start(FlowKind::UpdateChannelInfo)` to
 * propagate. The body is the same JSON wire shape used elsewhere on
 * the FFI: a UTF-8 JSON object with string keys + string values.
 *
 * # Safety
 *
 * `handle` must be a valid pointer returned by
 * [`super::derec_protocol_new`]. `info_json_ptr`/`info_json_len` must
 * describe a readable byte range. Concurrent calls on the same
 * handle from different threads are safe: the handle's internal
 * mutex serializes them.
 */
struct DeRecError derec_protocol_set_communication_info(struct DeRecProtocolHandle *handle,
                                                        const uint8_t *info_json_ptr,
                                                        size_t info_json_len);

/**
 * Replace this node's local transport endpoint. See
 * [`crate::protocol::DeRecProtocol::set_own_transport`] for the
 * changeover discipline (keep the old endpoint up during the
 * transition).
 *
 * # Safety
 *
 * `handle` must be a valid pointer returned by
 * [`super::derec_protocol_new`]. `uri_ptr`/`uri_len` must describe a
 * readable byte range. The `(uri, protocol)` pair is validated via
 * [`super::validate_transport`] before it is stored — see that
 * function's docs for the structural rules (length cap, scheme
 * match, enum discriminant). Concurrent calls on the same handle
 * from different threads are safe: the handle's internal mutex
 * serializes them.
 */
struct DeRecError derec_protocol_set_own_transport(struct DeRecProtocolHandle *handle,
                                                   const uint8_t *uri_ptr,
                                                   size_t uri_len,
                                                   int32_t protocol);

/**
 * Remove `Pending` channels older than `older_than_secs`. See
 * [`crate::protocol::DeRecProtocol::remove_expired_channels`] for the
 * semantics, including the strict `>` age boundary.
 *
 * # Safety
 *
 * `handle` must be a valid pointer returned by
 * [`super::derec_protocol_new`]. Concurrent calls on the same handle
 * from different threads are safe: the handle's internal mutex
 * serializes them.
 */
struct DeRecRemovedChannelsResult derec_protocol_remove_expired_channels(struct DeRecProtocolHandle *handle,
                                                                         uint64_t older_than_secs);

/**
 * Start a new flow. `flow_kind` matches the constants in
 * [`crate::interop::ffi::protocol::flow`]. `params_json_*` is a UTF-8 JSON blob
 * shaped to the matching `*ParamsJson` struct in that module.
 *
 * # Safety
 *
 * `handle` must be a valid pointer returned by
 * [`super::derec_protocol_new`]. `params_json_ptr`/`params_json_len`
 * must describe a readable byte range.
 */
struct DeRecProtocolEventsResult derec_protocol_start(struct DeRecProtocolHandle *handle,
                                                      uint32_t flow_kind,
                                                      const uint8_t *params_json_ptr,
                                                      size_t params_json_len);

/**
 * Process an inbound `DeRecMessage` envelope. See
 * [`crate::protocol::DeRecProtocol::process`].
 *
 * # Safety
 *
 * `handle` must be a valid pointer returned by
 * [`super::derec_protocol_new`]. `message_ptr`/`message_len` must
 * describe a readable byte range.
 */
struct DeRecProtocolEventsResult derec_protocol_process(struct DeRecProtocolHandle *handle,
                                                        const uint8_t *message_ptr,
                                                        size_t message_len);

/**
 * Advance time-driven state without an inbound message. See
 * [`crate::protocol::DeRecProtocol::tick`].
 *
 * Intended for a scheduler — a timer, a cron job, a queue heartbeat —
 * in deployments where nothing else would ever evaluate timeouts. Safe
 * to call on an idle protocol: it returns an empty event array.
 *
 * # Safety
 *
 * `handle` must be a valid pointer returned by
 * [`super::derec_protocol_new`].
 */
struct DeRecProtocolEventsResult derec_protocol_tick(struct DeRecProtocolHandle *handle);

/**
 * Accept a pending action from an `ActionRequired` event. See
 * [`crate::protocol::DeRecProtocol::accept`]. The `action_bytes` blob
 * is the exact payload the caller received in the event — the FFI
 * wire format is the encoding produced by
 * [`crate::protocol::utils::pending_action_wire::serialize`].
 *
 * # Safety
 *
 * `handle` must be a valid pointer returned by
 * [`super::derec_protocol_new`]. `action_ptr`/`action_len` must
 * describe a readable byte range.
 */
struct DeRecProtocolEventsResult derec_protocol_accept(struct DeRecProtocolHandle *handle,
                                                       const uint8_t *action_ptr,
                                                       size_t action_len);

/**
 * Reject a pending action from an `ActionRequired` event. See
 * [`crate::protocol::DeRecProtocol::reject`]. `status` matches
 * `derec_proto::StatusEnum` and `memo_ptr`/`memo_len` is an optional
 * UTF-8 string body (`memo_len == 0` for absent).
 *
 * # Safety
 *
 * `handle` must be a valid pointer returned by
 * [`super::derec_protocol_new`]. `action_ptr`/`action_len` must
 * describe a readable byte range.
 */
struct DeRecError derec_protocol_reject(struct DeRecProtocolHandle *handle,
                                        const uint8_t *action_ptr,
                                        size_t action_len,
                                        int32_t status,
                                        const uint8_t *memo_ptr,
                                        size_t memo_len);

/**
 * Rebuild this protocol's `secret_id` namespace from a recovered
 * `Secret`. See [`crate::protocol::DeRecProtocol::restore`] for the
 * full contract and error semantics.
 *
 * `params_json_*` is a UTF-8 JSON blob of the shape:
 *
 * ```json
 * {
 *   "version": 7,
 *   "recovered_secret": {
 *     "helpers": [{ "channel_id": "11", "transport_uri": "...",
 *                   "shared_key": [..32 bytes..],
 *                   "communication_info": {} }],
 *     "secrets": [{ "id": [..], "name": "...", "data": [..] }],
 *     "replicas": {
 *       "channel_id": "21",
 *       "members": [{ "replica_id": "51966", "transport_uri": "...",
 *                     "role": "Source", "communication_info": {} }],
 *       "shared_key": [..32 bytes..]
 *     }
 *   }
 * }
 * ```
 *
 * Field names mirror `SecretWire` in `protocol/events/wire.rs` — the
 * same shape `SecretRecovered` carries. `channel_id` and `replica_id`
 * are decimal `u64` strings (empty / absent means zero).
 *
 * `replicas` is an **object**, not an array, and is omitted entirely when
 * the `secret_id` has no replica group. Every member of the group shares
 * the one `channel_id` and the one `shared_key` it carries, so neither is
 * repeated per member; a member is identified by `replica_id` alone, and
 * the group's source is the member whose `role` is `"Source"`.
 *
 * # Safety
 *
 * `handle` must be a valid pointer returned by
 * [`super::derec_protocol_new`]. `params_json_ptr`/`params_json_len`
 * must describe a readable byte range.
 */
struct DeRecProtocolEventsResult derec_protocol_restore(struct DeRecProtocolHandle *handle,
                                                        const uint8_t *params_json_ptr,
                                                        size_t params_json_len);

/**
 * Derive the human-readable fingerprint for a paired channel. See
 * [`crate::protocol::DeRecProtocol::get_fingerprint`].
 *
 * # Safety
 *
 * `handle` must be a valid pointer returned by
 * [`super::derec_protocol_new`]. Concurrent calls on the same handle
 * from different threads are safe: the handle's internal mutex
 * serializes them.
 */
struct DeRecProtocolFingerprintResult derec_protocol_get_fingerprint(struct DeRecProtocolHandle *handle,
                                                                     uint64_t channel_id);

/**
 * Verify a fingerprint against the channel's locally-derived one. See
 * [`crate::protocol::DeRecProtocol::verify_fingerprint`].
 *
 * Writes `*out_matched = 1` if and only if the comparison
 * affirmatively succeeded. On every other outcome — null-pointer
 * rejection, malformed UTF-8 in `fingerprint_ptr`, a backend error,
 * or a legitimate mismatch — `*out_matched` is set to `0`. Callers
 * MUST also inspect the returned [`DeRecError`] to distinguish a
 * successful mismatch from a failure that could not produce a
 * verdict; treating `out_matched == 0` as "definitely not matched"
 * is safe only after confirming the envelope reports
 * [`DEREC_CATEGORY_OK`](crate::interop::ffi::error::DEREC_CATEGORY_OK).
 *
 * The fail-closed write happens immediately after the null-pointer
 * check, so a caller that allocates the output on the stack and
 * reads it without checking the error envelope still gets `0`,
 * never a stale `1` from uninitialized memory. This neutralizes
 * the "sloppy caller skips the error envelope and reads stale
 * stack" footgun on the MITM-protection gate.
 *
 * # Safety
 *
 * `handle` and `out_matched` must be valid pointers. `fingerprint_ptr`
 * must be a valid pointer to a NUL-terminated C string. Concurrent
 * calls on the same handle from different threads are safe: the
 * handle's internal mutex serializes them.
 */
struct DeRecError derec_protocol_verify_fingerprint(struct DeRecProtocolHandle *handle,
                                                    uint64_t channel_id,
                                                    const char *fingerprint_ptr,
                                                    uint32_t *out_matched);

/**
 * Generate an out-of-band contact message used to bootstrap pairing.
 * See [`crate::protocol::DeRecProtocol::create_contact`].
 *
 * `has_channel_id == 0` lets the library mint the channel id; `1`
 * supplies it via `channel_id`.
 *
 * # Safety
 *
 * `handle` must be a valid pointer returned by
 * [`super::derec_protocol_new`]. Concurrent calls on the same handle
 * from different threads are safe: the handle's internal mutex
 * serializes them.
 */
struct DeRecProtocolCreateContactResult derec_protocol_create_contact(struct DeRecProtocolHandle *handle,
                                                                      uint32_t has_channel_id,
                                                                      uint64_t channel_id,
                                                                      int32_t contact_mode,
                                                                      uint32_t has_nonce,
                                                                      uint64_t nonce);

struct DeRecProtocolVersion derec_protocol_version(void);

/**
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct ProduceGetShareRequestMessageResult produce_get_share_request_message(uint64_t channel_id,
                                                                             uint64_t secret_id,
                                                                             uint32_t version,
                                                                             const uint8_t *shared_key_ptr,
                                                                             size_t shared_key_len,
                                                                             const uint8_t *reply_to_ptr,
                                                                             size_t reply_to_len);

/**
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct ExtractGetShareRequestResult extract_get_share_request(const uint8_t *request_ptr,
                                                              size_t request_len,
                                                              const uint8_t *shared_key_ptr,
                                                              size_t shared_key_len);

/**
 * `request_proto_ptr` / `request_proto_len` must be the `request_proto_bytes`
 * returned by [`extract_get_share_request`].
 *
 * `stored_share_proto_ptr` / `stored_share_proto_len` must be the serialized
 * inner `StoreShareRequestMessage` the helper persisted at sharing time —
 * typically the `request_proto_bytes` returned by `extract_store_share_request`.
 *
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct ProduceGetShareResponseMessageResult produce_get_share_response_message(uint64_t channel_id,
                                                                               const uint8_t *request_proto_ptr,
                                                                               size_t request_proto_len,
                                                                               const uint8_t *stored_share_proto_ptr,
                                                                               size_t stored_share_proto_len,
                                                                               const uint8_t *shared_key_ptr,
                                                                               size_t shared_key_len);

/**
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct ExtractGetShareResponseResult extract_get_share_response(const uint8_t *response_ptr,
                                                                size_t response_len,
                                                                const uint8_t *shared_key_ptr,
                                                                size_t shared_key_len);

/**
 * `responses_ptr` / `responses_len` must follow the binary format documented
 * at the module level.
 *
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct RecoverFromShareResponsesResult recover_from_share_responses(const uint8_t *responses_ptr,
                                                                    size_t responses_len,
                                                                    uint64_t secret_id,
                                                                    uint32_t version);

/**
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct ProtectSecretResult protect_secret(uint64_t secret_id,
                                          const uint8_t *secret_data_ptr,
                                          size_t secret_data_len,
                                          const uint64_t *channels_ptr,
                                          size_t channels_len,
                                          size_t threshold,
                                          uint32_t version);

/**
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct ProduceStoreShareRequestMessageResult produce_store_share_request_message(uint64_t channel_id,
                                                                                 uint32_t version,
                                                                                 uint64_t secret_id,
                                                                                 const uint8_t *committed_share_ptr,
                                                                                 size_t committed_share_len,
                                                                                 const uint32_t *keep_list_ptr,
                                                                                 size_t keep_list_len,
                                                                                 const uint8_t *description_ptr,
                                                                                 size_t description_len,
                                                                                 const uint8_t *shared_key_ptr,
                                                                                 size_t shared_key_len,
                                                                                 const uint8_t *reply_to_ptr,
                                                                                 size_t reply_to_len);

/**
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct ExtractStoreShareRequestResult extract_store_share_request(const uint8_t *request_ptr,
                                                                  size_t request_len,
                                                                  const uint8_t *shared_key_ptr,
                                                                  size_t shared_key_len);

/**
 * `request_proto_ptr` / `request_proto_len` must be the `request_proto_bytes`
 * returned by [`extract_store_share_request`].
 *
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct ProduceStoreShareResponseMessageResult produce_store_share_response_message(uint64_t channel_id,
                                                                                   const uint8_t *request_proto_ptr,
                                                                                   size_t request_proto_len,
                                                                                   const uint8_t *shared_key_ptr,
                                                                                   size_t shared_key_len);

/**
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct ExtractStoreShareResponseResult extract_store_share_response(const uint8_t *response_ptr,
                                                                    size_t response_len,
                                                                    const uint8_t *shared_key_ptr,
                                                                    size_t shared_key_len);

/**
 * `response_proto_ptr` / `response_proto_len` must be the
 * `response_proto_bytes` returned by [`extract_store_share_response`].
 *
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct ProcessStoreShareResponseMessageResult process_store_share_response_message(uint32_t version,
                                                                                   const uint8_t *response_proto_ptr,
                                                                                   size_t response_proto_len);

/**
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct ProduceUnpairRequestMessageResult produce_unpair_request_message(uint64_t channel_id,
                                                                        const uint8_t *memo_ptr,
                                                                        size_t memo_len,
                                                                        const uint8_t *shared_key_ptr,
                                                                        size_t shared_key_len,
                                                                        const uint8_t *reply_to_ptr,
                                                                        size_t reply_to_len);

/**
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct ExtractUnpairRequestResult extract_unpair_request(const uint8_t *request_ptr,
                                                         size_t request_len,
                                                         const uint8_t *shared_key_ptr,
                                                         size_t shared_key_len);

/**
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct ProduceUnpairResponseMessageResult produce_unpair_response_message(uint64_t channel_id,
                                                                          const uint8_t *shared_key_ptr,
                                                                          size_t shared_key_len);

/**
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct ExtractUnpairResponseResult extract_unpair_response(const uint8_t *response_ptr,
                                                           size_t response_len,
                                                           const uint8_t *shared_key_ptr,
                                                           size_t shared_key_len);

/**
 * `response_proto_ptr` / `response_proto_len` must be the
 * `response_proto_bytes` returned by [`extract_unpair_response`].
 *
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct ProcessUnpairResponseResult process_unpair_response_message(const uint8_t *response_proto_ptr,
                                                                   size_t response_proto_len);

/**
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct ProduceVerifyShareRequestMessageResult produce_verify_share_request_message(uint64_t channel_id,
                                                                                   uint64_t secret_id,
                                                                                   uint32_t version,
                                                                                   const uint8_t *shared_key_ptr,
                                                                                   size_t shared_key_len,
                                                                                   const uint8_t *reply_to_ptr,
                                                                                   size_t reply_to_len);

/**
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct ExtractVerifyShareRequestResult extract_verify_share_request(const uint8_t *request_ptr,
                                                                    size_t request_len,
                                                                    const uint8_t *shared_key_ptr,
                                                                    size_t shared_key_len);

/**
 * `request_proto_ptr` / `request_proto_len` must be the `request_proto_bytes`
 * returned by [`extract_verify_share_request`].
 *
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct ProduceVerifyShareResponseMessageResult produce_verify_share_response_message(uint64_t channel_id,
                                                                                     const uint8_t *request_proto_ptr,
                                                                                     size_t request_proto_len,
                                                                                     const uint8_t *shared_key_ptr,
                                                                                     size_t shared_key_len,
                                                                                     const uint8_t *share_content_ptr,
                                                                                     size_t share_content_len);

/**
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct ExtractVerifyShareResponseResult extract_verify_share_response(const uint8_t *response_ptr,
                                                                      size_t response_len,
                                                                      const uint8_t *shared_key_ptr,
                                                                      size_t shared_key_len);

/**
 * Verify a `VerifyShareResponseMessage` against the originating
 * `VerifyShareRequestMessage` and the expected share content.
 *
 * `request_proto_ptr` / `request_proto_len` must carry the proto-
 * encoded [`derec_proto::VerifyShareRequestMessage`] the **owner**
 * previously produced for this challenge (kept by the caller in a
 * per-`channel_id` pending-verification map). The primitive
 * rejects any response whose `(nonce, secret_id, version)` triple
 * doesn't match — that's the anti-replay gate.
 *
 * `response_proto_ptr` / `response_proto_len` must be the
 * `response_proto_bytes` returned by [`extract_verify_share_response`].
 *
 * # Safety
 *
 * Non-null input pointers must point to the corresponding readable byte ranges.
 */
struct VerifyShareResponseResult process_verify_share_response_message(const uint8_t *request_proto_ptr,
                                                                       size_t request_proto_len,
                                                                       const uint8_t *response_proto_ptr,
                                                                       size_t response_proto_len,
                                                                       const uint8_t *share_content_ptr,
                                                                       size_t share_content_len);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* DEREC_FFI_H */
