// SPDX-License-Identifier: Apache-2.0

export { default as init } from "./derec_library.js";

export interface SecretStore {
  load(channelId: string, kind: 0 | 1 | 2): Promise<Uint8Array | null | undefined>;
  /**
   * Load secrets of the same `kind` for several channels in one call. Must
   * return an array with one entry per input id, in the same order, using
   * `null` (or `undefined`) for channels with no stored secret of `kind`.
   *
   * `missingPolicy` is the caller's preference for how to surface missing
   * entries:
   * - `"skip"` — return nulls for missing ids; the caller will drop them.
   * - `"fail"` — every requested id is expected to have an entry. Stores
   *   that can detect misses cheaply (e.g. by row count) may throw
   *   immediately to short-circuit unnecessary work; otherwise return nulls
   *   as in `"skip"` mode — the Rust adapter detects the misses and surfaces
   *   them as a structured error.
   */
  loadMany(
    channelIds: string[],
    kind: 0 | 1 | 2,
    missingPolicy: "skip" | "fail",
  ): Promise<Array<Uint8Array | null | undefined>>;
  save(channelId: string, kind: 0 | 1 | 2, value: Uint8Array): Promise<void>;
  remove(channelId: string, kind: 0 | 1 | 2): Promise<void>;
}

export interface ChannelStore {
  load(channelId: string): Promise<Uint8Array | null | undefined>;
  save(channelId: string, bytes: Uint8Array): Promise<void>;
  listChannels(): Promise<string[]>;
  remove(channelId: string): Promise<boolean>;
  linkChannel(channelId: string, linkedChannelId: string): Promise<void>;
  linkedChannels(channelId: string): Promise<string[]>;
}

export interface Share {
  secretId: string;
  version: number;
  bytes: Uint8Array;
}

export interface ShareStore {
  load(channelId: string, secretId: string, versions: number[]): Promise<Share[]>;
  loadMany(channelIds: string[], secretId: string, versions: number[]): Promise<Share[]>;

  loadAll(channelIds: string[]): Promise<Share[]>;
  save(channelId: string, share: Share): Promise<void>;
  latestVersion(): Promise<number | null>;
}

export interface Transport {
  send(endpoint: { protocol: string; uri: string }, message: Uint8Array): Promise<void>;
}

export enum SenderKind {
  Owner = 0,
  Helper = 1,
  ReplicaSource = 3,
  ReplicaDestination = 4,
}

/**
 * Selects how the initiator's public encryption material is delivered in a
 * `ContactMessage`.
 *
 * - `InlineKeys` (default): keys are embedded in the contact itself.
 * - `HashedKeys`: only a SHA-384 commitment to the keys is in the contact;
 *   the scanner must fetch the actual keys over the wire via the `PrePair`
 *   round-trip and verify them against the commitment before pairing.
 */
export enum ContactMode {
  InlineKeys = 0,
  HashedKeys = 1,
}

export enum FlowKind {
  Pairing = 0,
  Discovery = 1,
  ProtectSecret = 2,
  VerifyShares = 3,
  RecoverSecret = 4,
  Unpair = 5,
  UpdateChannelInfo = 6,
}

export type UnpairAck = "required" | "not_required";

export interface ContactMessage {
  channel_id: bigint;
  /** `ContactMode` numeric value (0 = INLINE_KEYS, 1 = HASHED_KEYS). */
  contact_mode: number;
  transport_protocol?: TransportProtocol;
  nonce: bigint;
  /** Present only when `contact_mode === ContactMode.InlineKeys`. */
  mlkem_encapsulation_key?: Uint8Array;
  /** Present only when `contact_mode === ContactMode.InlineKeys`. */
  ecies_public_key?: Uint8Array;
  /** Present only when `contact_mode === ContactMode.HashedKeys`. SHA-384 digest (48 bytes). */
  contact_binding_hash?: Uint8Array;
  timestamp?: Timestamp;
}

export interface UserSecret {

  id: Uint8Array;
  name: string;
  data: Uint8Array;
}

export type Target = bigint | bigint[] | null;

export interface PairingParams {
  kind: SenderKind;
  contact: ContactMessage;

  peerCommunicationInfo?: Record<string, string>;
}
export interface DiscoveryParams {
  target?: Target;
}
export interface ProtectSecretParams {
  secretId: bigint | string;
  target?: Target;
  secrets: UserSecret[];
  description?: string;
}
export interface VerifySharesParams {
  secretId: bigint | string;
  version: number;
  target?: Target;
}
export interface RecoverSecretParams {

  secretId: bigint | string;
  version: number;
}
export interface UnpairParams {
  target?: Target;

  memo?: string;
}
export interface UpdateChannelInfoParams {
  target?: Target;

  /** New communication-info map. `null`/absent leaves the peer's stored
   *  map untouched; pass an empty object to clear it. */
  communication_info?: Record<string, string>;

  /** New transport endpoint. Absent leaves it untouched. */
  transport_protocol?: { uri: string; protocol: number };
}

export type DeRecEvent =
  | { type: "PairingCompleted"; channel_id: string; kind: SenderKind; peer_communication_info?: Record<string, string> }
  | {
      type: "ActionRequired";
      channel_id: string;

      action: Uint8Array;

      action_kind: string;
      peer_communication_info?: Record<string, string>;

      sender_kind?: SenderKind;

      version?: number;
      share_description?: string;

      share_secret_id?: string;
    }
  | { type: "ShareStored"; channel_id: string; version: number }
  | { type: "ShareConfirmed"; channel_id: string; version: number }
  | { type: "ShareRejected"; channel_id: string; version: number; status: number; memo: string }
  | { type: "SharingComplete"; version: number; confirmed_count: number; failed_count: number; threshold_met: boolean }
  | { type: "ShareVerified"; channel_id: string; version: number }
  | {
      type: "SecretsDiscovered";
      channel_id: string;

      secrets: Array<{ secret_id: string; versions: Array<{ version: number; description: string }> }>;
    }
  | { type: "RecoveryShareReceived"; channel_id: string; shares_received: number }
  | { type: "RecoveryShareError"; channel_id: string; shares_received: number; error: string }
  | { type: "SecretRecovered"; secret: Uint8Array }

  | { type: "Unpaired"; channel_id: string }

  | { type: "UnpairRejected"; channel_id: string; status: number; memo: string }

  /** Contact creator answered the scanner's `PrePairRequest` with a
   *  non-Ok status (HashedKeys flow). Distinct from a cryptographic
   *  hash mismatch, which surfaces as a thrown error from `process()`. */
  | { type: "PrePairRejected"; channel_id: string; status: number; memo: string }

  /** Fires alongside `PairingCompleted` on replica-mode pair handshakes.
   *  `peer_replica_id` is the peer's hex-encoded `u64` (matches the wire
   *  `derec.replica_id` representation). The local side's role
   *  (`ReplicaSource` vs `ReplicaDestination`) is on the persisted
   *  channel record — replica pairings are unidirectional, so there is
   *  no separate "role in pair" field. */
  | {
      type: "ReplicaPaired";
      channel_id: string;
      peer_replica_id: string;
    }
  /** A `ReplicaSource` peer pushed a vault sync on a
   *  `ReplicaDestination` channel. The library decoded the
   *  `ReplicaSecretPayload`; the app installs `vault.secrets` and
   *  optionally uses `shares` for recovery. `from_replica_id` and the
   *  `replica_id` fields inside `vault` are hex-encoded `u64`. */
  | {
      type: "ReplicaVaultReceived";
      channel_id: string;
      from_replica_id: string;
      secret_id: string;
      version: number;
      vault: {
        helpers: Array<{
          channel_id: string;
          transport_uri: string;
          shared_key: Uint8Array;
          communication_info: Record<string, string>;
        }>;
        secrets: Array<{
          id: Uint8Array;
          name: string;
          data: Uint8Array;
        }>;
        replicas: Array<{
          channel_id: string;
          transport_uri: string;
          shared_key: Uint8Array;
          communication_info: Record<string, string>;
          replica_id: string;
          sender_kind: number;
        }>;
        owner_replica_id: string;
      };
      shares: Array<{
        channel_id: string;
        committed_share: Uint8Array;
      }>;
    }
  /** Peer's ack of a vault sync we sent. `status` is the `StatusEnum`
   *  integer (0 = Ok), `memo` is the peer's explanation. */
  | {
      type: "ReplicaVaultAcked";
      channel_id: string;
      from_replica_id: string;
      secret_id: string;
      version: number;
      status: number;
      memo: string;
    }
  /** A peer announced an updated `communication_info` map and/or
   *  transport endpoint via `start(FlowKind.UpdateChannelInfo)`.
   *  Surfaces on both sides — the initiator sees its own update echo
   *  back after the responder accepts. */
  | {
      type: "ChannelInfoUpdated";
      channel_id: string;
      peer_communication_info?: Record<string, string>;
      peer_transport_uri?: string;
    }
  /** The peer answered our outbound `UpdateChannelInfo` with a
   *  non-`Ok` status. Local state is not rolled back — the app decides
   *  whether to retry. */
  | {
      type: "ChannelInfoUpdateRejected";
      channel_id: string;
      status: number;
      memo: string;
    }
  | { type: "NoOp" };

/**
 * Fluent builder for {@link DeRecProtocol}. Mirrors the Rust
 * `DeRecProtocolBuilder` and the dotnet `DeRecProtocolBuilder`
 * method-for-method so a developer who already knows one SDK can move
 * between them without reaching for reference docs.
 *
 * Required setters: `withChannelStore`, `withShareStore`,
 * `withSecretStore`, `withTransport`, `withOwnTransport`. Calling
 * `build()` without all five throws.
 */
export declare class DeRecProtocolBuilder {
  constructor();

  withChannelStore(store: ChannelStore): DeRecProtocolBuilder;
  withShareStore(store: ShareStore): DeRecProtocolBuilder;
  withSecretStore(store: SecretStore): DeRecProtocolBuilder;
  withTransport(transport: Transport): DeRecProtocolBuilder;
  withOwnTransport(endpoint: { uri: string; protocol: string }): DeRecProtocolBuilder;

  /** Default: 3. */
  withThreshold(threshold: number): DeRecProtocolBuilder;
  /** Default: 3. */
  withKeepVersionsCount(count: number): DeRecProtocolBuilder;
  /** Seconds. Default: 300 (5 minutes). Clamped to at least 1. */
  withTimeout(timeoutInSecs: number): DeRecProtocolBuilder;
  /** Default: empty. */
  withCommunicationInfo(info: Record<string, string>): DeRecProtocolBuilder;
  /** Default: false. */
  withAutoRespondOnFailure(enabled: boolean): DeRecProtocolBuilder;
  /** Default: "required". */
  withUnpairAck(ack: UnpairAck): DeRecProtocolBuilder;
  /**
   * When `true`, every outbound channel-mode request stamps
   * `request.replyTo = ownTransport` so the responder routes its reply
   * back here even if the channel's stored peer endpoint points
   * elsewhere. Default: false.
   */
  withAutoReplyTo(enabled: boolean): DeRecProtocolBuilder;
  /**
   * Stable per-device replica id. Required to participate in any
   * `ReplicaSource` / `ReplicaDestination` pairing. The id must be
   * stable across restarts. Default: unset.
   */
  withReplicaId(id: bigint | number): DeRecProtocolBuilder;

  /**
   * Finalize the configuration. Throws if any of the required setters
   * was not called.
   */
  build(): DeRecProtocol;
}

export declare class DeRecProtocol {
  /** Use {@link DeRecProtocolBuilder} to construct instances. */
  private constructor();

  /**
   * Generate an out-of-band contact message used to bootstrap pairing.
   *
   * @param channelId  Optional channel identifier. Pass `null` /
   *                   `undefined` to have the library generate one.
   * @param contactMode  `ContactMode.InlineKeys` embeds the public keys
   *                     directly in the contact. `ContactMode.HashedKeys`
   *                     embeds only a SHA-384 binding hash (keys are
   *                     fetched later via the `PrePair` round-trip).
   *                     `HashedKeys` requires `ownTransportUri` to be
   *                     ephemeral.
   */
  createContact(channelId: bigint | null | undefined, contactMode: ContactMode): Promise<ContactMessage>;

  start(flowKind: FlowKind.Pairing, params: PairingParams): Promise<bigint>;
  start(flowKind: FlowKind.Discovery, params: DiscoveryParams): Promise<null>;
  start(flowKind: FlowKind.ProtectSecret, params: ProtectSecretParams): Promise<null>;
  start(flowKind: FlowKind.VerifyShares, params: VerifySharesParams): Promise<null>;
  start(flowKind: FlowKind.RecoverSecret, params: RecoverSecretParams): Promise<null>;
  start(flowKind: FlowKind.Unpair, params: UnpairParams): Promise<null>;
  start(flowKind: FlowKind.UpdateChannelInfo, params: UpdateChannelInfoParams): Promise<null>;

  /**
   * Replace this node's local <c>communication_info</c> map. Does not
   * contact peers — follow up with
   * <c>start(FlowKind.UpdateChannelInfo, ...)</c> to propagate.
   */
  setCommunicationInfo(info: Record<string, string>): void;

  /**
   * Replace this node's local transport endpoint. IMPORTANT: keep the
   * old endpoint operational during the changeover (see the Rust docs
   * on the matching setter for the discipline).
   */
  setOwnTransport(uri: string, protocol: string): void;

  process(message: Uint8Array): Promise<DeRecEvent[]>;

  accept(actionBytes: Uint8Array): Promise<DeRecEvent[]>;

  reject(actionBytes: Uint8Array, status: number, memo: string): Promise<void>;

  /**
   * Derive the human-readable fingerprint for a paired channel. Both sides
   * of a replica pair compute the same fingerprint from the shared key —
   * users compare them out of band before calling `verifyFingerprint`.
   */
  getFingerprint(channelId: bigint | number): Promise<string>;

  /**
   * Verify `fingerprint` against the channel's locally-derived one. On
   * match, the channel transitions from `Pending` to `Paired`. Returns
   * `true` on confirmation, `false` on mismatch.
   */
  verifyFingerprint(channelId: bigint | number, fingerprint: string): Promise<boolean>;
}

export interface RecoveredHelperInfo {

  channelId: string;
  transportUri: string;

  communicationInfo: Record<string, string>;

  sharedKey: Uint8Array | number[];
}

export interface RecoveredUserSecret {

  id: Uint8Array | number[];

  name: string;

  data: Uint8Array | number[];
}

export interface RecoveredSecretBag {
  helpers: RecoveredHelperInfo[];
  secrets: RecoveredUserSecret[];
}

export declare function decodeRecoveredSecretBag(bytes: Uint8Array): RecoveredSecretBag;

/**
 * Envelope-level helpers that operate on raw `DeRecMessage` bytes without
 * touching the encrypted inner payload. Useful for primitive-only consumers
 * that need to set or read the `traceId` correlation token themselves
 * (`DeRecProtocol` handles trace_id end-to-end automatically).
 */
export declare const envelope: {
  /**
   * Re-stamp `traceId` on an outbound envelope. Returns the re-encoded
   * bytes. The encrypted inner message is untouched.
   */
  apply_trace_id(envelope_bytes: Uint8Array, trace_id: bigint): Uint8Array;

  /**
   * Read `traceId` off an inbound envelope. Returns `0n` when unset (the
   * protobuf default is indistinguishable from an explicit zero).
   */
  read_trace_id(envelope_bytes: Uint8Array): bigint;
};

export declare function restoreFromRecoveredBag(
  channelStore: ChannelStore,
  secretStore: SecretStore,
  shareStore: ShareStore,
  recoveredBytes: Uint8Array,
  secretId: string,
  version: number,
): Promise<void>;

export interface Timestamp {

  seconds: bigint;
  nanos: number;
}

export interface DeRecResult {
  status: number;
  memo: string;
}

export interface GetSecretIdsVersionsRequestMessage {
  timestamp?: Timestamp;
  /** Ephemeral endpoint where the requester wants the response routed.
   *  Absent means "use the channel's stored peer endpoint". */
  reply_to?: TransportProtocol;
}

export interface VersionList {
  secret_id: bigint;
  versions: VersionListEntry[];
}

export interface VersionListEntry {
  version: number;
  version_description: string;
}

export interface GetSecretIdsVersionsResponseMessage {
  result?: DeRecResult;
  secret_list: VersionList[];
  timestamp?: Timestamp;
}

export interface VersionEntry {
  version: number;
  description: string;
}

export interface SecretVersionEntry {
  secret_id: bigint;
  versions: VersionEntry[];
}

export interface TransportProtocol {
  uri: string;

  protocol: number;
}

export interface CommunicationInfoKeyValue {
  key: string;
  string_value: string | null;
  bytes_value: Uint8Array | null;
}

export interface CommunicationInfo {
  communication_info_entries: CommunicationInfoKeyValue[];
}

// `ContactMessage` is defined once above (line ~75) and covers both
// `INLINE_KEYS` and `HASHED_KEYS` modes.


export interface ParameterRange {
  min_share_size: bigint;
  max_share_size: bigint;
  min_time_between_verifications: bigint;
  max_time_between_verifications: bigint;
  min_time_between_share_updates: bigint;
  max_time_between_share_updates: bigint;
  min_unresponsive_deletion_timeout: bigint;
  max_unresponsive_deletion_timeout: bigint;
  min_unresponsive_deactivation_timeout: bigint;
  max_unresponsive_deactivation_timeout: bigint;
}

export interface PairRequestMessage {
  sender_kind: number;
  mlkem_ciphertext: Uint8Array;
  ecies_public_key: Uint8Array;
  nonce: bigint;
  communication_info?: CommunicationInfo;
  parameter_range?: ParameterRange;
  transport_protocol?: TransportProtocol;
  timestamp?: Timestamp;
}

export interface PairResponseMessage {
  result?: DeRecResult;
  nonce: bigint;
  communication_info?: CommunicationInfo;
  parameter_range?: ParameterRange;
  timestamp?: Timestamp;
  /**
   * Post-handshake rekey channel id. Both sides switch their local channel
   * record to this value once the response is accepted. Derived by the
   * responder as `SHA-384(u64_be(originalChannelId) || sharedKey)[..8]`
   * interpreted as big-endian `u64`, and validated by the requester against
   * its own derivation. Zero on rejection (non-Ok `result.status`).
   */
  channel_id: bigint;
}

export interface PrePairRequestMessage {
  nonce: bigint;
  transport_protocol?: TransportProtocol;
  timestamp?: Timestamp;
}

export interface PrePairResponseMessage {
  result?: DeRecResult;
  /** Present only when `result.status === Ok`. */
  mlkem_encapsulation_key?: Uint8Array;
  /** Present only when `result.status === Ok`. */
  ecies_public_key?: Uint8Array;
  nonce: bigint;
  timestamp?: Timestamp;
}

export interface GetShareRequestMessage {
  secret_id: bigint;
  version: number;
  timestamp?: Timestamp;
  /** Ephemeral response endpoint; see `replyTo` semantics. */
  reply_to?: TransportProtocol;
}

export interface GetShareResponseMessage {
  share_algorithm: number;

  committed_de_rec_share: Uint8Array;
  result?: DeRecResult;
  timestamp?: Timestamp;
  /** Echoed from the request so the Owner can correlate responses across
   * concurrent recoveries without inspecting the share bytes. */
  secret_id: bigint;
  /** Echoed from the request for the same correlation reasons as `secret_id`. */
  version: number;
}

export interface SiblingHash {
  is_left: boolean;
  hash: Uint8Array;
}

export interface CommittedDeRecShare {

  de_rec_share: Uint8Array;
  commitment: Uint8Array;
  merkle_path: SiblingHash[];
}

export interface StoreShareRequestMessage {

  share: Uint8Array;
  share_algorithm: number;
  version: number;
  keep_list: number[];
  version_description: string;
  timestamp?: Timestamp;
  secret_id: bigint;
  /** Ephemeral response endpoint; see `replyTo` semantics. */
  reply_to?: TransportProtocol;
}

export interface StoreShareResponseMessage {
  result?: DeRecResult;
  version: number;
  timestamp?: Timestamp;
  secret_id: bigint;
}

export interface UnpairRequestMessage {
  memo: string;
  timestamp?: Timestamp;
  /** Ephemeral response endpoint; see `replyTo` semantics. */
  reply_to?: TransportProtocol;
}

export interface UnpairResponseMessage {
  result?: DeRecResult;
  timestamp?: Timestamp;
}

export interface VerifyShareRequestMessage {
  secret_id: bigint;
  version: number;
  nonce: bigint;
  timestamp?: Timestamp;
  /** Ephemeral response endpoint; see `replyTo` semantics. */
  reply_to?: TransportProtocol;
}

export interface VerifyShareResponseMessage {
  result?: DeRecResult;
  secret_id: bigint;
  version: number;
  nonce: bigint;
  hash: Uint8Array;
  timestamp?: Timestamp;
}

export interface ProduceResult {

  envelope: Uint8Array;
}

export interface SharingResponseProduceResult extends ProduceResult {
  committed_share: CommittedDeRecShare;
  secret_id: bigint;
  version: number;
}

export interface CreateContactResult {
  contact_message: ContactMessage;

  secret_key: Uint8Array;
}

export interface PairingRequestProduceResult extends ProduceResult {
  initiator_contact_message: ContactMessage;

  secret_key: Uint8Array;
}

export interface PairingResponseProduceResult extends ProduceResult {
  peer_transport_protocol: TransportProtocol;

  shared_key: Uint8Array;

  /**
   * Post-handshake rekey channel id the responder is committing to.
   * Callers MUST atomically rename their local channel record from the
   * pre-rekey id (the one passed to `pairing.response.produce`) to this
   * value as part of accepting the response.
   */
  channel_id: bigint;
}

export interface PairingProcessResult {

  shared_key: Uint8Array;

  /**
   * Post-handshake rekey channel id — already validated against the
   * caller's own derivation. Callers MUST atomically rename their local
   * channel record from the pre-rekey id (the one in the contact) to this
   * value.
   */
  channel_id: bigint;
}

export interface ProducePrePairResult {

  envelope: Uint8Array;
}

export interface PrePairRequestExtractResult {

  request: PrePairRequestMessage;
}

export interface PrePairResponseExtractResult {

  response: PrePairResponseMessage;
}

export interface ProcessPrePairResult {

  /** Initiator's ML-KEM-768 encapsulation key, validated against the
   * contact's `contactBindingHash`. */
  mlkem_encapsulation_key: Uint8Array;

  /** Initiator's ECIES public key, validated against the contact's
   * `contactBindingHash`. */
  ecies_public_key: Uint8Array;

  /** Nonce echoed from the original `ContactMessage`. */
  nonce: bigint;
}

export interface SplitResult {
  /** Map keyed by channel id (`bigint`). */
  shares: Map<bigint, CommittedDeRecShare>;
}

export interface RecoverResult {
  secret_data: Uint8Array;
}

export interface UnpairingProcessResult {
  acknowledged: boolean;
}

export interface DiscoveryProcessResult {
  secret_list: SecretVersionEntry[];
}

export type DeRecErrorCategory =
  | "pairing"
  | "recovery"
  | "discovery"
  | "sharing"
  | "verification"
  | "unpairing"
  | "derec_message"
  | "secret_store"
  | "channel_store"
  | "share_store"
  | "input"
  | "protobuf"
  | "invariant"
  | "wasm";

export interface DeRecError {
  category: DeRecErrorCategory;
  code: string;
  message: string;
  status?: number;
  memo?: string;
  expected?: number;
  got?: number;
}

export declare const primitives: {
  discovery: {
    request: {
      /**
       * @param reply_to  Optional ephemeral response endpoint. `null` /
       *                  `undefined` means "no override" (the responder
       *                  routes to the channel's stored peer endpoint).
       */
      produce(
        channel_id: bigint,
        shared_key: Uint8Array,
        reply_to?: TransportProtocol | null,
      ): ProduceResult;
      extract(envelope_bytes: Uint8Array, shared_key: Uint8Array): { request: GetSecretIdsVersionsRequestMessage };
    };
    response: {
      produce(channel_id: bigint, secret_list: SecretVersionEntry[], shared_key: Uint8Array): ProduceResult;
      extract(envelope_bytes: Uint8Array, shared_key: Uint8Array): { response: GetSecretIdsVersionsResponseMessage };
      process(response: GetSecretIdsVersionsResponseMessage): DiscoveryProcessResult;
    };
  };
  pairing: {
    request: {
      /**
       * Creates an out-of-band `ContactMessage` to bootstrap pairing.
       *
       * @param channel_id  Identifier for the local pairing session.
       * @param contact_mode  `ContactMode.InlineKeys` embeds the keys directly;
       *                      `ContactMode.HashedKeys` embeds only a SHA-384
       *                      commitment and the scanner must complete a
       *                      `PrePair` round-trip first.
       * @param transport_protocol  Endpoint the scanner uses to talk back. For
       *                            `HashedKeys` mode it MUST be ephemeral.
       */
      create_contact(
        channel_id: bigint,
        contact_mode: ContactMode | number,
        transport_protocol: TransportProtocol,
      ): CreateContactResult;
      encode_contact(contact_message: ContactMessage): Uint8Array;
      decode_contact(bytes: Uint8Array): ContactMessage;
      produce(
        kind: SenderKind,
        transport_protocol: TransportProtocol,
        contact_message: ContactMessage,
        communication_info: CommunicationInfo | null,
      ): PairingRequestProduceResult;

      extract(envelope_bytes: Uint8Array, secret_key: Uint8Array): { request: PairRequestMessage };

      /**
       * Scanner-side: build a plaintext `PrePairRequest` envelope when the
       * contact was sent in `HashedKeys` mode. The keys obtained via the
       * matching `PrePairResponse` MUST be checked against the contact's
       * binding hash with `pairing.response.process_pre_pair` before
       * proceeding to a normal `produce`.
       */
      produce_pre_pair(
        transport_protocol: TransportProtocol,
        contact_message: ContactMessage,
      ): ProducePrePairResult;

      /**
       * Initiator-side: decode an inbound plaintext `PrePairRequest`
       * envelope.
       */
      extract_pre_pair(envelope_bytes: Uint8Array): PrePairRequestExtractResult;
    };
    response: {
      produce(
        channel_id: bigint,
        request: PairRequestMessage,
        secret_key: Uint8Array,
        communication_info: CommunicationInfo | null,
      ): PairingResponseProduceResult;

      extract(envelope_bytes: Uint8Array, secret_key: Uint8Array): { response: PairResponseMessage };
      process(
        contact_message: ContactMessage,
        response: PairResponseMessage,
        secret_key: Uint8Array,
      ): PairingProcessResult;

      /**
       * Contact-creator side: publish the actual public keys back to the
       * scanner in response to a `PrePairRequest`.
       */
      produce_pre_pair(
        channel_id: bigint,
        request: PrePairRequestMessage,
        secret_key: Uint8Array,
      ): ProducePrePairResult;

      /**
       * Scanner-side: decode an inbound plaintext `PrePairResponse`
       * envelope.
       */
      extract_pre_pair(envelope_bytes: Uint8Array): PrePairResponseExtractResult;

      /**
       * Scanner-side: validate the `PrePairResponse` against the contact's
       * SHA-384 binding hash. Returns the validated public keys + echoed
       * nonce on match; throws on mismatch.
       */
      process_pre_pair(
        contact_message: ContactMessage,
        response: PrePairResponseMessage,
      ): ProcessPrePairResult;
    };
  };
  recovery: {
    request: {
      produce(
        channel_id: bigint,
        secret_id: bigint,
        version: number,
        shared_key: Uint8Array,
        /** See `discovery.request.produce.reply_to`. */
        reply_to?: TransportProtocol | null,
      ): ProduceResult;
      extract(envelope_bytes: Uint8Array, shared_key: Uint8Array): { request: GetShareRequestMessage };
    };
    response: {
      produce(
        channel_id: bigint,
        request: GetShareRequestMessage,
        stored_share_request: StoreShareRequestMessage,
        shared_key: Uint8Array,
      ): ProduceResult;
      extract(envelope_bytes: Uint8Array, shared_key: Uint8Array): { response: GetShareResponseMessage };
      recover(secret_id: bigint, version: number, responses: GetShareResponseMessage[]): RecoverResult;
    };
  };
  sharing: {
    request: {
      split(
        channels: bigint[],
        secret_id: bigint,
        version: number,
        secret_data: Uint8Array,
        threshold: number,
      ): SplitResult;
      produce(
        channel_id: bigint,
        version: number,
        secret_id: bigint,
        committed_share: CommittedDeRecShare,
        keep_list: number[],
        description: string,
        shared_key: Uint8Array,
        /** See `discovery.request.produce.reply_to`. */
        reply_to?: TransportProtocol | null,
      ): ProduceResult;
      extract(envelope_bytes: Uint8Array, shared_key: Uint8Array): { request: StoreShareRequestMessage };
    };
    response: {
      produce(
        channel_id: bigint,
        request: StoreShareRequestMessage,
        shared_key: Uint8Array,
      ): SharingResponseProduceResult;
      extract(envelope_bytes: Uint8Array, shared_key: Uint8Array): { response: StoreShareResponseMessage };
      process(version: number, response: StoreShareResponseMessage): void;
    };
  };
  unpairing: {
    request: {
      produce(
        channel_id: bigint,
        memo: string,
        shared_key: Uint8Array,
        /** See `discovery.request.produce.reply_to`. */
        reply_to?: TransportProtocol | null,
      ): ProduceResult;
      extract(envelope_bytes: Uint8Array, shared_key: Uint8Array): { request: UnpairRequestMessage };
    };
    response: {
      produce(channel_id: bigint, shared_key: Uint8Array): ProduceResult;
      extract(envelope_bytes: Uint8Array, shared_key: Uint8Array): { response: UnpairResponseMessage };
      process(response: UnpairResponseMessage): UnpairingProcessResult;
    };
  };
  verification: {
    request: {
      produce(
        channel_id: bigint,
        secret_id: bigint,
        version: number,
        shared_key: Uint8Array,
        /** See `discovery.request.produce.reply_to`. */
        reply_to?: TransportProtocol | null,
      ): ProduceResult;
      extract(envelope_bytes: Uint8Array, shared_key: Uint8Array): { request: VerifyShareRequestMessage };
    };
    response: {
      produce(
        channel_id: bigint,
        request: VerifyShareRequestMessage,
        shared_key: Uint8Array,
        share_content: Uint8Array,
      ): ProduceResult;
      extract(envelope_bytes: Uint8Array, shared_key: Uint8Array): { response: VerifyShareResponseMessage };

      process(response: VerifyShareResponseMessage, share_content: Uint8Array): boolean;
    };
  };
};
