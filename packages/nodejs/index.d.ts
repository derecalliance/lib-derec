// SPDX-License-Identifier: Apache-2.0

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
  Replica = 2,
}

export enum FlowKind {
  Pairing = 0,
  Discovery = 1,
  ProtectSecret = 2,
  VerifyShares = 3,
  RecoverSecret = 4,
  Unpair = 5,
}

export type UnpairAck = "required" | "not_required";

export interface ContactMessage {
  channel_id: string;
  nonce: string;
  transport_protocol: { uri: string; protocol: string };
  mlkem_encapsulation_key: Uint8Array;
  ecies_public_key: Uint8Array;
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
  secrets: UserSecret[];
  description?: string;
}
export interface VerifySharesParams {
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
  | { type: "NoOp" };

export declare class DeRecProtocol {

  constructor(
    channelStore: ChannelStore,
    shareStore: ShareStore,
    secretStore: SecretStore,
    transport: Transport,
    ownTransportUri: string,
    ownTransportProtocol: string,
    threshold: number,
    keepVersionsCount: number,
    secretId: bigint,
    communicationInfo: Record<string, string>,
    timeoutInSecs?: number | null,
    autoRespondOnFailure?: boolean | null,

    unpairAck?: UnpairAck | null,
  );

  createContact(channelId?: bigint | null): Promise<ContactMessage>;

  start(flowKind: FlowKind.Pairing, params: PairingParams): Promise<bigint>;
  start(flowKind: FlowKind.Discovery, params: DiscoveryParams): Promise<null>;
  start(flowKind: FlowKind.ProtectSecret, params: ProtectSecretParams): Promise<null>;
  start(flowKind: FlowKind.VerifyShares, params: VerifySharesParams): Promise<null>;
  start(flowKind: FlowKind.RecoverSecret, params: RecoverSecretParams): Promise<null>;
  start(flowKind: FlowKind.Unpair, params: UnpairParams): Promise<null>;
  start(flowKind: number, params: unknown): Promise<bigint | null>;

  process(message: Uint8Array): Promise<DeRecEvent[]>;

  accept(actionBytes: Uint8Array): Promise<DeRecEvent[]>;

  reject(actionBytes: Uint8Array, status: number, memo: string): Promise<void>;
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

export interface ContactMessage {
  channel_id: bigint;
  transport_protocol?: TransportProtocol;
  nonce: bigint;
  mlkem_encapsulation_key: Uint8Array;
  ecies_public_key: Uint8Array;
  timestamp?: Timestamp;
}

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
  channel_id: bigint;
  nonce: bigint;
  communication_info?: CommunicationInfo;
  parameter_range?: ParameterRange;
  transport_protocol?: TransportProtocol;
  timestamp?: Timestamp;
}

export interface PairResponseMessage {
  sender_kind: number;
  result?: DeRecResult;
  nonce: bigint;
  communication_info?: CommunicationInfo;
  parameter_range?: ParameterRange;
  timestamp?: Timestamp;
}

export interface GetShareRequestMessage {
  secret_id: bigint;
  version: number;
  timestamp?: Timestamp;
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

export interface AcceptResult extends ProduceResult {
  peer_transport_protocol: TransportProtocol;

  shared_key: Uint8Array;
}

export interface RejectResult extends ProduceResult {
  peer_transport_protocol: TransportProtocol;
}

export interface PairingProcessResult {

  shared_key: Uint8Array;
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
      produce(channel_id: bigint, shared_key: Uint8Array): ProduceResult;
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
      create_contact(channel_id: bigint, transport_protocol: TransportProtocol): CreateContactResult;
      encode_contact(contact_message: ContactMessage): Uint8Array;
      decode_contact(bytes: Uint8Array): ContactMessage;
      produce(
        kind: SenderKind,
        transport_protocol: TransportProtocol,
        contact_message: ContactMessage,
        communication_info: CommunicationInfo | null,
      ): PairingRequestProduceResult;

      extract(envelope_bytes: Uint8Array, secret_key: Uint8Array): { request: PairRequestMessage };
    };
    response: {
      accept(
        kind: SenderKind,
        request: PairRequestMessage,
        secret_key: Uint8Array,
        communication_info: CommunicationInfo | null,
      ): AcceptResult;
      reject(
        kind: SenderKind,
        request: PairRequestMessage,
        status: number,
        memo: string,
        communication_info: CommunicationInfo | null,
      ): RejectResult;

      extract(envelope_bytes: Uint8Array, secret_key: Uint8Array): { response: PairResponseMessage };
      process(
        contact_message: ContactMessage,
        response: PairResponseMessage,
        secret_key: Uint8Array,
      ): PairingProcessResult;
    };
  };
  recovery: {
    request: {
      produce(channel_id: bigint, secret_id: bigint, version: number, shared_key: Uint8Array): ProduceResult;
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
      produce(channel_id: bigint, memo: string, shared_key: Uint8Array): ProduceResult;
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
      produce(channel_id: bigint, secret_id: bigint, version: number, shared_key: Uint8Array): ProduceResult;
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
