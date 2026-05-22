// SPDX-License-Identifier: Apache-2.0
//
// Hand-authored type definitions for the DeRec WASM package.
//
// These reflect the REAL runtime surface produced by wasm-bindgen
// (`DeRecProtocolWasm`, re-exported here as `DeRecProtocol`): the low-level
// `start(flowKind, params) / process / accept / reject` API plus the four
// store interfaces. Keep this file in sync with:
//   - library/src/wasm/protocol/mod.rs   (constructor, parse_flow, methods)
//   - library/src/wasm/protocol/stores.rs (store JS contracts)
//   - library/src/wasm/protocol/events.rs (DeRecEvent shapes)

/** Initializes the WebAssembly module. Must be called before constructing
 *  `DeRecProtocol` or using any `primitives` function. */
export { default as init } from "./derec_library.js";

// ── Store interfaces ──────────────────────────────────────────────────────────

/**
 * Keychain-grade storage for cryptographic secrets.
 *
 * - kind 0 = SharedKey (32 raw bytes)
 * - kind 1 = PairingSecret (ark-serialized, ephemeral)
 * - kind 2 = PairingContact (protobuf-encoded ContactMessage, ephemeral)
 */
export interface SecretStore {
  load(channelId: string, kind: 0 | 1 | 2): Promise<Uint8Array | null | undefined>;
  save(channelId: string, kind: 0 | 1 | 2, value: Uint8Array): Promise<void>;
  remove(channelId: string, kind: 0 | 1 | 2): Promise<void>;
}

/**
 * Storage for paired channels AND the channel-link graph.
 *
 * `load`/`save` persist an opaque JSON-encoded channel record keyed by
 * channel id. Linking records that two channels belong to the same Owner
 * identity (undirected, idempotent, transitive); `linkedChannels` returns the
 * transitive closure of `channelId` **including `channelId` itself**.
 */
export interface ChannelStore {
  load(channelId: string): Promise<Uint8Array | null | undefined>;
  save(channelId: string, bytes: Uint8Array): Promise<void>;
  listChannels(): Promise<string[]>;
  remove(channelId: string): Promise<boolean>;
  linkChannel(channelId: string, linkedChannelId: string): Promise<void>;
  linkedChannels(channelId: string): Promise<string[]>;
}

/** A single stored share. `secretId` is a u64 secret identifier as a decimal string. */
export interface Share {
  secretId: string;
  version: number;
  bytes: Uint8Array;
}

/**
 * Pure keyed store for secret shares. It never sees the channel-link graph —
 * recovery resolves the linked channel set via `ChannelStore.linkedChannels`
 * and passes it to `loadMany`, scoped to a single `secretId`. Discovery uses
 * `loadAll` — the one legitimate "no secretId" load, since it enumerates the
 * helper's holdings before any secret is known.
 *
 * `secretId` is the u64 secret identifier as a decimal string (matching
 * `Share.secretId`). For `load`/`loadMany`, an empty `versions` array means
 * "all versions of `secretId`".
 *
 * Versions are namespaced by `secretId`: the same `version` number can
 * legitimately exist for two different secrets — a version-only query would
 * conflate them, which is why `secretId` is required on filtered loads.
 */
export interface ShareStore {
  load(channelId: string, secretId: string, versions: number[]): Promise<Share[]>;
  loadMany(channelIds: string[], secretId: string, versions: number[]): Promise<Share[]>;
  /** Discovery-only: every share for these channels — all secrets, all versions. */
  loadAll(channelIds: string[]): Promise<Share[]>;
  save(channelId: string, share: Share): Promise<void>;
  latestVersion(): Promise<number | null>;
}

/** Outbound message delivery. */
export interface Transport {
  send(endpoint: { protocol: string; uri: string }, message: Uint8Array): Promise<void>;
}

// ── Enums ─────────────────────────────────────────────────────────────────────

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

/**
 * Whether the unpair initiator waits for the peer's acknowledgement before
 * dropping local state. Passed as the last `DeRecProtocol` constructor
 * argument (`"required"` is the default).
 *
 * - `"required"`: keep local channel/share/secret state until the peer
 *   confirms with `Ok` or the configured protocol timeout elapses.
 * - `"not_required"`: drop local state immediately on `start(Unpair)` and
 *   ignore any later response (fire-and-forget).
 */
export type UnpairAck = "required" | "not_required";

// ── Plain message / value shapes ──────────────────────────────────────────────

/** Plain JS representation of a protobuf ContactMessage, as returned by `createContact`. */
export interface ContactMessage {
  channel_id: string;
  nonce: string;
  transport_protocol: { uri: string; protocol: string };
  mlkem_encapsulation_key: Uint8Array;
  ecies_public_key: Uint8Array;
}

/** An application secret inside the secret bag (ProtectSecret flow). */
export interface UserSecret {
  /** Application-defined identifier bytes. */
  id: Uint8Array;
  name: string;
  data: Uint8Array;
}

/** A single peer target: a channel id as a `bigint`. */
export type Target = bigint | bigint[] | null;

// ── `start()` flow parameters ─────────────────────────────────────────────────

export interface PairingParams {
  kind: SenderKind;
  contact: ContactMessage;
  /**
   * Free-form app-level identity metadata for the peer. Persisted verbatim
   * on the resulting channel's `communication_info`; the protocol never
   * inspects keys or values. Omit (or pass `{}`) to record nothing.
   * By convention, a `"name"` key holds a display name.
   */
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
  /** u64 secret id as a `bigint` or decimal string. */
  secretId: bigint | string;
  version: number;
}
export interface UnpairParams {
  target?: Target;
  /** Optional human-readable reason; shows up in the peer's `ActionRequired`
   *  event memo. Omit to send an empty string. */
  memo?: string;
}

// ── Events ────────────────────────────────────────────────────────────────────

/** Returned by `start`, `process`, and `accept`. */
export type DeRecEvent =
  | { type: "PairingCompleted"; channel_id: string; kind: SenderKind; peer_communication_info?: Record<string, string> }
  | {
      type: "ActionRequired";
      channel_id: string;
      /** Opaque token — pass back to `accept()` or `reject()`. */
      action: Uint8Array;
      /** "Pairing" | "StoreShare" | "VerifyShare" | "Discovery" | "GetShare" */
      action_kind: string;
      peer_communication_info?: Record<string, string>;
      /** For Pairing actions: the peer's SenderKind. */
      sender_kind?: SenderKind;
      /** For StoreShare/VerifyShare actions. */
      share_version?: number;
      share_description?: string;
      /** u64 secret id as a decimal string (may exceed 2^53). */
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
      /** `secret_id` is a u64 as a decimal string. */
      secrets: Array<{ secret_id: string; versions: Array<{ version: number; description: string }> }>;
    }
  | { type: "RecoveryShareReceived"; channel_id: string; shares_received: number }
  | { type: "RecoveryShareError"; channel_id: string; shares_received: number; error: string }
  | { type: "SecretRecovered"; secret: Uint8Array }
  /** A channel's local state was dropped as a result of an unpair flow —
   *  emitted on both sides. */
  | { type: "Unpaired"; channel_id: string }
  /** The peer rejected an outbound unpair request. Local state is **not**
   *  dropped; the application decides what to do next. */
  | { type: "UnpairRejected"; channel_id: string; status: number; memo: string }
  | { type: "NoOp" };

// ── Low-level protocol orchestrator ───────────────────────────────────────────

/**
 * The DeRec protocol object (wasm-bindgen `DeRecProtocolWasm`).
 *
 * Drive flows with `start(FlowKind, params)` (dispatches outbound messages via
 * the `Transport`; returns the channel id for `Pairing`, `null` otherwise).
 * Feed inbound wire bytes to `process(bytes)`, which returns `DeRecEvent[]`.
 * When a returned event has type `"ActionRequired"`, pass its `action` bytes to
 * `accept()` (performs the operation, returns more events) or `reject()`.
 *
 * Call `await init()` before constructing.
 */
export declare class DeRecProtocol {
  /**
   * @param channelStore           JS object implementing `ChannelStore`.
   * @param shareStore             JS object implementing `ShareStore`.
   * @param secretStore            JS object implementing `SecretStore`.
   * @param transport              JS object implementing `Transport`.
   * @param ownTransportUri        URI this node advertises to peers.
   * @param ownTransportProtocol   Protocol string — currently `"https"`.
   * @param threshold              Minimum shares required to reconstruct.
   * @param keepVersionsCount      Number of recent versions each Helper retains.
   * @param secretId               This node's u64 secret id as a `bigint`.
   * @param communicationInfo      Key/value identity map (e.g. `{ name }`).
   * @param timeoutInSecs           General protocol timeout (seconds). Passive
   *                               message/round expiry in `process()`. Default 300.
   * @param autoRespondOnFailure   When true, auto-send failure responses on
   *                               inbound processing errors. Default false.
   */
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
    /** Selects the unpair acknowledgement policy. Defaults to `"required"`. */
    unpairAck?: UnpairAck | null,
  );

  /** Generate a contact message. Returns a plain JS `ContactMessage` object. */
  createContact(channelId?: bigint | null): Promise<ContactMessage>;

  /**
   * Begin a protocol flow.
   *
   * Returns the new channel id (`bigint`) for `Pairing`, and `null` for every
   * other flow. Flows do NOT return events here — outbound messages are
   * dispatched via the `Transport`, and resulting events surface later from
   * `process()` / `accept()` on inbound messages.
   */
  start(flowKind: FlowKind.Pairing, params: PairingParams): Promise<bigint>;
  start(flowKind: FlowKind.Discovery, params: DiscoveryParams): Promise<null>;
  start(flowKind: FlowKind.ProtectSecret, params: ProtectSecretParams): Promise<null>;
  start(flowKind: FlowKind.VerifyShares, params: VerifySharesParams): Promise<null>;
  start(flowKind: FlowKind.RecoverSecret, params: RecoverSecretParams): Promise<null>;
  start(flowKind: FlowKind.Unpair, params: UnpairParams): Promise<null>;
  start(flowKind: number, params: unknown): Promise<bigint | null>;

  /** Feed inbound wire bytes; returns events to react to. */
  process(message: Uint8Array): Promise<DeRecEvent[]>;

  /** Accept an `ActionRequired` action (performs the requested operation). Returns events. */
  accept(actionBytes: Uint8Array): Promise<DeRecEvent[]>;

  /** Reject an `ActionRequired` action with a status code and memo. */
  reject(actionBytes: Uint8Array, status: number, memo: string): Promise<void>;
}

// ── Recovered secret-bag decoder ──────────────────────────────────────────────
//
// `SecretRecovered.secret` carries the protobuf-encoded `DeRecSecret` wrapping
// the `SecretContainer` bag. Use this helper to unwrap both layers into the
// same structured shape the owner originally protected.

export interface RecoveredHelperInfo {
  /** u64 channel id as decimal string. */
  channelId: string;
  transportUri: string;
  /** App-level identity metadata, opaque to the protocol. */
  communicationInfo: Record<string, string>;
  /** 32-byte shared key. (`Vec<u8>` arrives as `Array<number>`; convert if needed.) */
  sharedKey: Uint8Array | number[];
}

export interface RecoveredUserSecret {
  /** App-defined identifier (binary). */
  id: Uint8Array | number[];
  /** Human-readable label. */
  name: string;
  /** Raw secret bytes — apps that store text decode via `TextDecoder`. */
  data: Uint8Array | number[];
}

export interface RecoveredSecretBag {
  helpers: RecoveredHelperInfo[];
  secrets: RecoveredUserSecret[];
}

/**
 * Decode the bytes carried by a `SecretRecovered` event into the original
 * `SecretContainer` bag shape (helpers + secrets). Throws on malformed input.
 */
export declare function decodeRecoveredSecretBag(bytes: Uint8Array): RecoveredSecretBag;

/**
 * Re-populate the given (empty) channel/secret/share stores from a recovered
 * secret bag, so the caller can resume normal operation as if the bag had
 * been distributed by this device originally. The caller must wipe the
 * target namespace first; this function does not clear pre-existing state.
 *
 * @param channelStore   JS ChannelStore in the target namespace.
 * @param secretStore    JS SecretStore in the target namespace.
 * @param shareStore     JS ShareStore in the target namespace.
 * @param recoveredBytes Bytes carried by the `SecretRecovered` event.
 * @param secretId       u64 secret id as a decimal string.
 * @param version        Version restored.
 */
export declare function restoreFromRecoveredBag(
  channelStore: ChannelStore,
  secretStore: SecretStore,
  shareStore: ShareStore,
  recoveredBytes: Uint8Array,
  secretId: string,
  version: number,
): Promise<void>;

// ── Low-level primitives ──────────────────────────────────────────────────────
//
// Escape hatch mirroring crate::primitives::*. Argument/return shapes are
// plain JS objects specific to each step; typed loosely here on purpose —
// consult library/src/wasm/primitives/* for exact shapes.

export declare const primitives: {
  pairing: {
    request: {
      create_contact(channel_id: bigint, transport_protocol: any): any;
      encode_contact(contact_message: any): Uint8Array;
      decode_contact(bytes: Uint8Array): any;
      produce(kind: SenderKind, transport_protocol: any, contact_message: any): any;
    };
    response: {
      accept(kind: SenderKind, pair_request: any, pairing_secret_key_material: Uint8Array): any;
      reject(kind: SenderKind, pair_request: any): any;
      process(contact_message: any, pair_response: any, pairing_secret_key_material: Uint8Array): any;
    };
  };
  sharing: {
    request: {
      split(secret_id: bigint, secret_data: Uint8Array, channels: any, threshold: number, version: number): any;
      produce(channel_id: bigint, version: number, secret_id: bigint, committed_share: Uint8Array, keep_list: any, description: string, shared_key: Uint8Array): any;
    };
    response: {
      produce(channel_id: bigint, shared_key: Uint8Array, request: any): any;
      process(version: number, shared_key: Uint8Array, response: any): void;
    };
    decode_committed_share(bytes: Uint8Array): any;
  };
  verification: {
    request: {
      produce(channel_id: bigint, secret_id: bigint, version: number, shared_key: Uint8Array): any;
      extract(request: any, shared_key: Uint8Array): any;
    };
    response: {
      produce(channel_id: bigint, secret_id: bigint, version: number, nonce: bigint, shared_key: Uint8Array, stored_request: any): any;
      extract(response: any, shared_key: Uint8Array): any;
      process(response: any, shared_key: Uint8Array, stored_request: any): boolean;
    };
  };
  discovery: {
    request: {
      produce(channel_id: bigint, shared_key: Uint8Array): any;
      extract(request: any, shared_key: Uint8Array): any;
    };
    response: {
      produce(channel_id: bigint, secret_list: Array<{ secret_id: bigint; versions: Array<{ version: number; description: string }> }>, shared_key: Uint8Array): any;
      process(response: any, shared_key: Uint8Array): Array<{ secret_id: number; versions: Array<{ version: number; description: string }> }>;
    };
  };
  recovery: {
    request: {
      produce(channel_id: bigint, secret_id: bigint, version: number, shared_key: Uint8Array): any;
    };
    response: {
      produce(secret_id: bigint, channel_id: bigint, stored_share_request: any, request: any, shared_key: Uint8Array): any;
      recover(responses: any, secret_id: bigint, version: number): Uint8Array;
    };
  };
  unpairing: {
    request: {
      produce(channel_id: bigint, memo: string, shared_key: Uint8Array): any;
      extract(request: any, shared_key: Uint8Array): { channel_id: bigint; memo: string };
    };
    response: {
      produce(channel_id: bigint, shared_key: Uint8Array): any;
      reject(channel_id: bigint, shared_key: Uint8Array, status: number, memo: string): any;
      extract(response: any, shared_key: Uint8Array): { channel_id: bigint; status: number; memo: string };
      /** `true` when the response carried `StatusEnum.Ok`, `false` for any
       *  non-OK status. Throws if the response is malformed. */
      process(response: any, shared_key: Uint8Array): boolean;
    };
  };
};
