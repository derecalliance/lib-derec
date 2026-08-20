// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

export { default as init } from "./derec_library.js";

export interface SecretStore {
  load(
    secretId: string,
    channelId: string,
    kind: 0 | 1 | 2,
  ): Promise<Uint8Array | null | undefined>;
  /**
   * Load secrets of the same `kind` for several channels in one call,
   * scoped to `secretId`. Must return an array with one entry per input
   * id, in the same order, using `null` (or `undefined`) for channels
   * with no stored secret of `kind`.
   */
  loadMany(
    secretId: string,
    channelIds: string[],
    kind: 0 | 1 | 2,
    missingPolicy: "skip" | "fail",
  ): Promise<Array<Uint8Array | null | undefined>>;
  save(
    secretId: string,
    channelId: string,
    kind: 0 | 1 | 2,
    value: Uint8Array,
  ): Promise<void>;
  remove(secretId: string, channelId: string, kind: 0 | 1 | 2): Promise<void>;
}

/**
 * Channel-record persistence.
 *
 * A record is addressed by `(channelId, replicaId)`. A `replicaId` of `"0"` —
 * the value the protocol reserves as "absent" — addresses the helper channel
 * at `channelId`.
 *
 * Any other value addresses that member of the replica group, and the member
 * is keyed by **`replicaId` alone**. The accompanying `channelId` is context,
 * not part of the key: a member moves between channels during an admission
 * handover while remaining the same member, and a lookup that required both to
 * match would miss it exactly when the move needs to be observed. Keep two
 * maps — helpers by `channelId`, members by `replicaId` — not one keyed by the
 * pair.
 *
 * `load`/`save` bytes are a JSON-encoded `ChannelRecord`: an externally
 * tagged union carrying exactly one of `Helper` or `Replica`. `listHelpers`
 * and `listReplicas` return a JSON-encoded array of the corresponding
 * records. All payloads are opaque to the application — persist them
 * verbatim.
 */
export interface ChannelStore {
  load(
    secretId: string,
    channelId: string,
    replicaId: string,
  ): Promise<Uint8Array | null | undefined>;
  save(
    secretId: string,
    channelId: string,
    replicaId: string,
    bytes: Uint8Array,
  ): Promise<void>;
  remove(secretId: string, channelId: string, replicaId: string): Promise<boolean>;
  /** JSON array of the helper channels stored under `secretId`. */
  listHelpers(secretId: string): Promise<Uint8Array | null | undefined>;
  /**
   * JSON array of the replica-group members stored under `secretId`,
   * including this device's own row.
   *
   * The order is significant in exactly one situation. A group has one member
   * holding the `Source` role; when it is removed, the protocol promotes the
   * first element of this array that is neither the departing member nor
   * itself leaving. Ordering this array is therefore how an application
   * chooses its succession policy. The choice is read once, on the single
   * device running the removal, and is then published in the roster, so
   * implementations on different devices need not agree on order. Nothing else
   * consults it.
   *
   * Returning an arbitrary order is correct and simply delegates the choice to
   * the storage — note that an IndexedDB cursor without an explicit index and
   * `Map` insertion order after arbitrary edits are both effectively
   * arbitrary. Order explicitly to make succession predictable.
   */
  listReplicas(secretId: string): Promise<Uint8Array | null | undefined>;
  linkChannel(
    secretId: string,
    channelId: string,
    linkedChannelId: string,
  ): Promise<void>;
  linkedChannels(secretId: string, channelId: string): Promise<string[]>;
}

export interface Share {
  secretId: string;
  version: number;
  bytes: Uint8Array;
}

export interface ShareStore {
  load(secretId: string, channelId: string, versions: number[]): Promise<Share[]>;
  loadMany(
    secretId: string,
    channelIds: string[],
    versions: number[],
  ): Promise<Share[]>;
  loadAll(secretId: string, channelIds: string[]): Promise<Share[]>;
  save(secretId: string, channelId: string, share: Share): Promise<void>;
  latestVersion(secretId: string): Promise<number | null>;
  removeChannel(secretId: string, channelId: string): Promise<void>;
}

export interface UserSecretEntry {
  id: Uint8Array;
  name: string;
  data: Uint8Array;
}

export interface UserSecrets {
  version: number;
  secrets: UserSecretEntry[];
  description?: string;
}

/**
 * Persistence for the user-facing secret contents, keyed by `secretId`.
 * One `secretId` maps to at most one stored snapshot — the most recent
 * `start(ProtectSecret)` value. Read back by the pair-completion
 * auto-publish hook so freshly-paired peers receive the current secret.
 */
export interface UserSecretStore {
  loadLatest(secretId: string): Promise<UserSecrets | null | undefined>;
  saveLatest(secretId: string, value: UserSecrets): Promise<void>;
  remove(secretId: string): Promise<void>;
}

/**
 * In-flight orchestrator state persistence. The library treats item
 * payloads as opaque JSON blobs — `save` writes the blob, `load`
 * returns the exact blob it received, `remove` drops the row, and
 * `loadAll` returns every blob whose `kind` matches the requested
 * category (`0` = PendingVerification, `1` = PendingRecovery,
 * `2` = PendingUnpair, `3` = SharingRound).
 *
 * Rows are keyed by `(secretId, StateKey)` — the `keyJson` buffer is
 * a JSON object `{ kind, channel_id?, version? }` matching the `kind`
 * numbering above. The library will `save`/`load`/`remove` under the
 * same key across a session, so implementations can hash the entire
 * `keyJson` buffer or unpack its fields (`kind` + `channel_id` +
 * `version`) as the composite key.
 *
 * Save is full-replacement upsert — accumulator-style state
 * (PendingRecovery and SharingRound) grows via load-modify-save cycles
 * from the library; no per-row append primitive is required.
 */
export interface StateStore {
  save(secretId: string, itemJson: Uint8Array): Promise<void>;
  load(
    secretId: string,
    keyJson: Uint8Array,
  ): Promise<Uint8Array | null | undefined>;
  remove(secretId: string, keyJson: Uint8Array): Promise<boolean>;
  loadAll(secretId: string, kind: 0 | 1 | 2 | 3 | 4): Promise<Uint8Array[]>;
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
 * - `NoKeys`: no key material and no commitment. The contact carries only
 *   `channel_id`, `nonce`, and `transport_protocol` — small enough to be
 *   hand-typed or dictated. Keys are generated on the fly by the contact
 *   creator when the `PrePairRequest` arrives; the scanner accepts them
 *   without cryptographic verification. Trust rests entirely on the OOB
 *   delivery channel being fully trusted (e.g. a verified email from an
 *   already-KYC-authenticated institution). Applications MUST rate-limit
 *   inbound `PrePairRequest`s per channel and expire outstanding NoKeys
 *   contacts on a short timer.
 */
export enum ContactMode {
  InlineKeys = 0,
  HashedKeys = 1,
  NoKeys = 2,
}

export enum FlowKind {
  Pairing = 0,
  Discovery = 1,
  ProtectSecret = 2,
  VerifyShares = 3,
  RecoverSecret = 4,
  Unpair = 5,
  UpdateChannelInfo = 6,
  /** Ask the replica group whether this device is behind, and catch up if it
   *  is. Replica-only, and takes no parameters — the group and this device's
   *  own version both come from the stores. */
  SyncCheck = 7,
  /** Remove a member from the replica group. Replica-only. Naming this device
   *  is a voluntary departure; naming another is an eviction. Params:
   *  `{ replica_id: string; memo?: string }` — `replica_id` is a decimal
   *  string so ids above 2^53 survive JS number handling. */
  RemoveReplica = 8,
}

export type UnpairAck = "required" | "not_required";

export interface ContactMessage {
  channel_id: bigint;
  /** `ContactMode` numeric value (0 = INLINE_KEYS, 1 = HASHED_KEYS, 2 = NO_KEYS). */
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
  channel_id: string;

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
  | {
      type: "PairingCompleted";
      /** Long-term `channel_id` both peers atomically rotated to at handshake completion. */
      channel_id: string;
      /** Transient `channel_id` used only during pairing (the one that traveled on the ContactMessage). No longer resolves in library state. */
      pairing_channel_id: string;
      kind: SenderKind;
      peer_communication_info?: Record<string, string>;
    }
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
  /** A group member refused a secret sync. Keyed by `replica_id`, not
   *  `channel_id`: every member answers on the one group channel. A
   *  `VERSION_CONFLICT` status means the round must be resolved and
   *  republished at a new version. */
  | {
      type: "ReplicaSyncRejected";
      replica_id: string;
      secret_id: string;
      version: number;
      status: number;
      memo: string;
    }
  /** A secret sync could not be delivered to a member at all — distinct from
   *  `ReplicaSyncRejected`, which is the member answering "no". */
  | { type: "ReplicaSyncFailed"; replica_id: string; version: number; reason: string }
  /** A member left the group and its roster row was dropped. Fires on the
   *  members that remain. */
  | { type: "ReplicaRemoved"; replica_id: string }
  /** The group's source role moved to another member because the previous
   *  source is leaving. Fires on the device that chose the successor — which
   *  it does by the order its channel store returns members in — and on the
   *  successor itself when the roster promoting it arrives. */
  | { type: "ReplicaSourceChanged"; replica_id: string }
  /** This device left the group and dropped its whole `secret_id` partition —
   *  group channel, helper channels, shares, secrets and the snapshot. Fires
   *  only once it was told to leave *and* has since seen a roster excluding
   *  it; absence alone never destroys a copy of the secret. */
  | { type: "SelfRemovedFromGroup"; version: number }
  /** A replica catch-up finished. `fetched_from` is absent when this device
   *  was already current, in which case no hydration event follows. */
  | {
      type: "SyncCheckComplete";
      local_version: number;
      group_version: number;
      fetched_from?: string;
    }
  /** The replica leg of a publishing round finished. Reported separately from
   *  `SharingComplete`: replicas are best-effort, so a member in `behind` does
   *  not fail the round. `behind` is the application's retry list — the
   *  library keeps no durable per-member sync state. */
  | { type: "ReplicaSyncComplete"; version: number; synced: string[]; behind: string[] }
  | { type: "ShareVerified"; channel_id: string; version: number }
  | {
      type: "SecretsDiscovered";
      channel_id: string;

      secrets: Array<{ secret_id: string; versions: Array<{ version: number; description: string }> }>;
    }
  | { type: "RecoveryShareReceived"; channel_id: string; shares_received: number }
  | { type: "RecoveryShareError"; channel_id: string; shares_received: number; error: string }
  /** Recovery completed — the typed `Secret` snapshot the owner
   *  originally protected. Mirrors `ReplicaSecretReceived.secret`:
   *  `secrets` is the user-facing `Vec<UserSecret>` the application
   *  fed to `start(FlowKind.ProtectSecret)`; `helpers` and `replicas`
   *  are the roster snapshot captured at distribution time. The library handles the two-stage
   *  `DeRecSecret` → `Secret` protobuf decode internally. */
  | {
      type: "SecretRecovered";
      secret: {
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
        /** Replica composite. Absent when this `secret_id` has no
         *  replica setup. Carries the full member roster, the one channel
         *  they share, and the 32-byte group key. Required by `restore` to
         *  rebuild replica state without re-pairing. */
        replicas?: {
          /** The one channel every member is addressed on. */
          channel_id: string;
          /** Every member of the group, including the writer. Exactly one
           *  carries `role: "Source"` — that member is where the secret
           *  originated, which is why no separate owner field is needed. */
          members: Array<{
            replica_id: string;
            transport_uri: string;
            role: "Source" | "Destination";
            communication_info: Record<string, string>;
          }>;
          shared_key: Uint8Array;
        };
      };
    }

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
  /** A `ReplicaSource` peer pushed a secret sync on a
   *  `ReplicaDestination` channel. The library decoded the
   *  `ReplicaSecretPayload`; the app installs `secret.secrets` and
   *  optionally uses `shares` for recovery. `from_replica_id` and the
   *  `replica_id` fields inside `secret` are hex-encoded `u64`. */
  | {
      type: "ReplicaSecretReceived";
      channel_id: string;
      from_replica_id: string;
      secret_id: string;
      version: number;
      secret: {
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
        /** Replica composite. Absent when this `secret_id` has no
         *  replica setup. The same shape as `SecretRecovered.secret.replicas`. */
        replicas?: {
          /** The one channel every member is addressed on. */
          channel_id: string;
          /** Every member of the group, including the writer. Exactly one
           *  carries `role: "Source"` — that member is where the secret
           *  originated, which is why no separate owner field is needed. */
          members: Array<{
            replica_id: string;
            transport_uri: string;
            role: "Source" | "Destination";
            communication_info: Record<string, string>;
          }>;
          shared_key: Uint8Array;
        };
      };
      shares: Array<{
        channel_id: string;
        committed_share: Uint8Array;
      }>;
    }
  /** The first sync for a `secret_id` this device had no snapshot for —
   *  the secret now exists here. Same payload as `ReplicaSecretReceived`,
   *  which reports a later version of a secret the device already held.
   *  Both are written to the stores by the library before the event is
   *  delivered; the distinct type is what tells an application the set of
   *  secrets on the device changed.
   *
   *  This is not a recovery: recovery reconstructs a secret from helper
   *  shares and is driven by the application through `restore`. */
  | {
      type: "ReplicaSecretInstalled";
      channel_id: string;
      from_replica_id: string;
      secret_id: string;
      version: number;
      secret: {
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
        /** Replica composite. Absent when this `secret_id` has no
         *  replica setup. The same shape as `SecretRecovered.secret.replicas`. */
        replicas?: {
          /** The one channel every member is addressed on. */
          channel_id: string;
          /** Every member of the group, including the writer. Exactly one
           *  carries `role: "Source"` — that member is where the secret
           *  originated, which is why no separate owner field is needed. */
          members: Array<{
            replica_id: string;
            transport_uri: string;
            role: "Source" | "Destination";
            communication_info: Record<string, string>;
          }>;
          shared_key: Uint8Array;
        };
      };
      shares: Array<{
        channel_id: string;
        committed_share: Uint8Array;
      }>;
    }
  /** Peer's ack of a secret sync we sent. `status` is the `StatusEnum`
   *  integer (0 = Ok), `memo` is the peer's explanation. */
  | {
      type: "ReplicaSecretAcked";
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
  /** Emitted by `process()` in place of `ActionRequired` when the
   *  configured {@link AutoAcceptPolicy} opts in to the inbound
   *  action's flow. The same event vec carries the flow's completion
   *  events (e.g. `ShareStored`, `PairingCompleted`). Use this purely
   *  for observability — no further action is required. `action_kind`
   *  is the same label vocabulary as `ActionRequired.action_kind`
   *  (`"Pairing"`, `"StoreShare"`, …). */
  | { type: "AutoAccepted"; channel_id: string; action_kind: string }
  | { type: "NoOp" }
  /** A pairing handshake was dispatched successfully. `kind` is the
   *  local party's role — same value the subsequent `PairingCompleted`
   *  will carry. Emitted by `start(Pairing)`. */
  | { type: "PairingStarted"; channel_id: string; kind: SenderKind }
  /** A discovery request was dispatched to `channel_id`. Emitted per
   *  targeted helper by `start(Discovery)`. */
  | { type: "DiscoveryStarted"; channel_id: string }
  /** A discovery request could not be dispatched to `channel_id`. Other
   *  targeted channels are unaffected. */
  | { type: "DiscoveryFailed"; channel_id: string; error: string }
  /** A share-storage request was dispatched to `channel_id`. Emitted per
   *  targeted peer by `start(ProtectSecret)`. */
  | { type: "ProtectSecretStarted"; channel_id: string; version: number }
  /** A share-storage request could not be dispatched to `channel_id`. */
  | {
      type: "ProtectSecretFailed";
      channel_id: string;
      version: number;
      error: string;
    }
  /** A verify-share challenge was dispatched to `channel_id`. */
  | { type: "VerifySharesStarted"; channel_id: string; version: number }
  /** A verify-share challenge could not be dispatched to `channel_id`. */
  | {
      type: "VerifySharesFailed";
      channel_id: string;
      version: number;
      error: string;
    }
  /** A recovery share request was dispatched to `channel_id`. */
  | { type: "RecoverSecretStarted"; channel_id: string; version: number }
  /** A recovery share request could not be dispatched to `channel_id`. */
  | {
      type: "RecoverSecretFailed";
      channel_id: string;
      version: number;
      error: string;
    }
  /** An unpair request was dispatched to `channel_id`. Followed by an
   *  `Unpaired` event once the peer acknowledges (or in the same event
   *  vec, under `UnpairAck.NotRequired`). */
  | { type: "UnpairFailed"; channel_id: string; error: string }
  | { type: "UnpairStarted"; channel_id: string }
  /** An update-channel-info request was dispatched to `channel_id`. */
  | { type: "UpdateChannelInfoStarted"; channel_id: string }
  /** An update-channel-info request could not be dispatched to
   *  `channel_id`. */
  | { type: "UpdateChannelInfoFailed"; channel_id: string; error: string };

/**
 * Per-flow auto-accept policy. When a field is `true`, `process()`
 * internally accepts the matching inbound request and emits
 * `AutoAccepted` in place of `ActionRequired`. Every field defaults
 * to `false`.
 *
 * Per-field caveats (read before enabling in production):
 * - `pairing` — covers standard and replica pairing. Replica pairing
 *   remains `Pending` until both sides run `verifyFingerprint()`, so
 *   auto-accept is safe for replicas. Standard pairing transitions to
 *   `Paired` immediately.
 * - `prePair` — turns the initiator into a request-amplification
 *   oracle. Anyone who knows a HashedKeys contact's nonce can elicit a
 *   key-publish response. Keep off unless you control both ends of
 *   the transport.
 * - `storeShare` — the helper's only admission-control point for
 *   inbound shares. The protocol enforces no size, quota or rate limit
 *   of its own, and `maxShareSize` is checked for range overlap at
 *   pairing time only, never against an actual share. While this is
 *   `false`, `ActionRequired` carries the decoded request, so the
 *   application can inspect the share and call `reject()` with
 *   `StatusEnum.SizeLimitExceeded`. Setting it `true` removes that
 *   opportunity entirely: every share from every paired Owner is stored
 *   unconditionally, at whatever size it arrives. Keep off in any
 *   deployment with per-user storage limits.
 * - `unpair` — destructive. Accepting deletes the local channel
 *   record before any UI confirmation.
 * - `updateChannelInfo` — silently overwrites the channel record with
 *   the peer's announced transport / communication info.
 */
export interface AutoAcceptPolicy {
  pairing?: boolean;
  prePair?: boolean;
  storeShare?: boolean;
  verifyShare?: boolean;
  discovery?: boolean;
  getShare?: boolean;
  unpair?: boolean;
  updateChannelInfo?: boolean;
}

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
  /**
   * Construct a builder bound to a specific secret. `secretId`
   * identifies the single secret this protocol instance manages.
   * Apps that juggle multiple secrets instantiate one
   * {@link DeRecProtocol} per id.
   */
  constructor(secretId: bigint | number);

  withChannelStore(store: ChannelStore): DeRecProtocolBuilder;
  withShareStore(store: ShareStore): DeRecProtocolBuilder;
  withSecretStore(store: SecretStore): DeRecProtocolBuilder;
  withUserSecretStore(store: UserSecretStore): DeRecProtocolBuilder;
  withStateStore(store: StateStore): DeRecProtocolBuilder;
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
   * Per-flow auto-accept policy. When a field is `true`, `process()`
   * internally accepts the matching inbound request and emits
   * `AutoAccepted` in place of `ActionRequired`. See
   * {@link AutoAcceptPolicy} for per-field caveats.
   *
   * Default: empty policy (every flow off).
   */
  withAutoAccept(policy: AutoAcceptPolicy): DeRecProtocolBuilder;
  /**
   * Stable per-device replica id. Required to participate in any
   * `ReplicaSource` / `ReplicaDestination` pairing. The id must be
   * stable across restarts. Default: unset.
   */
  withReplicaId(id: bigint | number): DeRecProtocolBuilder;
  /**
   * Automatic removal of expired `Pending` channels during `process()`.
   *
   * Both arguments are always forwarded to the library. When `enabled` is
   * `false` the library ignores `timeoutInSecs`; that decision is not made
   * in this binding. A timeout of `0` is clamped to 1 by the library.
   *
   * `Pending` covers both an in-flight pairing handshake and a replica
   * channel awaiting out-of-band fingerprint verification, and one timeout
   * governs both. Fingerprint verification is paced by a human, so
   * deployments that pair replicas should raise the timeout, or disable it
   * and call {@link DeRecProtocol.removeExpiredChannels} on their own
   * schedule.
   *
   * Not calling this leaves the library's default in force.
   */
  withRemoveExpiredChannels(enabled: boolean, timeoutInSecs: number): DeRecProtocolBuilder;

  /**
   * Finalize the configuration. Throws if any of the required setters
   * was not called.
   */
  build(): DeRecProtocol;
}

export declare class DeRecProtocol {
  /** Use {@link DeRecProtocolBuilder} to construct instances. */
  private constructor();

  /** The secret identifier this protocol instance is bound to. */
  secretId(): bigint;

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
  /**
   * Single entry point for all three `ContactMode` variants.
   *
   * @param channelId `null`/`undefined` lets the library mint a random id.
   * @param contactMode `InlineKeys` embeds keys directly; `HashedKeys`
   * embeds only a SHA-384 commitment (keys fetched via `PrePair`);
   * `NoKeys` carries no key material — the creator generates keys on the
   * fly when the `PrePairRequest` arrives. Only appropriate for `NoKeys`
   * when the OOB delivery channel is fully trusted.
   * @param nonce `null`/`undefined` lets the library generate a fresh
   * random `bigint`. Required for `NoKeys` where callers typically pick
   * a small human-typable value.
   */
  createContact(
    channelId: bigint | null | undefined,
    contactMode: ContactMode,
    nonce?: bigint | null,
  ): Promise<ContactMessage>;

  start(flowKind: FlowKind.Pairing, params: PairingParams): Promise<DeRecEvent[]>;
  start(flowKind: FlowKind.Discovery, params: DiscoveryParams): Promise<DeRecEvent[]>;
  start(flowKind: FlowKind.ProtectSecret, params: ProtectSecretParams): Promise<DeRecEvent[]>;
  start(flowKind: FlowKind.VerifyShares, params: VerifySharesParams): Promise<DeRecEvent[]>;
  start(flowKind: FlowKind.RecoverSecret, params: RecoverSecretParams): Promise<DeRecEvent[]>;
  start(flowKind: FlowKind.Unpair, params: UnpairParams): Promise<DeRecEvent[]>;
  start(flowKind: FlowKind.UpdateChannelInfo, params: UpdateChannelInfoParams): Promise<DeRecEvent[]>;

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

  /**
   * Advance time-driven state without an inbound message.
   *
   * Timeouts are otherwise only evaluated by `process`, so a publish whose
   * helpers all go quiet has nothing left to close it: the round stays open
   * and no `SharingComplete` is ever emitted. Call this from a timer —
   * `setInterval`, a service-worker alarm, a job runner — at an interval
   * shorter than the configured timeout.
   *
   * Safe to call at any time; with nothing in flight it resolves to an empty
   * array. It mutates the same round state an inbound response does, so it
   * must be serialized against `process` for the same `secretId`.
   */
  tick(): Promise<DeRecEvent[]>;

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
  /**
   * Remove `Pending` channels older than `olderThanSecs`, along with their
   * pairing keys. Resolves to the removed channel ids as decimal strings.
   *
   * Independent of the configured cleanup policy — this sweeps at the
   * threshold given even when that policy is disabled. The age comparison
   * is strict, so a channel created within the current second survives
   * even `0`.
   */
  removeExpiredChannels(olderThanSecs: number): Promise<string[]>;

  /**
   * Rebuild this protocol's `secret_id` namespace from a recovered
   * `Secret`. Mirrors the Rust `DeRecProtocol::restore` — pass the
   * typed `secret` carried by the `SecretRecovered` event verbatim.
   *
   * Errors surface as structured objects with a `code` field:
   *
   * | code               | meaning                                                          |
   * |--------------------|------------------------------------------------------------------|
   * | `ALREADY_RESTORED` | A user-secret snapshot already exists for this `secret_id`.      |
   * | `CONFLICT`         | Channels live at canonical helper / replica ids. The error       |
   * |                    | carries `channel_ids: string[]` listing the collisions.          |
   * | `INVARIANT`        | The recovered `Secret` is internally inconsistent.               |
   * | `STORAGE`          | A store I/O call failed mid-restore.                             |
   */
  restore(
    recoveredSecret: Extract<DeRecEvent, { type: "SecretRecovered" }>["secret"],
    version: number,
  ): Promise<DeRecEvent[]>;
}

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
        parameter_range: ParameterRange | null,
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
        parameter_range: ParameterRange | null,
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

      /** `request` must be the request the owner previously produced
       *  for this challenge (kept by the caller in a per-channel
       *  pending-verification map). Responses whose
       *  `(nonce, secret_id, version)` triple doesn't match are
       *  rejected — that's the anti-replay gate. */
      process(
        request: VerifyShareRequestMessage,
        response: VerifyShareResponseMessage,
        share_content: Uint8Array,
      ): boolean;
    };
  };
};
