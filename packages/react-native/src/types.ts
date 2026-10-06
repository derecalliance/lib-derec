// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

import { getNative } from './native';

export interface SecretStore {
  load(
    secretId: string,
    channelId: string,
    kind: 0 | 1 | 2,
  ): Promise<Uint8Array | null | undefined>;
  /**
   * Load secrets of the same `kind` for several channels in one call,
   * scoped to `secretId`. Must return an array with exactly one entry per
   * input id, in the same order, using `null` (or `undefined`) for channels
   * with no stored secret of `kind`. Whether a missing entry is an error is
   * decided by the library.
   */
  loadMany(
    secretId: string,
    channelIds: string[],
    kind: 0 | 1 | 2,
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
 * A channel's lifecycle status, as the Rust variant name the core emits.
 */
export type ChannelStatusName = "Pending" | "Paired" | "Unpairing";

/**
 * A peer's role on a helper channel, as the Rust variant name.
 */
export type SenderKindName =
  | "Owner"
  | "Helper"
  | "ReplicaSource"
  | "ReplicaDestination";

/**
 * A member's role within a replica group, as the Rust variant name.
 */
export type ReplicaRoleName = "Source" | "Destination";

/**
 * Narrows a listing from {@link ChannelStore}.
 *
 * Every field is a restriction, and every field's empty value means "do not
 * restrict on this" — a filter of all-empties selects everything.
 * Restrictions combine with AND, and `exclude` is applied last, overriding
 * `ids`.
 *
 * **Returning everything under the `secretId` and ignoring the filter is
 * correct**, and the implementation to write unless there is a measured reason
 * not to. The library re-applies the filter to whatever you return and drops
 * what it excludes, so a superset is trimmed before anything acts on it.
 *
 * Pushing the filter into your query — a `WHERE` clause, a key-condition
 * expression — is an optimization you opt into. It saves transferring rows the
 * caller discards, which costs bandwidth everywhere and real money on a metered
 * backing that bills by bytes read. Verify one against
 * `library/tests/fixtures/channel_filter.json`.
 *
 * The asymmetry is what makes pushdown worth verifying: the re-check can drop
 * rows but cannot recover one that was never returned, so selecting too *few*
 * is undetectable at runtime — no exception, no event, just a share that was
 * never published. That matters most here, because TypeScript accepts a
 * function of fewer parameters where more are declared: a store written before
 * this parameter existed still satisfies the interface and compiles clean under
 * `--strict`, so the type system cannot see the gap either.
 *
 * Ids are decimal strings, like every other `u64` on this bridge.
 */
export interface ChannelFilter<Role> {
  /** Restrict to these ids. Empty selects every record. */
  ids: string[];
  /** Restrict to these statuses. Empty selects any status. */
  status: ChannelStatusName[];
  /** Restrict to this role. `null` selects any role. */
  role: Role | null;
  /** Omit these ids, applied after `ids`. Empty omits nothing. */
  exclude: string[];
}

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
export function channelFilterMatches(
  filter: HelperFilter | ReplicaFilter | null | undefined,
  id: string,
  status: ChannelStatusName,
  role: SenderKindName | ReplicaRoleName,
): boolean {
  if (!filter) return true;
  const ids = filter.ids ?? [];
  const statuses = filter.status ?? [];
  const exclude = filter.exclude ?? [];
  if (ids.length > 0 && !ids.includes(id)) return false;
  if (statuses.length > 0 && !statuses.includes(status)) return false;
  if (filter.role != null && filter.role !== role) return false;
  return !exclude.includes(id);
}

/**
 * The endpoints a peer-supplied message advertises, in the peer's own order.
 *
 * Reports what was advertised, not what is acceptable — nothing here is
 * validated, and the protocol still applies its own transport policy to
 * whatever it records.
 */
export function advertisedEndpoints(
  message: { supported_transports?: TransportProtocol[] } | null | undefined,
): TransportProtocol[] {
  if (!message) return [];
  return message.supported_transports ?? [];
}

/**
 * Narrows `listHelpers`. Ids are the channel's `channel_id` and the role is
 * the **peer's** `peer_role`.
 */
export type HelperFilter = ChannelFilter<SenderKindName>;

/**
 * Narrows `listReplicas`. Ids are the member's `replica_id` and the role is
 * the member's `role`.
 */
export type ReplicaFilter = ChannelFilter<ReplicaRoleName>;

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
 * tagged union carrying exactly one of `Helper` or `Replica`.
 *
 * `listHelpers` and `listReplicas` are **not** arrays of that union — they
 * return a JSON array of the **inner** records with the tag stripped:
 * `[{ schema_version, channel_id, transports, ... }, ...]`, `HelperChannel` for the first and
 * `ReplicaMember` for the second. Wrapping each element back in
 * `{ "Helper": ... }` will not decode.
 *
 * Build that array by **splicing the stored bytes as text** — the payloads are
 * opaque, so persist and re-emit them verbatim:
 *
 * ```js
 * const inner = rows.map((r) => new TextDecoder().decode(r));
 * return new TextEncoder().encode(`[${inner.join(",")}]`);
 * ```
 *
 * Do not `JSON.parse` and re-serialise. Every id in these records is a `u64`,
 * and `JSON.parse` silently rounds anything above 2^53 — the corruption only
 * appears once a real id happens to be large.
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
  /**
   * JSON array of the helper channels stored under `secretId` that `filter`
   * selects.
   *
   * Apply the filter in your query rather than listing everything and
   * discarding rows; see {@link ChannelFilter}. The library re-applies it to
   * whatever you return, so ignoring it is slow rather than wrong — but
   * returning fewer rows than it selects is wrong, and undetectable.
   */
  listHelpers(
    secretId: string,
    filter: HelperFilter,
  ): Promise<Uint8Array | null | undefined>;
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
   * the storage — note that a SQL `SELECT` without `ORDER BY` and `Map`
   * insertion order after arbitrary edits are both effectively arbitrary.
   * Order explicitly to make succession predictable.
   */
  listReplicas(
    secretId: string,
    filter: ReplicaFilter,
  ): Promise<Uint8Array | null | undefined>;
  linkChannel(secretId: string, a: string, b: string): Promise<void>;
  linkedChannels(secretId: string, channelId: string): Promise<string[]>;
}

export interface Share {
  secretId: string;
  version: number;
  bytes: Uint8Array;
}

/**
 * Share-record persistence.
 *
 * Rows are keyed by `(secretId, channelId, version)` where `secretId` is
 * the partition passed to every method. `Share.secretId` is a different
 * value: it names the secret the bytes belong to, which on a helper is
 * the owner's id and routinely differs from the partition this device
 * stores under. Key on the argument and carry `share.secretId` alongside
 * as data — keying on it instead puts rows where no `load` looks, since
 * every read filters on the partition.
 */
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
  /**
   * Drop the shares stored under `(secretId, channelId)` at each of
   * `versions`. Idempotent: a version that is not stored is skipped, and
   * an empty array is a no-op.
   *
   * A helper calls this to apply `StoreShareRequestMessage.keepList`, the
   * complete set of versions the owner wants retained: every stored
   * version outside it is removed once the incoming share is persisted.
   * Shares under other channels or partitions must be left untouched.
   */
  removeVersions(
    secretId: string,
    channelId: string,
    versions: number[],
  ): Promise<void>;
  /**
   * Owner only: the versions every helper keeps after the owner distributes
   * `version`. Asked once per sharing round, before anything is sent,
   * including the rounds the library starts itself; the answer becomes
   * `keepList` for every helper.
   *
   * Return `null` or `undefined` to send no `keepList` (it goes out empty):
   * helpers then keep every version they hold. An app that wants to cap how
   * many versions helpers retain returns that cap here. A returned list is
   * used as is, plus `version`, which the library always adds. Helpers
   * delete every version that is not listed, so list only versions that
   * committed (for example, those whose `SharingComplete` reported
   * `threshold_met`) and always keep the latest committed version; an
   * over-eager list can make the secret unrecoverable.
   */
  keepList(
    secretId: string,
    version: number,
  ): Promise<number[] | null | undefined>;
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
  /** Decimal `replica_id` of the member that published `version`. Absent
   *  when none is recorded. Store and return it unchanged: replica members
   *  compare it to detect a conflicting copy of the same version. */
  author_replica_id?: string;
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
 * `2` = PendingUnpair, `3` = SharingRound, `4` = PendingReplicaDiscovery).
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

/** A transport protocol, by name. */
export type TransportProtocolName = "https" | "grpc";

/**
 * One endpoint a node serves or a peer advertised, as every app-facing call
 * and event carries it.
 */
export interface Endpoint {
  uri: string;
  protocol: TransportProtocolName;
}

/**
 * Outbound message delivery.
 *
 * This is a mailbox, not a request/response channel: every peer has an
 * address, and a reply is posted to that address rather than returned from
 * `process`. Where both sides are reachable services, a one-way push is all
 * that is needed.
 *
 * A peer that cannot be addressed — a phone, a browser, anything behind NAT —
 * breaks that silently: the reply is handed to `send`, goes nowhere, and
 * nothing reports an error. Such a service must answer on the connection the
 * request arrived on, by building the protocol per request with a `Transport`
 * that collects into a buffer instead of sending, then returning the collected
 * message whose trace id matches the inbound envelope's
 * (`envelope_read_trace_id`). One call can emit several messages, so the rest
 * of the buffer is genuine fan-out and still has to be delivered. See "Serving
 * DeRec over request/response transports" in the Rust SDK README.
 */
export interface Transport {
  /**
   * Delivers `message` to a peer reachable at any of `endpoints`.
   *
   * `endpoints` are the addresses that peer advertised, in the order it
   * offered them, already filtered to those the library will record. The
   * library does not rank them: which to dial, and whether to fall back when
   * one is unreachable, is this implementation's choice. Never empty.
   *
   * Delivery to any one endpoint is success. Reject only when the message
   * reached none of them.
   *
   * **Deliver once.** Every entry addresses the same peer, so sending to all
   * of them delivers one authenticated message several times. Stop at the
   * first success. The protocol's handlers are idempotent, so a duplicate
   * does not corrupt state, but it is still a duplicate to anything counting
   * messages, and a peer entitled to treat re-delivery as a replay will.
   *
   * **Prefer an adapter to writing this by hand.** Choosing which endpoint to
   * dial is yours and stays here; the bookkeeping around it is the same
   * everywhere and is already written and tested. Write a {@link SendOne} and
   * wrap it in {@link sequentialFailover}. Taking `endpoints[0]` type-checks,
   * passes every test, and silently gives up the failover the list exists to
   * provide — if that is genuinely wanted, say so with
   * {@link singleEndpointTransport} rather than by indexing.
   */
  send(
    endpoints: ReadonlyArray<Endpoint>,
    message: Uint8Array,
  ): Promise<void>;
}

/**
 * Delivers one message to one endpoint.
 *
 * The narrow half of a transport: everything genuinely about dialing, and
 * nothing about which endpoint to dial. Pass one of these to
 * {@link sequentialFailover} or {@link singleEndpointTransport} to get a
 * {@link Transport}.
 *
 * Rejecting means the endpoint did not receive the message. The rejection
 * reason need not distinguish "unreachable" from "rejected":
 * {@link sequentialFailover} treats both as a reason to try the next endpoint,
 * which is the safe reading. Trying an endpoint that would have refused costs
 * a round trip; skipping one that would have worked costs the delivery.
 */
export type SendOne = (
  endpoint: Endpoint,
  message: Uint8Array,
) => Promise<void>;

/**
 * The DeRec protocol version this build speaks — the `protocolVersionMajor` /
 * `protocolVersionMinor` it writes into every envelope it produces. Not the
 * package version.
 */
export function protocol_version(): { major: number; minor: number } {
  return getNative().version();
}

/**
 * A fresh, random replica id — never `0`. Generate it once per device,
 * persist it, and pass the same value to
 * `DeRecProtocolBuilder.withReplicaId` on every init.
 */
export function generate_replica_id(): bigint {
  return getNative().generate_replica_id();
}

/**
 * Builds a {@link Transport} that tries each endpoint in the order the peer
 * offered it and stops at the first success.
 *
 * An error is thrown only when every endpoint failed. The message is delivered
 * at most once.
 *
 * This is the right default. A peer advertising several endpoints is saying it
 * can be reached at any of them, and the reason 0.0.3 records the whole list is
 * so one being down does not end the conversation.
 */
export function sequentialFailover(dialer: SendOne): Transport {
  return {
    async send(endpoints, message) {
      let last: unknown;
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
      throw last ?? new Error('send was called with no endpoints');
    },
  };
}

/**
 * Builds a {@link Transport} that uses the first endpoint only.
 *
 * Reproduces the pre-0.0.3 behaviour exactly, for an application that genuinely
 * serves one endpoint or has a reason not to fail over.
 *
 * It exists so that choosing it is visible. `endpoints[0]` written inline looks
 * like an implementation detail and reads as finished; naming this records that
 * failover was considered and declined, which is a claim a reviewer can
 * disagree with. If the peers this application talks to advertise more than one
 * endpoint, prefer {@link sequentialFailover} — every endpoint after the first
 * is reachability being thrown away.
 */
export function singleEndpointTransport(dialer: SendOne): Transport {
  return {
    async send(endpoints, message) {
      if (endpoints.length === 0) {
        throw new Error('send was called with no endpoints');
      }
      await dialer(endpoints[0]!, message);
    },
  };
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
 *   `channel_id`, `nonce`, and `supported_transports` — small enough to be
 *   hand-typed or dictated. Keys are generated on the fly by the contact
 *   creator when the `PrePairRequest` arrives; the scanner accepts them
 *   without cryptographic verification. Trust rests entirely on the OOB
 *   delivery channel being fully trusted (e.g. a verified email from an
 *   already-KYC-authenticated institution). Applications MUST rate-limit
 *   inbound `PrePairRequest`s per channel and expire outstanding NoKeys
 *   contacts on a short timer.
 *
 *   Because nothing binds the published keys to the contact, the channel is
 *   held `Pending` until `verifyFingerprint` succeeds on both sides: it is
 *   not a publish target, not a recovery source, and inbound messages on it
 *   are ignored. A man-in-the-middle on the plaintext `PrePair` leg leaves
 *   the two sides with different shared keys and so different fingerprints,
 *   which is what the comparison catches — the role `contact_binding_hash`
 *   plays for `HashedKeys`.
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
  ReplicaDiscovery = 7,
  /** Remove a member from the replica group. Replica-only. Naming this device
   *  is a voluntary departure; naming another is an eviction. Params:
   *  `{ replica_id: string; memo?: string }` — `replica_id` is a decimal
   *  string so ids above 2^53 survive JS number handling. */
  UnpairReplica = 8,
}

/** Result status carried in every protocol response (`result.proto`). Passed
 *  to `reject()` to say why an inbound request was refused. */
export enum StatusEnum {
  Ok = 0,
  Partial = 1,
  Fail = 2,
  SizeLimitExceeded = 3,
  TooFrequent = 4,
  UnknownSecretId = 5,
  UnknownShareVersion = 6,
  DecryptionFailed = 7,
  VerificationFailed = 8,
  FormatError = 9,
  Rejected = 10,
  IncompatibleParameterRange = 11,
  UnsupportedTransportProtocol = 12,
  VersionConflict = 13,
  ReplicaIdConflict = 14,
  RequestToClose = 99,
}

export type UnpairAck = "required" | "not_required";

export interface ContactMessage {
  channel_id: bigint;
  /** `ContactMode` numeric value (0 = INLINE_KEYS, 1 = HASHED_KEYS, 2 = NO_KEYS). */
  contact_mode: number;
  nonce: bigint;
  /** Present only when `contact_mode === ContactMode.InlineKeys`. */
  mlkem_encapsulation_key?: Uint8Array;
  /** Present only when `contact_mode === ContactMode.InlineKeys`. */
  ecies_public_key?: Uint8Array;
  /** Present only when `contact_mode === ContactMode.HashedKeys`. SHA-384 digest (48 bytes). */
  contact_binding_hash?: Uint8Array;
  timestamp?: Timestamp;
  /** Every transport endpoint the creator of this contact can be reached
   *  on, in its own preference order. */
  supported_transports: TransportProtocol[];
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

  /**
   * Every endpoint this node now serves, in its own preference order.
   * Omitted leaves the target(s)' stored set untouched.
   */
  own_transports?: Endpoint[];
}

/**
 * How long the protocol waits on each thing that can keep it waiting. Every
 * field is optional; omit one to keep the library's default for it.
 */
export interface Timeouts {
  /** Staleness boundary for inbound envelopes — the replay-defence window.
   *  Any message older than this is discarded on receipt, whatever the flow.
   *  Lowering it starts refusing legitimately old messages from slow
   *  transports or skewed clocks. Library default: 300. */
  inbound_message_secs?: number;
  /** How long a publishing round waits on a peer that has not answered.
   *  Bounds how long `SharingComplete` can be delayed by one unreachable
   *  peer. Library default: 60. */
  sharing_round_secs?: number;
  /** How long to wait for an unpair acknowledgement before dropping local
   *  channel state anyway. Library default: 60. */
  unpair_ack_secs?: number;
  /** Removal of channels still awaiting out-of-band fingerprint
   *  confirmation — every replica pairing, and every `NoKeys` pairing.
   *  Unlike the others this can be disabled, leaving the sweep to the
   *  application via `removeExpiredChannels`. The budget is a **human** one:
   *  someone comparing a fingerprint, possibly over the phone. Library
   *  default: `{ enabled: true, timeout_in_secs: 300 }`. */
  expired_channels?: { enabled: boolean; timeout_in_secs: number };
}

/** `ReplicaDiscovery` takes no parameters: the group and this device's own version
 *  are both read from the stores. The argument may be omitted entirely. */
export type ReplicaDiscoveryParams = Record<string, never>;

/** Any member may remove any member, the source included: a lost or stolen
 *  source must be removable by the devices that remain, and the library
 *  checks no role. Ask the user before starting this flow, above all when it
 *  names the source. Removing the source promotes the first remaining member
 *  in the order the channel store's `listReplicas` returns. The removed
 *  member is not asked and gets no event when told to leave: when a roster
 *  excluding it arrives it drops its whole `secret_id` partition and emits
 *  `SelfRemovedFromGroup`. The secret survives on the remaining members and
 *  the helpers. */
export interface UnpairReplicaParams {
  /** The member to remove, as a **decimal** `u64` string — the same form
   *  `ReplicaPaired.peer_replica_id` hands back. A value naming no current
   *  member is rejected; it is not silently ignored. */
  replica_id: string;

  memo?: string;
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

      action_kind: PendingActionKind;
      /** Correlation token of the inbound request, decimal-encoded. */
      trace_id: string;
      /** Pairing only. */
      peer_communication_info?: Record<string, string>;
      /** `sender_kind` of the inbound pair request (Pairing only). */
      sender_kind?: SenderKind;
      /** Share version (StoreShare / VerifyShare / GetShare). */
      version?: number;
      /** Description of the secret version (StoreShare only). */
      share_description?: string;
      /** Secret identifier, decimal-encoded (StoreShare / VerifyShare /
       *  GetShare). On GetShare, with `version`, names the requested share. */
      share_secret_id?: string;
      /** Length in bytes of the share the helper would store (StoreShare
       *  only) — what a size or quota decision is made on. */
      share_size?: number;
      /** The peer's memo (Unpair only). */
      unpair_memo?: string;
      /** Communication info the peer replaces its stored map with
       *  (UpdateChannelInfo only). Absent: unchanged. Empty: cleared. */
      updated_communication_info?: Record<string, string>;
      /** Endpoints the peer is moving to (UpdateChannelInfo only). Absent:
       *  unchanged. */
      updated_transports?: Endpoint[];
    }
  | { type: "ShareStored"; channel_id: string; version: number }
  | { type: "ShareConfirmed"; channel_id: string; version: number }
  | { type: "ShareRejected"; channel_id: string; version: number; status: StatusEnum; memo: string }
  /** A publishing round finished — every targeted helper confirmed,
   *  rejected, or timed out.
   *
   *  **A mixed round waits for the replica leg.** The counts here describe
   *  helpers only and are known the instant the helpers answer, but the
   *  event is withheld until every replica member has also acknowledged,
   *  refused, or timed out. One unreachable member therefore delays it by
   *  up to the configured timeout, which is easy to mistake for a hang.
   *  Nothing is lost — the round always terminates and a silent member is
   *  reported in `ReplicaSyncComplete.behind` rather than failing it.
   *
   *  Drive per-helper progress from `ShareConfirmed` instead: those land as
   *  each helper answers, with no cross-population wait. A helpers-only
   *  round is unaffected. */
  | { type: "SharingComplete"; version: number; confirmed_count: number; failed_count: number; threshold_met: boolean }
  /** A group member refused a secret sync. Keyed by `replica_id`, not
   *  `channel_id`: every member answers on the one group channel. A
   *  `VERSION_CONFLICT` status means another member holds a different copy
   *  of this version: do not publish from this device again until the
   *  conflict is resolved. Run `start(FlowKind.ReplicaDiscovery)` to receive
   *  the group's copy as `ReplicaVersionConflict`, merge, and publish the
   *  result once with `start(FlowKind.ProtectSecret)`. */
  | {
      type: "ReplicaSyncRejected";
      replica_id: string;
      secret_id: string;
      version: number;
      status: StatusEnum;
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
   *  it; absence alone never destroys a copy of the secret. The teardown is
   *  automatic: this device is not asked first and gets no earlier event. */
  | { type: "SelfRemovedFromGroup"; version: number }
  /** A replica catch-up finished. `fetched_from` is absent when this device
   *  was already current, in which case no hydration event follows. */
  | {
      type: "ReplicaDiscoveryComplete";
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
  /** A helper refused a verification challenge: its response carried a
   *  non-OK `status` instead of a proof. The challenge is spent; a new
   *  `VerifyShares` round challenges the helper again. */
  | { type: "ShareVerifyRejected"; channel_id: string; version: number; status: StatusEnum; memo: string }
  | {
      type: "SecretsDiscovered";
      channel_id: string;

      secrets: Array<{ secret_id: string; versions: Array<{ version: number; description: string }> }>;
    }
  | { type: "RecoveryShareReceived"; channel_id: string; shares_received: number }
  | { type: "RecoveryShareError"; channel_id: string; shares_received: number; error: string }
  /** A helper refused a recovery share request: its response carried a
   *  non-OK `status` (e.g. `UNKNOWN_SHARE_VERSION`) instead of a share. The
   *  refusal is not collected — it does not count towards `shares_received`
   *  and the recovery stays open for the other helpers' shares — but it does
   *  answer that helper's `RecoverSecretStarted`. */
  | { type: "RecoveryShareRefused"; channel_id: string; version: number; status: StatusEnum; memo: string }
  /** A helper answered with a share that cannot be part of the secret;
   *  `reason` says how it failed. `Malformed` and `InvalidProof` are judged
   *  on arrival; `Inconsistent` (valid on its own but disagreeing with the
   *  shares the secret was rebuilt from) is reported alongside
   *  `SecretRecovered`, once per helper. The share is set aside — it does
   *  not count towards `shares_received` and never blocks the recovery. An
   *  honest helper never sends one, so the app may treat it as a sign of a
   *  damaged or compromised helper, e.g. offer to unpair it. It also
   *  answers that helper's `RecoverSecretStarted`. */
  | { type: "RecoveryShareCorrupted"; channel_id: string; version: number; reason: CorruptionReason }
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
          /** Every endpoint this peer advertised, in the order it offered them. */
          transports: Endpoint[];
          shared_key: Uint8Array;
          communication_info?: Record<string, string>;
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
            /** Every endpoint this peer advertised, in the order it offered them. */
            transports: Endpoint[];
            role: "Source" | "Destination";
            communication_info?: Record<string, string>;
          }>;
          shared_key: Uint8Array;
        };
      };
    }

  | { type: "Unpaired"; channel_id: string }

  | { type: "UnpairRejected"; channel_id: string; status: StatusEnum; memo: string }

  /** Contact creator answered the scanner's `PrePairRequest` with a
   *  non-Ok status (HashedKeys flow). Distinct from a cryptographic
   *  hash mismatch, which surfaces as a thrown error from `process()`. */
  | { type: "PrePairRejected"; channel_id: string; status: StatusEnum; memo: string }

  /** Fires alongside `PairingCompleted` on replica-mode pair handshakes.
   *  `peer_replica_id` is the peer's `u64` as a **decimal** string,
   *  matching the wire `derec.replica_id` representation and every other
   *  id across this boundary. Pass it back verbatim — `UnpairReplica`
   *  expects the same decimal form. The local side's role
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
   *  optionally uses `shares` for recovery. `from_replica_id`,
   *  `author_replica_id` and the `replica_id` fields inside `secret` are
   *  `u64` as **decimal** strings.
   *
   *  `from_replica_id` is the member this copy came from: the publisher on
   *  a push, the serving member on a catch-up. `author_replica_id` is the
   *  member that published `version`, or `null` when the serving member's
   *  snapshot records none. */
  | {
      type: "ReplicaSecretReceived";
      channel_id: string;
      from_replica_id: string;
      author_replica_id: string | null;
      secret_id: string;
      version: number;
      secret: {
        helpers: Array<{
          channel_id: string;
          /** Every endpoint this peer advertised, in the order it offered them. */
          transports: Endpoint[];
          shared_key: Uint8Array;
          communication_info?: Record<string, string>;
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
            /** Every endpoint this peer advertised, in the order it offered them. */
            transports: Endpoint[];
            role: "Source" | "Destination";
            communication_info?: Record<string, string>;
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
      author_replica_id: string | null;
      secret_id: string;
      version: number;
      secret: {
        helpers: Array<{
          channel_id: string;
          /** Every endpoint this peer advertised, in the order it offered them. */
          transports: Endpoint[];
          shared_key: Uint8Array;
          communication_info?: Record<string, string>;
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
            /** Every endpoint this peer advertised, in the order it offered them. */
            transports: Endpoint[];
            role: "Source" | "Destination";
            communication_info?: Record<string, string>;
          }>;
          shared_key: Uint8Array;
        };
      };
      shares: Array<{
        channel_id: string;
        committed_share: Uint8Array;
      }>;
    }
  /** A member offered a different copy of the version this device holds.
   *  Nothing was written: this device keeps its own copy and refuses the
   *  incoming one with `VERSION_CONFLICT`, so the publisher sees
   *  `ReplicaSyncRejected`. Both copies are complete states — the held one
   *  is in the local stores, the incoming one is `secret`. Resolve by
   *  publishing the chosen state with `start(FlowKind.ProtectSecret)`; the
   *  next version supersedes both on every member and helper. Until then,
   *  do not publish from this device: any further `ProtectSecret` is a
   *  higher version that every other member applies over its own copy,
   *  losing the change it never merged.
   *
   *  `held_author_replica_id` / `incoming_author_replica_id` are the
   *  decimal `replica_id` of each copy's publisher, or `null` when that
   *  copy records none. */
  | {
      type: "ReplicaVersionConflict";
      channel_id: string;
      from_replica_id: string;
      secret_id: string;
      version: number;
      held_author_replica_id: string | null;
      incoming_author_replica_id: string | null;
      secret: {
        helpers: Array<{
          channel_id: string;
          /** Every endpoint this peer advertised, in the order it offered them. */
          transports: Endpoint[];
          shared_key: Uint8Array;
          communication_info?: Record<string, string>;
        }>;
        secrets: Array<{
          id: Uint8Array;
          name: string;
          data: Uint8Array;
        }>;
        /** The same shape as `SecretRecovered.secret.replicas`. */
        replicas?: {
          /** The one channel every member is addressed on. */
          channel_id: string;
          /** Every member of the group, including the writer. Exactly one
           *  carries `role: "Source"` — that member is where the secret
           *  originated, which is why no separate owner field is needed. */
          members: Array<{
            replica_id: string;
            /** Every endpoint this peer advertised, in the order it offered them. */
            transports: Endpoint[];
            role: "Source" | "Destination";
            communication_info?: Record<string, string>;
          }>;
          shared_key: Uint8Array;
        };
      };
    }
  /** Peer's ack of a secret sync we sent. `status` is the `StatusEnum`
   *  integer (0 = Ok), `memo` is the peer's explanation. */
  | {
      type: "ReplicaSecretAcked";
      channel_id: string;
      from_replica_id: string;
      secret_id: string;
      version: number;
      status: StatusEnum;
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
      status: StatusEnum;
      memo: string;
    }
  /** Emitted by `process()` in place of `ActionRequired` when the
   *  configured {@link AutoAcceptPolicy} opts in to the inbound
   *  action's flow. The same event vec carries the flow's completion
   *  events (e.g. `ShareStored`, `PairingCompleted`). Use this purely
   *  for observability — no further action is required. `action_kind`
   *  is the same label vocabulary as `ActionRequired.action_kind`
   *  (`"Pairing"`, `"StoreShare"`, …). */
  | { type: "AutoAccepted"; channel_id: string; action_kind: PendingActionKind }
  | { type: "NoOp" }
  /** An inbound message was dropped untouched: no store was written and
   *  nothing was sent back. `reason` says why.
   *
   *  `"PendingVerification"` means the peer sent something before this
   *  device confirmed the channel's fingerprint — typically a replica source
   *  pushing its first copy while this destination still shows the code.
   *  Confirming does not replay it: after `verifyFingerprint` succeeds, a
   *  replica destination calls `start(FlowKind.ReplicaDiscovery)` to pull
   *  the copy itself. `"Expired"` means the message was older than the
   *  inbound timeout. `trace_id` matches the peer's `*Started` event for
   *  the same round (`"0"` when the sender set none). */
  | {
      type: "MessageIgnored";
      channel_id: string;
      reason: IgnoreReason;
      trace_id: string;
    }
  /** Returned by `restore`: a roster entry got no channel, so this device
   *  cannot reach that peer. Every other entry and the user-secret snapshot
   *  were restored; `reason` says why this one was not. `"NoTransports"`
   *  means the recovered roster names no endpoint for it.
   *
   *  For a helper, `channel_id` is its channel and `replica_id` is absent.
   *  For a replica group member, `channel_id` is the group's channel and
   *  `replica_id` names the member. The peer itself is untouched — a helper
   *  still holds its share — and pairing with it again makes it reachable. */
  | {
      type: "PeerNotRestored";
      channel_id: string;
      replica_id?: string;
      reason: NotRestoredReason;
    }
  /** A pairing handshake was dispatched successfully. `kind` is the
   *  local party's role — same value the subsequent `PairingCompleted`
   *  will carry. Emitted by `start(Pairing)`. */
  | { type: "PairingStarted"; channel_id: string; kind: SenderKind; trace_id: string }
  /** A discovery request was dispatched to `channel_id`. Emitted per
   *  targeted helper by `start(Discovery)`. */
  | { type: "DiscoveryStarted"; channel_id: string; trace_id: string }
  /** A discovery request could not be dispatched to `channel_id`. Other
   *  targeted channels are unaffected. */
  | { type: "DiscoveryFailed"; channel_id: string; error: string }
  /** A share-storage request was dispatched to `channel_id`. Emitted per
   *  targeted peer by `start(ProtectSecret)`. */
  | { type: "ProtectSecretStarted"; channel_id: string; version: number; trace_id: string }
  /** A share-storage request could not be dispatched to `channel_id`. */
  | {
      type: "ProtectSecretFailed";
      channel_id: string;
      version: number;
      error: string;
    }
  /** A verify-share challenge was dispatched to `channel_id`. */
  | { type: "VerifySharesStarted"; channel_id: string; version: number; trace_id: string }
  /** A verify-share challenge could not be dispatched to `channel_id`. */
  | {
      type: "VerifySharesFailed";
      channel_id: string;
      version: number;
      error: string;
    }
  /** A recovery share request was dispatched to `channel_id`. */
  | { type: "RecoverSecretStarted"; channel_id: string; version: number; trace_id: string }
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
  | { type: "UnpairStarted"; channel_id: string; trace_id: string }
  /** An update-channel-info request was dispatched to `channel_id`. */
  | { type: "UpdateChannelInfoStarted"; channel_id: string; trace_id: string }
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
 *   `false`, `ActionRequired` carries `share_size`, so the application
 *   can compare it to its quota and call `reject()` with
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
  /**
   * Every endpoint the requester can be answered on for this exchange, in
   * its own preference order. Omitted means route to the endpoints already
   * recorded for the channel.
   */
  reply_to?: TransportProtocol[];
  /** Replica-group member that sent this; see `replicaId` semantics. */
  replica_id?: bigint;
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
  /** Replica-group member that sent this; see `replicaId` semantics. */
  replica_id?: bigint;
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

// `ContactMessage` is defined once above and covers both `INLINE_KEYS` and
// `HASHED_KEYS` modes.

/** Why a `MessageIgnored` event dropped a message. Matches the Rust
 *  `IgnoreReason` discriminants one-for-one. */
export type IgnoreReason = "PendingVerification" | "Expired";

/** Why a `PeerNotRestored` event left a roster entry without a channel.
 *  Matches the Rust `NotRestoredReason` discriminants one-for-one. */
export type NotRestoredReason = "NoTransports";

/** Why a `RecoveryShareCorrupted` event set a helper's share aside.
 *  Matches the Rust `CorruptionReason` discriminants one-for-one:
 *  `Malformed` — no decodable share for the requested secret and version;
 *  `InvalidProof` — the share fails its own Merkle proof;
 *  `Inconsistent` — valid on its own, but its commitment root or ciphertext
 *  disagrees with the shares the secret was rebuilt from. */
export type CorruptionReason = "Malformed" | "InvalidProof" | "Inconsistent";

/**
 * The label vocabulary for `ActionRequired.action_kind` and
 * `AutoAccepted.action_kind` — one value per pending-action kind the
 * protocol can raise. Matches the Rust `PendingActionKind` discriminants
 * one-for-one.
 */
export type PendingActionKind =
  | "Pairing"
  | "PrePair"
  | "StoreShare"
  | "VerifyShare"
  | "Discovery"
  | "GetShare"
  | "Unpair"
  | "UpdateChannelInfo";

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
  timestamp?: Timestamp;
  /** Every transport endpoint the initiator can be reached on, in its own
   *  preference order. */
  supported_transports: TransportProtocol[];
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
  timestamp?: Timestamp;
  /**
   * Every endpoint the sender can be reached on for the PrePair reply, in
   * its own preference order.
   */
  supported_transports: TransportProtocol[];
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
  /**
   * Every endpoint the requester can be answered on for this exchange, in
   * its own preference order. Omitted means route to the endpoints already
   * recorded for the channel.
   */
  reply_to?: TransportProtocol[];
  /** Replica-group member that sent this; see `replicaId` semantics. */
  replica_id?: bigint;
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
  /** Replica-group member that sent this; see `replicaId` semantics. */
  replica_id?: bigint;
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
  /**
   * Every endpoint the requester can be answered on for this exchange, in
   * its own preference order. Omitted means route to the endpoints already
   * recorded for the channel.
   */
  reply_to?: TransportProtocol[];
  /** Replica-group member that sent this; see `replicaId` semantics. */
  replica_id?: bigint;
}

export interface StoreShareResponseMessage {
  result?: DeRecResult;
  version: number;
  timestamp?: Timestamp;
  secret_id: bigint;
  /** Replica-group member that sent this; see `replicaId` semantics. */
  replica_id?: bigint;
}

export interface UnpairRequestMessage {
  memo: string;
  timestamp?: Timestamp;
  /** Ephemeral response endpoint; see `replyTo` semantics. */
  /**
   * Every endpoint the requester can be answered on for this exchange, in
   * its own preference order. Omitted means route to the endpoints already
   * recorded for the channel.
   */
  reply_to?: TransportProtocol[];
  /** Replica-group member that sent this; see `replicaId` semantics. */
  replica_id?: bigint;
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
  /**
   * Every endpoint the requester can be answered on for this exchange, in
   * its own preference order. Omitted means route to the endpoints already
   * recorded for the channel.
   */
  reply_to?: TransportProtocol[];
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
  /**
   * Every endpoint the requester advertised, in the order it offered them,
   * filtered to those the library will record. Never empty. Choosing which
   * to dial, and failing over when one is unreachable, is the application's.
   */
  peer_transports: TransportProtocol[];

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

export interface ProducePrePairNoKeysResult {

  envelope: Uint8Array;

  /** Secret key material generated for this pairing. The caller MUST persist
   * it: the `PairRequest` that follows is encrypted to it. */
  secret_key_material: Uint8Array;
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
