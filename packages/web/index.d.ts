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
 * Whether a channel or member with these attributes survives `filter`.
 *
 * Every empty field means "do not restrict", `exclude` is applied after `ids`,
 * and the restrictions combine with AND — the same contract the core states on
 * {@link ChannelFilter}. A store whose backing cannot express the filter as a
 * query can list and call this; that is correct but transfers the rows the
 * filter exists to leave behind.
 *
 * `id` is a decimal string, as ids are everywhere on this bridge. `role` is the
 * peer's `SenderKind` name for `listHelpers` and the member's `ReplicaRole`
 * name for `listReplicas`.
 */
export declare function channelFilterMatches(
  filter: HelperFilter | ReplicaFilter | null | undefined,
  id: string,
  status: ChannelStatusName,
  role: SenderKindName | ReplicaRoleName,
): boolean;

/**
 * The endpoints a peer-supplied message advertises, in the peer's own order.
 *
 * Reports what was advertised, not what is acceptable — nothing here is
 * validated, and the protocol still applies its own transport policy to
 * whatever it records.
 */
export declare function advertisedEndpoints(
  message:
    | Pick<ContactMessage, "supported_transports">
    | Pick<PairRequestMessage, "supported_transports">
    | Pick<PrePairRequestMessage, "supported_transports">
    | null
    | undefined,
): TransportProtocol[];


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
 * Do not re-serialise a parsed record. Every id in these records is a `u64`,
 * and `JSON.parse` silently rounds anything above 2^53 — the corruption only
 * appears once a real id happens to be large.
 *
 * A helper record's `weight` is the number of Shamir subshares that helper
 * receives: the weight the last `start(ProtectSecret)` resolved for it, which
 * every publish the library starts on its own reuses (1 for a new pairing and
 * for a record written before the field existed). Parsing a stored helper
 * record to read `Helper.weight` is safe and is the normal way to pre-fill
 * the weights the user is shown: it is a small integer, and the channel id
 * comes from the store call's `channelId` argument, never from the parsed
 * object. Keep persisting the original bytes.
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
   * the storage — note that an IndexedDB cursor without an explicit index and
   * `Map` insertion order after arbitrary edits are both effectively
   * arbitrary. Order explicitly to make succession predictable.
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
  /**
   * How many subshares the share carries, recorded on the owner side only:
   * the library sets it on every share the owner saves (including a replica
   * Destination's mirrored copies) and leaves it absent on a helper's share.
   * Owner shares stored before the field existed read back absent; the
   * library never backfills them. Persist it as given and return it
   * unchanged. `null` and `undefined` both mean no count.
   */
  subshares?: number | null;
  /**
   * The threshold this version was split with, recorded on the owner side
   * only, on the same shares as `subshares`: a later round may change the
   * threshold, so this is the only record of the one an older version needs
   * to be recoverable. Absent on a helper's share and on owner shares stored
   * before the field existed. Persist it as given and return it unchanged.
   * `null` and `undefined` both mean none.
   */
  threshold?: number | null;
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
  /**
   * Reject, or throw, a {@link shareStoreRefusal} `Error` to refuse a share
   * update on a helper channel; any other rejection is an ordinary backend
   * failure.
   */
  save(secretId: string, channelId: string, share: Share): Promise<void>;
  latestVersion(secretId: string): Promise<number | null>;
  removeChannel(secretId: string, channelId: string): Promise<void>;
  /**
   * Drop the shares stored under `(secretId, channelId)` at each of
   * `versions`. Idempotent: a version that is not stored is skipped, and
   * an empty array is a no-op.
   *
   * A helper calls this to apply `StoreShareRequestMessage.keepVersion`:
   * once the incoming share is persisted, every version stored on the
   * channel other than the incoming one and `keepVersion` is removed.
   * Shares under other channels or partitions must be left untouched.
   */
  removeVersions(secretId: string, channelId: string, versions: number[]): Promise<void>;
  /**
   * Owner only: the one older version every helper keeps after the owner
   * distributes `version`. Asked once per sharing round, before anything is
   * sent, including the rounds the library starts itself; the answer
   * becomes `keepVersion` for every helper.
   *
   * Resolve to an integer in `0..=4294967295`. A helper that stores
   * `version` keeps it and the returned version, and deletes every other
   * version it holds; `0` keeps no other version. An answer equal to or
   * greater than `version` fails the round with `invalid_keep_version`
   * before anything is sent.
   *
   * Return the last valid version: the newest one whose `SharingComplete`
   * reported `threshold_met`. A version whose round is still open is
   * deleted from every helper that stores `version` unless it is the one
   * returned here. Only the application knows which versions committed.
   * When a helper confirms `version`, the library also removes this
   * device's rows for that channel other than `version` and the returned
   * version.
   */
  keepVersion(secretId: string, version: number): Promise<number>;
  /**
   * Record a verification challenge the helper is about to answer for
   * `(secretId, channelId, version)`. Called once per accepted challenge,
   * after the challenged share is found and before the helper answers.
   *
   * Reject, or throw, a {@link shareStoreRefusal} `Error` to refuse the
   * verification on a helper channel; the library answers the owner with
   * the mapped status instead of the verification result. Any other
   * rejection is an ordinary backend failure.
   */
  recordVerification(secretId: string, channelId: string, version: number): Promise<void>;
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
  /** The threshold the next publish splits at unless
   *  `ProtectSecretParams.threshold` passes its own. Every publish writes the
   *  threshold it used, and `restore` and replica hydration write the
   *  recovered roster's. Absent on a snapshot written before the threshold
   *  was recorded, or restored from a roster that carries none; the
   *  builder's `withThreshold` then applies. Store and return it unchanged.
   *  `null` and `undefined` both mean none. */
  threshold?: number | null;
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
   * everywhere and is already written and tested. Write a
   * {@link SendOne} and wrap it in {@link sequentialFailover}. Taking
   * `endpoints[0]` type-checks, passes every test, and silently gives up the
   * failover the list exists to provide — if that is genuinely wanted, say so
   * with {@link singleEndpointTransport} rather than by indexing.
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
export declare function protocol_version(): { major: number; minor: number };

/**
 * A fresh replica identity, generated by the core — never `0`. Persist it
 * once per device and pass the same value to `withReplicaId` on every
 * protocol init: a device whose id changes cannot be re-identified by its
 * group.
 */
export declare function generate_replica_id(): bigint;

/** Reason a `ShareStore` gives for refusing a `save` or `recordVerification`
 *  call, carried on the `refusal` property of the `Error` {@link
 *  shareStoreRefusal} builds. The app picks the reason; the library alone
 *  decides the status and memo that reach the peer. */
export type ShareStoreRefusalReason = "too_frequent" | "size_limit_exceeded" | "rejected";

/**
 * Builds the `Error` a `ShareStore`'s `save`/`recordVerification` throws, or
 * rejects its promise with, to refuse the call: `reason` tagged onto the
 * error's `refusal` property.
 */
export declare function shareStoreRefusal(reason: ShareStoreRefusalReason): Error;

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
export declare function sequentialFailover(dialer: SendOne): Transport;

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
export declare function singleEndpointTransport(dialer: SendOne): Transport;

export declare const SenderKind: {
  readonly Owner: 0;
  readonly Helper: 1;
  readonly ReplicaSource: 3;
  readonly ReplicaDestination: 4;
};
export type SenderKind = (typeof SenderKind)[keyof typeof SenderKind];
export declare namespace SenderKind {
  type Owner = typeof SenderKind.Owner;
  type Helper = typeof SenderKind.Helper;
  type ReplicaSource = typeof SenderKind.ReplicaSource;
  type ReplicaDestination = typeof SenderKind.ReplicaDestination;
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
 *   plays for `HashedKeys`. The creator's `PrePair` response also carries a
 *   commitment to a nonce it reveals only in its `PairResponse`, and the
 *   channel key depends on that nonce, so whoever answers the scanner cannot
 *   search offline for keys that make the two fingerprints agree.
 */
export declare const ContactMode: {
  readonly InlineKeys: 0;
  readonly HashedKeys: 1;
  readonly NoKeys: 2;
};
export type ContactMode = (typeof ContactMode)[keyof typeof ContactMode];
export declare namespace ContactMode {
  type InlineKeys = typeof ContactMode.InlineKeys;
  type HashedKeys = typeof ContactMode.HashedKeys;
  type NoKeys = typeof ContactMode.NoKeys;
}

export declare const FlowKind: {
  readonly Pairing: 0;
  readonly Discovery: 1;
  readonly ProtectSecret: 2;
  readonly VerifyShares: 3;
  readonly RecoverSecret: 4;
  readonly Unpair: 5;
  readonly UpdateChannelInfo: 6;
  /** Ask the replica group whether this device is behind, and catch up if it
   *  is. Replica-only, and takes no parameters — the group and this device's
   *  own version both come from the stores. */
  readonly ReplicaDiscovery: 7;
  /** Remove a member from the replica group. Replica-only. Naming this device
   *  is a voluntary departure; naming another is an eviction. Params:
   *  `{ replica_id: string; memo?: string }` — `replica_id` is a decimal
   *  string so ids above 2^53 survive JS number handling. */
  readonly UnpairReplica: 8;
};
export type FlowKind = (typeof FlowKind)[keyof typeof FlowKind];
export declare namespace FlowKind {
  type Pairing = typeof FlowKind.Pairing;
  type Discovery = typeof FlowKind.Discovery;
  type ProtectSecret = typeof FlowKind.ProtectSecret;
  type VerifyShares = typeof FlowKind.VerifyShares;
  type RecoverSecret = typeof FlowKind.RecoverSecret;
  type Unpair = typeof FlowKind.Unpair;
  type UpdateChannelInfo = typeof FlowKind.UpdateChannelInfo;
  type ReplicaDiscovery = typeof FlowKind.ReplicaDiscovery;
  type UnpairReplica = typeof FlowKind.UnpairReplica;
}

/** Result status carried in every protocol response (`result.proto`). Passed
 *  to `reject()` to say why an inbound request was refused. */
export declare const StatusEnum: {
  readonly Ok: 0;
  readonly Partial: 1;
  readonly Fail: 2;
  readonly SizeLimitExceeded: 3;
  readonly TooFrequent: 4;
  readonly UnknownSecretId: 5;
  readonly UnknownShareVersion: 6;
  readonly DecryptionFailed: 7;
  readonly VerificationFailed: 8;
  readonly FormatError: 9;
  readonly Rejected: 10;
  readonly IncompatibleParameterRange: 11;
  readonly UnsupportedTransportProtocol: 12;
  readonly VersionConflict: 13;
  readonly ReplicaIdConflict: 14;
  readonly RequestToClose: 99;
};
export type StatusEnum = (typeof StatusEnum)[keyof typeof StatusEnum];
export declare namespace StatusEnum {
  type Ok = typeof StatusEnum.Ok;
  type Partial = typeof StatusEnum.Partial;
  type Fail = typeof StatusEnum.Fail;
  type SizeLimitExceeded = typeof StatusEnum.SizeLimitExceeded;
  type TooFrequent = typeof StatusEnum.TooFrequent;
  type UnknownSecretId = typeof StatusEnum.UnknownSecretId;
  type UnknownShareVersion = typeof StatusEnum.UnknownShareVersion;
  type DecryptionFailed = typeof StatusEnum.DecryptionFailed;
  type VerificationFailed = typeof StatusEnum.VerificationFailed;
  type FormatError = typeof StatusEnum.FormatError;
  type Rejected = typeof StatusEnum.Rejected;
  type IncompatibleParameterRange = typeof StatusEnum.IncompatibleParameterRange;
  type UnsupportedTransportProtocol = typeof StatusEnum.UnsupportedTransportProtocol;
  type VersionConflict = typeof StatusEnum.VersionConflict;
  type ReplicaIdConflict = typeof StatusEnum.ReplicaIdConflict;
  type RequestToClose = typeof StatusEnum.RequestToClose;
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
  /**
   * Present only when `contact_mode === ContactMode.InlineKeys`. The
   * creator's 32-byte commitment to the fingerprint nonce its
   * `PairResponseMessage` reveals. For the other modes it arrives with the
   * keys in the `PrePairResponseMessage`; a contact filled in from a
   * `ProcessPrePairResult` must carry it alongside the two keys.
   */
  fingerprint_commitment?: Uint8Array;
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
  /**
   * Channel ID to how many subshares that channel should hold. The map is the
   * full assignment, not a patch: a paired helper absent from it holds one
   * subshare. The resolved weights are stored on each helper's channel
   * record. A key is a channel id as bigint or decimal string, e.g. the
   * `channel_id` string from an event.
   *
   * Weights are the user's choice. Before `start`, show the user each paired
   * helper's current weight, pre-filled from your `ChannelStore` (the stored
   * `Helper.weight`, which is safe to read; see `ChannelStore`), and pass the
   * user's final choice as the whole map. Reading the stored weights first is
   * the normal flow. Every other `start(ProtectSecret)` the app makes, such
   * as a republish after editing the secrets or the follow-up after
   * `restore`, must pass the stored weights unchanged: a helper left out
   * returns to 1, which silently undoes the user's choice. Only the
   * publishes the library starts on its own (after pairing, after a
   * fingerprint is confirmed) reuse the stored weights by themselves.
   *
   * A stored weight the round's threshold does not allow fails the
   * publishes the library starts on its own with `invalid_weight`, before
   * anything is sent: `process()` throws with the message's `events`
   * (`PairingCompleted` included); `accept()` throws after the pairing has
   * completed and its response was sent, without returning
   * `PairingCompleted`; `verifyFingerprint()` throws after the promotion,
   * which stands, and a retry resolves `true` and publishes nothing. Call
   * `start` with `ProtectSecret` and valid weights to publish.
   *
   * When the paired helpers' resolved total is below the round's threshold
   * (see `threshold`), `start` skips the split: no helper is sent anything, so no
   * `ProtectSecretStarted` / `ProtectSecretFailed` comes back for one. A
   * paired replica still gets its usual secret-only copy and events; with
   * none paired, `start` resolves with no events at all — this is not an
   * error. The version still advances and the secrets/description are
   * saved as the latest snapshot, so the next publish that reaches
   * threshold shares it. Sum the weights about to be assigned against the
   * threshold beforehand, or count the returned helper events afterward,
   * to detect the case.
   */
  weights?: Map<bigint | string, number>;
  /**
   * The threshold this round splits at: the number of distinct subshares
   * that reconstruct this version. Absent keeps the stored threshold
   * (`UserSecrets.threshold`), or the builder's `withThreshold` when none is
   * stored; a value changes it, and the new threshold is stored with this
   * round. Leave it absent on the follow-up after `restore`, which has
   * already put the recovered threshold back. Publishes the library starts
   * on its own always use the stored threshold.
   *
   * The resolved threshold must be at least 2 (`invalid_threshold`), above
   * every resolved weight (`invalid_weight`), and no greater than a
   * `withMaxSubshares` cap (`invalid_input`). Each check runs before
   * anything is written or sent.
   */
  threshold?: number;
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
  /** The library refused an inbound share (helper side) instead of raising
   *  `ActionRequired`: nothing was stored, no stored version was removed, and
   *  the owner was answered with `status` and `memo`, which it observes as
   *  `ShareRejected`. `status` is FORMAT_ERROR (the share does not decode),
   *  VERIFICATION_FAILED (it does not verify against its commitment),
   *  SIZE_LIMIT_EXCEEDED (outside the helper's size range) or
   *  VERSION_CONFLICT (a different share is stored at `version`). A refusal
   *  from the application's own share store does not raise it. */
  | { type: "ShareRefused"; channel_id: string; version: number; status: StatusEnum; memo: string }
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
  /** A helper's verification proof checked out (owner side). `subshares` is
   *  how many subshares this helper holds for `version`: the count on the
   *  owner's stored share for this channel and version, not the helper's
   *  current weight; absent when that share was stored before the count was
   *  recorded. `threshold` is the threshold `version` was split with, from
   *  the same owner share, not the current one; absent when that share was
   *  stored before the threshold was recorded. To judge whether a version is
   *  recoverable, sum `subshares` over its `ShareVerified` events and compare
   *  with their `threshold`. If either is absent on any of those events, the
   *  result is unknown: an absent count is not `0` or `1`. */
  | { type: "ShareVerified"; channel_id: string; version: number; subshares?: number; threshold?: number }
  /** A helper answered a verification challenge, but its proof does not
   *  match the share this device stored. The challenge is spent; a new
   *  `VerifyShares` round challenges the helper again. */
  | { type: "ShareVerifyInvalid"; channel_id: string; version: number }
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
          communication_info?: Record<string, string> | null;
          /** Shamir subshares this helper received in the round that wrote the
           *  roster. `restore` writes it into the helper's channel record, so the
           *  next publish gives it the same count. Every event carries it;
           *  `restore` reads an absent value as 1. */
          weight?: number;
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
            communication_info?: Record<string, string> | null;
          }>;
          shared_key: Uint8Array;
        };
        /** The threshold the secret was split with. Absent when the roster
         *  records none. `restore` writes it into the snapshot, so the next
         *  publish splits at the same threshold; to change it, pass
         *  `threshold` on `start(ProtectSecret)`. */
        threshold?: number;
      };
    }

  | { type: "Unpaired"; channel_id: string }

  | { type: "UnpairRejected"; channel_id: string; status: StatusEnum; memo: string }

  /** Contact creator answered the scanner's `PrePairRequest` with a
   *  non-Ok status (HashedKeys flow). Distinct from a cryptographic
   *  hash mismatch, which surfaces as a thrown error from `process()`. */
  | { type: "PrePairRejected"; channel_id: string; status: StatusEnum; memo: string }
  /** The peer answered a message from this device with an
   *  `ErrorResponseMessage`: it could not process it, typically because the
   *  body could not be decoded (`FORMAT_ERROR`). Never answered. */
  | { type: "ErrorResponseReceived"; channel_id: string; status: StatusEnum; memo: string }
  /** This device refused an inbound `PairRequest` under a protocol rule
   *  (`INCOMPATIBLE_PARAMETER_RANGE` or `REPLICA_ID_CONFLICT`), whatever the
   *  auto-accept or `auto_respond_on_failure` setting, and sent the requester a
   *  `PairResponse` carrying `status` and `memo`. No channel was created.
   *  Returned by `process()`; it does not throw. `memo` is what the requester
   *  reads, written from its side. `error_code` (`"incompatible_parameter_range"`
   *  or `"replica_id_conflict"`) and `message` carry the local reason, as on
   *  `RequestFailed`; `message` is never sent to the peer. */
  | {
      type: "PairingRefused";
      channel_id: string;
      status: StatusEnum;
      memo: string;
      error_code: DeRecErrorCode;
      message: string;
    }

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
          /** Shamir subshares this helper received in the round that wrote the
           *  roster. `restore` writes it into the helper's channel record, so the
           *  next publish gives it the same count. Every event carries it;
           *  `restore` reads an absent value as 1. */
          weight?: number;
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
        /** The threshold the secret was split with. Absent when the roster
         *  records none. `restore` writes it into the snapshot, so the next
         *  publish splits at the same threshold; to change it, pass
         *  `threshold` on `start(ProtectSecret)`. */
        threshold?: number;
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
          /** Shamir subshares this helper received in the round that wrote the
           *  roster. `restore` writes it into the helper's channel record, so the
           *  next publish gives it the same count. Every event carries it;
           *  `restore` reads an absent value as 1. */
          weight?: number;
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
        /** The threshold the secret was split with. Absent when the roster
         *  records none. `restore` writes it into the snapshot, so the next
         *  publish splits at the same threshold; to change it, pass
         *  `threshold` on `start(ProtectSecret)`. */
        threshold?: number;
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
          /** Shamir subshares this helper received in the round that wrote the
           *  roster. `restore` writes it into the helper's channel record, so the
           *  next publish gives it the same count. Every event carries it;
           *  `restore` reads an absent value as 1. */
          weight?: number;
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
        /** The threshold the secret was split with. Absent when the roster
         *  records none. `restore` writes it into the snapshot, so the next
         *  publish splits at the same threshold; to change it, pass
         *  `threshold` on `start(ProtectSecret)`. */
        threshold?: number;
      };
    }
  /** This device's library refused a group member's copy of the secret:
   *  `FORMAT_ERROR` (the payload does not decode or is not self-consistent)
   *  or `VERIFICATION_FAILED` (a share map entry does not verify against its
   *  commitment). Nothing was written. On a push the publisher was answered
   *  with this `status` and `memo`, which it observes as
   *  `ReplicaSyncRejected`; a copy served by a catch-up is not answered. */
  | {
      type: "ReplicaSecretRefused";
      channel_id: string;
      from_replica_id: string;
      secret_id: string;
      version: number;
      status: StatusEnum;
      memo: string;
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
  /** A request that arrived on an authenticated channel failed while it
   *  was being handled. Every such request is owed exactly one response.
   *  When the library sent it, `responded` is `true` and `action` is absent.
   *  Otherwise `responded` is `false` and `action` is the same opaque token
   *  `ActionRequired` carries: pass it to `reject` to send the response
   *  (`accept` refuses it). `action` is also absent when `reject` could
   *  never answer it: a request on a replica group channel that names no
   *  member, which has no reply target, or, with `autoRespondOnFailure`
   *  off, a replica copy that hands this device the group key and fails
   *  before that key is stored. Resolve each token once: the library is
   *  stateless, so rejecting the same token twice sends two responses.
   *  `action_kind` is the type of the failed request, `"Failed"` when its
   *  body could not be decoded or is a request the channel cannot carry.
   *  `status` is the `StatusEnum` value that was sent, or would have been,
   *  and `memo` the wire-safe memo sent with it, or that would have been:
   *  `reject(action, status, memo)` sends exactly the response
   *  `autoRespondOnFailure` would have sent. `message` is a local
   *  description, never sent to the peer. Reported
   *  instead of a thrown error from `process()` or `accept()`, so the call's
   *  other events are kept. */
  | {
      type: "RequestFailed";
      channel_id: string;
      action_kind: PendingActionKind;
      responded: boolean;
      status: StatusEnum;
      memo: string;
      error_code: DeRecErrorCode;
      message: string;
      action?: Uint8Array;
    }
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
   *  inbound timeout. `"TimestampMismatch"` means the envelope's timestamp
   *  and the encrypted message's differ, or one is absent: a sender stamps
   *  both with the same time, so the envelope was altered or built by a
   *  non-conforming peer. `"StaleResponse"` means a verification answer to
   *  a challenge that a newer one on the channel replaced; the newer
   *  challenge stays outstanding and its own answer still completes it.
   *  `trace_id` matches the peer's `*Started` event for the same round
   *  (`"0"` when the sender set none). */
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
   *  targeted peer by `start(ProtectSecret)`. `weight` is the number of
   *  subshares sent, which is also the weight now stored for this channel:
   *  its `ProtectSecretParams.weights` entry, 1 when the map does not name
   *  it, or the stored weight on a publish the library starts on its own. */
  | { type: "ProtectSecretStarted"; channel_id: string; version: number; trace_id: string; weight: number }
  /** A share-storage request could not be dispatched to `channel_id`. */
  | {
      type: "ProtectSecretFailed";
      channel_id: string;
      version: number;
      error: string;
      /** Number of subshares that were to be sent to this channel; see
       *  `ProtectSecretStarted.weight`. */
      weight: number;
    }
  /** A verify-share challenge was dispatched to `channel_id`. */
  | { type: "VerifySharesStarted"; channel_id: string; version: number; trace_id: string }
  /** Verification reached no verdict for `channel_id`. `reason` says why. */
  | {
      type: "VerifySharesFailed";
      channel_id: string;
      version: number;
      reason: VerifyFailureReason;
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
  /** An unpair request was dispatched to `channel_id`, by
   *  `start(Unpair)` or by `restore` for each recovery channel. Under
   *  `UnpairAck.Required` the channel is now `"Unpairing"`, and an
   *  `Unpaired` event follows once the peer acknowledges or the
   *  acknowledgement window elapses, or `UnpairRejected` if the peer
   *  refuses (the channel is `"Paired"` again). Under
   *  `UnpairAck.NotRequired`, `Unpaired` follows in the same event vec. */
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
 * - `storeShare` — the helper's admission-control point for inbound
 *   shares beyond what the library already checks: this device's own
 *   configured `minShareSize`/`maxShareSize` is enforced against every
 *   inbound share's actual length regardless of this flag, before
 *   `ActionRequired` is ever considered — an out-of-range share is
 *   refused with `StatusEnum.SizeLimitExceeded` either way, and this
 *   flag has no say in it. While this is `false`, `ActionRequired`
 *   carries the decoded request, which is where a tighter or per-user
 *   size limit, storage quota, or any other app-specific decline
 *   belongs — call `reject()` for that. Setting it `true` removes that
 *   opportunity: every in-range share from every paired Owner is stored
 *   unconditionally, unless the share store refuses it. Keep off in any
 *   deployment with per-user storage limits tighter than this device's
 *   own configured range.
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
 * The five stores {@link DeRecProtocolBuilder.build} requires, bundled for
 * {@link DeRecProtocolBuilder.withStores}.
 */
export interface StoresInit {
  channelStore: ChannelStore;
  shareStore: ShareStore;
  secretStore: SecretStore;
  userSecretStore: UserSecretStore;
  stateStore: StateStore;
}

/**
 * `parameter_range` bounds inside {@link DeRecProtocolConfig}. Each bound is
 * a JSON number or a decimal string — the string form carries a bound past
 * `Number.MAX_SAFE_INTEGER` through a config file or a JSON encoder whose
 * numbers are `f64`. An absent bound is `0` ("no bound"), the same as
 * {@link DeRecProtocolBuilder.withParameterRange}.
 */
export interface DeRecParameterRangeConfig {
  min_share_size?: number | string;
  max_share_size?: number | string;
  min_time_between_verifications?: number | string;
  max_time_between_verifications?: number | string;
  min_time_between_share_updates?: number | string;
  max_time_between_share_updates?: number | string;
  min_unresponsive_deletion_timeout?: number | string;
  max_unresponsive_deletion_timeout?: number | string;
  min_unresponsive_deactivation_timeout?: number | string;
  max_unresponsive_deactivation_timeout?: number | string;
}

/**
 * `auto_accept` inside {@link DeRecProtocolConfig}: the same eight flows as
 * {@link AutoAcceptPolicy}, named as the canonical JSON spells them rather
 * than in `camelCase`. An absent flow is `false`. See {@link AutoAcceptPolicy}
 * for per-field caveats.
 */
export interface DeRecAutoAcceptConfig {
  pairing?: boolean;
  pre_pair?: boolean;
  store_share?: boolean;
  verify_share?: boolean;
  discovery?: boolean;
  get_share?: boolean;
  unpair?: boolean;
  update_channel_info?: boolean;
}

/**
 * Every data setting of {@link DeRecProtocolBuilder} in one serializable
 * value, in the canonical `snake_case` JSON shape every SDK accepts — the
 * format for a config file or a user record. Passed to
 * {@link DeRecProtocolBuilder.withConfig}.
 *
 * Every field is optional: an absent or `null` field leaves that setting
 * unset. Stores, the delivery transport and the constructor's `secretId` are
 * not settings and are not carried here.
 *
 * Configs layer: apply a general config, then a per-user one, then any
 * individual `with*` call, and the last write wins per field —
 * `timeouts` merges per field too, so a config that sets only
 * `inbound_message_secs` keeps whatever `sharing_round_secs` an earlier
 * config or call set. Every other nested object (`parameter_range`,
 * `auto_accept`, `own_transports`) replaces as a whole.
 *
 * Values set through a field here are validated by `build()` exactly as the
 * matching `with*` setter's value would be: there is one rule set.
 *
 * ```json
 * {
 *   "threshold": 3,
 *   "max_subshares": "12",
 *   "timeouts": { "inbound_message_secs": 120, "sharing_round_secs": 30 },
 *   "parameter_range": { "min_share_size": 1, "max_share_size": 4096 },
 *   "auto_accept": { "pairing": true, "store_share": true },
 *   "auto_respond_on_failure": false,
 *   "auto_reply_to": false,
 *   "unpair_ack": "required",
 *   "unsafe_connection": false,
 *   "communication_info": { "name": "alice" },
 *   "own_transports": [{ "uri": "https://me.example.com/derec", "protocol": "https" }],
 *   "replica_id": "9007199254740993"
 * }
 * ```
 */
export interface DeRecProtocolConfig {
  threshold?: number;
  /** Decimal string. A `bigint` throws `decode_error`; call
   *  {@link DeRecProtocolBuilder.withMaxSubshares} directly for a `bigint`. */
  max_subshares?: string;
  timeouts?: Timeouts;
  parameter_range?: DeRecParameterRangeConfig;
  auto_accept?: DeRecAutoAcceptConfig;
  auto_respond_on_failure?: boolean;
  auto_reply_to?: boolean;
  /** Its name, or the discriminant `0` (`"required"`) / `1`
   *  (`"not_required"`). */
  unpair_ack?: UnpairAck | 0 | 1;
  unsafe_connection?: boolean;
  communication_info?: Record<string, string>;
  own_transports?: Endpoint[];
  /** Decimal string. A `bigint` throws `decode_error`; call
   *  {@link DeRecProtocolBuilder.withReplicaId} directly for a `bigint`. */
  replica_id?: string;
}

/**
 * Fluent builder for {@link DeRecProtocol}. Mirrors the Rust
 * `DeRecProtocolBuilder` and the dotnet `DeRecProtocolBuilder`
 * method-for-method so a developer who already knows one SDK can move
 * between them without reaching for reference docs.
 *
 * Required setters: `withChannelStore`, `withShareStore`,
 * `withSecretStore`, `withUserSecretStore`, `withStateStore`, and
 * `withTransport`. Calling `build()` without all six throws. Own transports
 * come from `withOwnTransports` or a config applied with `withConfig`;
 * `build()` fails with `InvalidInput` if none are set.
 *
 * An optional setter that is never called leaves the library's default in
 * force.
 */
export declare class DeRecProtocolBuilder {
  /**
   * Release the builder's memory in the library. `build()` already releases
   * it; call this only for a builder that is discarded unbuilt. Safe to call
   * more than once.
   */
  free(): void;
  /** Same as {@link DeRecProtocolBuilder.free}, for `using`. */
  [Symbol.dispose](): void;

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
  /**
   * Set every store in one call. Forwards to {@link DeRecProtocolBuilder.withChannelStore},
   * {@link DeRecProtocolBuilder.withShareStore}, {@link DeRecProtocolBuilder.withSecretStore},
   * {@link DeRecProtocolBuilder.withUserSecretStore} and {@link DeRecProtocolBuilder.withStateStore}
   * in turn, so calling one of them again afterwards replaces just that store.
   */
  withStores(stores: StoresInit): DeRecProtocolBuilder;
  withTransport(transport: Transport): DeRecProtocolBuilder;
  /**
   * Set every transport endpoint this application serves, in preference
   * order. `protocol` is `"https"` or `"grpc"` (case-insensitive) per
   * entry.
   *
   * The order is this application's own preference and decides which of
   * a peer's offered endpoints is used; it is not sorted, deduplicated,
   * or reordered. Every listed transport must actually be served,
   * because delivery is push-only — listing an endpoint this application
   * does not serve makes pairing succeed and replies vanish.
   */
  withOwnTransports(transports: Endpoint[]): DeRecProtocolBuilder;

  /**
   * The starting threshold: the minimum number of subshares required to
   * reconstruct the secret, for a secret with no threshold stored. Every
   * publish stores the threshold it used (`UserSecrets.threshold`), the
   * roster carries it, and `restore` and replica hydration put it back. A
   * round splits at `ProtectSecretParams.threshold`, otherwise at the stored
   * threshold, and only otherwise at this value, so changing it later does
   * not change a stored threshold.
   *
   * A Helper holds one subshare unless `ProtectSecretParams.weights` has
   * given it a weight, so with no weights the threshold is a number of
   * Helpers, as before. Every weight must be below the round's threshold, so
   * no single Helper can recover alone. When this value applies and is
   * lowered to or below a stored weight, every publish fails with
   * `invalid_weight` until `ProtectSecret` assigns valid weights. Default: 3.
   */
  withThreshold(threshold: number): DeRecProtocolBuilder;
  /**
   * Configure how long the protocol waits on each thing that can keep it
   * waiting. Every field is optional and **absent means "keep the library
   * default"**; not calling this at all leaves all four at their defaults.
   *
   * These were one setting until it became clear they answer different
   * questions. `inbound_message_secs` is a **security** boundary — how stale
   * a message may be and still be accepted — so it has to tolerate transport
   * latency and clock skew. The other three are **liveness** budgets: how
   * long to keep hoping a peer will answer.
   *
   * Values are forwarded verbatim; clamping, and the meaning of a disabled
   * `expired_channels`, are library decisions rather than this binding's.
   */
  withTimeouts(timeouts: Timeouts): DeRecProtocolBuilder;

  /**
   * Accept plaintext `http://` and `grpc://` transport endpoints.
   * **Development only.** Default: `false`.
   *
   * With `false`, plaintext is accepted in exactly one situation: an endpoint
   * this device configured for **itself** that names loopback (`localhost`,
   * `127.0.0.1`, `::1`). A local dev server therefore needs no configuration
   * at all.
   *
   * With `true`, plaintext is accepted for **any host on any path**,
   * including endpoints a peer supplies. That is what makes the LAN case
   * work — a phone talking to a laptop, where neither side is loopback — and
   * why the name is blunt.
   *
   * This is a guardrail, not transport security. The SDK opens no sockets;
   * delivery is your `Transport`. Nothing here stops an application sending
   * plaintext — it governs which endpoints the protocol will record,
   * propagate to peers, and reply to.
   */
  withUnsafeConnection(allow: boolean): DeRecProtocolBuilder;
  /** Default: empty. */
  withCommunicationInfo(info: Record<string, string>): DeRecProtocolBuilder;
  /**
   * Who answers an inbound request whose handling failed. `true`: the
   * library sends the response itself. `false`: nothing is sent, and the
   * `RequestFailed` event carries a token to pass to `reject`. Default:
   * false.
   */
  withAutoRespondOnFailure(enabled: boolean): DeRecProtocolBuilder;
  /** Exactly `"required"` or `"not_required"`; any other string throws
   *  `invalid_unpair_ack`. Default: `"required"`. */
  withUnpairAck(ack: UnpairAck): DeRecProtocolBuilder;
  /**
   * When `true`, every outbound channel-mode request stamps
   * `request.reply_to` with this node's own transports so the responder
   * routes its reply back here even if the channel's stored peer endpoint
   * points elsewhere. Default: false.
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
   * stable across restarts: mint it once with {@link generate_replica_id}
   * and persist it. Default: unset.
   */
  withReplicaId(id: bigint | number): DeRecProtocolBuilder;
  /**
   * Declare the bounds this node advertises during pair negotiation.
   *
   * Embedded in outbound `PairRequest` / `PairResponse` envelopes and
   * checked against the peer's range on inbound ones: a range that fails to
   * intersect rejects the pairing. Keys match the {@link ParameterRange}
   * interface; every field is optional and defaults to `0`, which the
   * protocol reads as no constraint on that dimension.
   *
   * Default: unset — no constraints advertised, every peer range accepted.
   *
   * Share size is enforced by the helper; frequency limits are enforced by
   * the app's share store (refuse from `save`/`recordVerification`); the
   * deletion and deactivation timeouts are checked at pairing only.
   */
  withParameterRange(range: Partial<ParameterRange>): DeRecProtocolBuilder;
  /**
   * Cap the total number of subshares one sharing round may split the
   * secret into — the sum of every helper's weight. Default: unset, no
   * cap.
   *
   * Checked only by `start(ProtectSecret)`, including the publishes the
   * library starts itself: a round over the cap fails with
   * `too_many_subshares` before anything is sent. Recovery applies no cap.
   * Recovering costs time that grows quadratically with the total number of
   * subshares, so the cap bounds what a later recovery must do. A cap below
   * the threshold makes `build()` throw.
   */
  withMaxSubshares(max: bigint | number): DeRecProtocolBuilder;

  /**
   * Layer a {@link DeRecProtocolConfig} onto the builder: a field the config
   * sets replaces what the builder currently holds, a field it leaves unset
   * is untouched, and `timeouts` merges per field against the builder's
   * current timeouts rather than resetting the other three. Every other
   * nested object replaces as a whole. Apply a general config, then a
   * per-user one, then any individual `with*` call — the last write wins
   * per field, same as two `withConfig` calls in a row.
   *
   * Applies the fields; does not validate them. `build()` runs exactly the
   * rules the matching `with*` setter documents.
   *
   * Throws `decode_error` if `config` is not a plain object in the
   * canonical shape, or if it (or a nested object) has an unknown key.
   */
  withConfig(config: DeRecProtocolConfig): DeRecProtocolBuilder;

  /**
   * Finalize the configuration. Throws if any of the required setters
   * was not called.
   */
  build(): DeRecProtocol;
}

/**
 * Every method that touches protocol state returns a `Promise` and runs under
 * one lock per instance, so overlapping calls on the same instance — a `tick`
 * timer firing while `process` handles an inbound message — queue and run one
 * at a time, in the order they were made. Distinct instances do not share the
 * lock: two instances bound to the same `secretId` and the same stores must
 * still be serialized by the caller.
 *
 * A store or transport callback must not await a call on the instance that
 * invoked it: that call queues behind the one waiting on the callback, and
 * neither settles. Calling `free()` while a call is in flight throws.
 */
export declare class DeRecProtocol {
  /** Use {@link DeRecProtocolBuilder} to construct instances. */
  private constructor();

  /**
   * Release this protocol's memory in the library, and its references to the
   * stores and transport. The library's memory is not reclaimed by the
   * JavaScript garbage collector in time to rely on, so call this when done.
   * Safe to call more than once; any other method called afterwards throws,
   * as does calling this while a call is in flight.
   */
  free(): void;
  /** Same as {@link DeRecProtocol.free}, for `using`. */
  [Symbol.dispose](): void;

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
   *                     `HashedKeys` requires the advertised own
   *                     transports to be ephemeral.
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
  start(flowKind: FlowKind.ReplicaDiscovery, params?: ReplicaDiscoveryParams): Promise<DeRecEvent[]>;

  /** Announce a member's removal. This does **not** remove anything on its
   *  own and emits no `ReplicaRemoved`: it tells every member and flags the
   *  target locally. The removal completes only once the application
   *  publishes a roster omitting that member — an ordinary
   *  `start(FlowKind.ProtectSecret)` — at which point `ReplicaRemoved`
   *  fires. A group with no secret to publish therefore cannot complete a
   *  removal. */
  start(flowKind: FlowKind.UnpairReplica, params: UnpairReplicaParams): Promise<DeRecEvent[]>;

  /**
   * Replace this node's local <c>communication_info</c> map. Does not
   * contact peers — follow up with
   * <c>start(FlowKind.UpdateChannelInfo, ...)</c> to propagate.
   */
  setCommunicationInfo(info: Record<string, string>): Promise<void>;

  /**
   * Replace every endpoint this node advertises, in preference order —
   * the runtime counterpart to `withOwnTransports`.
   *
   * A node serves at most one endpoint per protocol, so this list is a
   * preference order over distinct protocols. Two entries of the same
   * protocol are rejected.
   *
   * Every entry is validated before any is stored, so a malformed URI
   * leaves the previous set intact. An empty array is rejected.
   */
  setOwnTransports(transports: Endpoint[]): Promise<void>;

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
   * array. Overlapping calls with `process` on the same instance queue
   * rather than collide.
   */
  tick(): Promise<DeRecEvent[]>;

  /**
   * Accept a pending action from an `ActionRequired` event, returning the
   * events it produces.
   *
   * When the action completes a pairing, the publish that follows reuses the
   * stored helper weights. If one is no longer valid under the round's
   * threshold, that publish fails with `invalid_weight` before anything is
   * sent and this throws: the pairing has completed and its response was
   * sent, but the `PairingCompleted` event is not returned. Call `start`
   * with `ProtectSecret` and valid weights to publish.
   */
  accept(actionBytes: Uint8Array): Promise<DeRecEvent[]>;

  reject(actionBytes: Uint8Array, status: StatusEnum, memo: string): Promise<void>;

  /**
   * Derive the human-readable fingerprint for a paired channel. Both sides
   * compute the same value from the shared key — users compare them out of
   * band before calling `verifyFingerprint`. Required for every replica
   * pairing and every `NoKeys` pairing, which stay unusable until it
   * succeeds.
   */
  getFingerprint(channelId: bigint | number): Promise<string>;

  /**
   * Verify `fingerprint` against the channel's locally-derived one. On
   * match, the channel transitions from `Pending` to `Paired`.
   *
   * A mismatch rejects with code `fingerprint_mismatch` — a possible
   * man-in-the-middle. A `Pending` pairing is revoked: its records, channel
   * key and pairing material are deleted, so pair again. A channel already
   * `Paired` is left as it is.
   *
   * On a replica destination, confirming is also the decision to adopt the
   * group's vault: the source's publish is then installed as it arrives,
   * with no further prompt. Ask the user before calling this; to decline,
   * never confirm: expired-channel cleanup removes the channel and its key.
   *
   * On a promotion the current snapshot is published to the promoted peer,
   * reusing the stored helper weights. If one is no longer valid under the
   * current threshold, that publish fails with `invalid_weight` before
   * anything is sent and this throws. The promotion stands: calling this
   * again resolves and publishes nothing, so call `start` with
   * `ProtectSecret` and valid weights to reach the promoted peer.
   */
  verifyFingerprint(channelId: bigint | number, fingerprint: string): Promise<void>;
  /**
   * Remove `Pending` channels older than `olderThanSecs`, along with their
   * pairing keys. Resolves to the removed channel ids as decimal strings.
   *
   * Independent of the configured cleanup policy — this sweeps at the
   * threshold given even when that policy is disabled. The age comparison
   * is strict, so a channel created within the current second survives
   * even `0`.
   *
   * `olderThanSecs` is a `u64`: a `bigint`, a non-negative safe-integer
   * `number`, or a decimal string. Anything else throws `decode_error`.
   */
  removeExpiredChannels(olderThanSecs: bigint | number | string): Promise<string[]>;

  /**
   * Rebuild this protocol's `secret_id` namespace from a recovered
   * `Secret`. Mirrors the Rust `DeRecProtocol::restore` — pass the
   * typed `secret` carried by the `SecretRecovered` event verbatim.
   *
   * Recovery and restore are separate steps on purpose: `SecretRecovered`
   * writes nothing. Show the user what was recovered, or ask them, before
   * calling `restore`, which commits it to this device.
   *
   * A helper or member whose `transports` is empty gets no channel: it is
   * reported as a `PeerNotRestored` event in the returned array and the rest
   * of the roster is restored.
   *
   * A helper's or member's `communication_info` may be absent or `null`;
   * both mean the same thing — no entries.
   *
   * Errors surface as a `DeRecError` (`category`, `code`, `message`):
   *
   * | code               | meaning                                                          |
   * |--------------------|------------------------------------------------------------------|
   * | `already_restored` | A user-secret snapshot already exists for this `secret_id`.      |
   * | `restore_conflict` | Channels live at ids restore is about to write. The error        |
   * |                    | carries `channel_ids: string[]` listing the collisions.          |
   * | `invariant`        | The recovered `Secret` is internally inconsistent.               |
   * | `invalid_recovered_secret` | `recoveredSecret` is malformed — e.g. a missing or       |
   * |                    | non-decimal `channel_id` / `replica_id`.                         |
   * | `store_error`      | A store call failed mid-restore; `category` names the store.     |
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

// `ContactMessage` is defined once above and covers both
// `INLINE_KEYS` and `HASHED_KEYS` modes.

/** Why a `MessageIgnored` event dropped a message. Matches the Rust
 *  `IgnoreReason` discriminants one-for-one. */
export type IgnoreReason = "PendingVerification" | "Expired" | "TimestampMismatch" | "StaleResponse";

/** Why a `PeerNotRestored` event left a roster entry without a channel.
 *  Matches the Rust `NotRestoredReason` discriminants one-for-one. */
export type NotRestoredReason = "NoTransports";

/** Why a `VerifySharesFailed` event reached no verdict for a channel.
 *  Matches the Rust `VerifyFailureReason` discriminants
 *  one-for-one. */
export type VerifyFailureReason = "NoSharedKey" | "NoProof" | "DispatchFailed";

/** Why a `RecoveryShareCorrupted` event set a helper's share aside.
 *  Matches the Rust `CorruptionReason` discriminants one-for-one:
 *  `Malformed` — no decodable share for the requested secret and version;
 *  `InvalidProof` — the share fails its own Merkle proof;
 *  `Inconsistent` — valid on its own, but its commitment root or ciphertext
 *  disagrees with the shares the secret was rebuilt from. */
export type CorruptionReason = "Malformed" | "InvalidProof" | "Inconsistent";

/**
 * The label vocabulary for `ActionRequired.action_kind`,
 * `AutoAccepted.action_kind` and `RequestFailed.action_kind` — one value per
 * pending-action kind the protocol can raise, plus `"Failed"` for a request
 * whose body could not be decoded or that the channel cannot carry. Matches the Rust `PendingActionKind`
 * discriminants one-for-one.
 */
export type PendingActionKind =
  | "Pairing"
  | "PrePair"
  | "StoreShare"
  | "VerifyShare"
  | "Discovery"
  | "GetShare"
  | "Unpair"
  | "UpdateChannelInfo"
  | "Failed";

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
  /**
   * Present only when `result.status === Ok`. The 32-byte fingerprint nonce
   * the contact creator committed to in `fingerprint_commitment`.
   */
  fingerprint_nonce?: Uint8Array;
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
  /**
   * Present only when `result.status === Ok`. The creator's 32-byte
   * commitment to the fingerprint nonce its `PairResponseMessage` reveals,
   * covering the two keys above.
   */
  fingerprint_commitment?: Uint8Array;
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
  keep_version: number;
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

  /** Initiator's ML-KEM-1024 encapsulation key, validated against the
   * contact's `contactBindingHash`. */
  mlkem_encapsulation_key: Uint8Array;

  /** Initiator's ECIES public key, validated against the contact's
   * `contactBindingHash`. */
  ecies_public_key: Uint8Array;

  /** Nonce echoed from the original `ContactMessage`. */
  nonce: bigint;

  /** The creator's 32-byte commitment to its fingerprint nonce. Copy it into
   * the contact the pair request is built from, alongside the two keys. */
  fingerprint_commitment: Uint8Array;
}

/**
 * A channel paired with how many subshares it holds. A weight of `1` is an
 * ordinary helper; every weight must satisfy `1 <= weight < threshold`.
 * `channelId` is a channel id as bigint or decimal string, e.g. the
 * `channel_id` string from an event.
 */
export type WeightedChannel = [channelId: bigint | string, weight: number];

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
  | "state_store"
  | "input"
  | "protobuf"
  | "invariant"
  | "wasm";

/**
 * Every code `derec_error_code_name` can return, plus the WASM-marshalling
 * codes this binding raises itself before a value reaches the library (see
 * `library/src/interop/wasm/**\/*.rs`'s `js_error` call sites) — rejecting a
 * malformed argument shape, a bad flow kind, or a value that will not fit a
 * `u64`.
 */
export type DeRecErrorCode =
  | "ok"
  | "non_ok_status"
  | "version_mismatch"
  | "invariant"
  | "invalid_input"
  | "protobuf_decode"
  | "protobuf_encode"
  | "protocol_violation"
  | "store_error"
  | "builder_error"
  | "missing_shared_key"
  | "role_mismatch"
  | "replica_id_not_configured"
  | "channel_already_paired"
  | "already_restored"
  | "restore_conflict"
  | "replica_id_conflict"
  | "fingerprint_mismatch"
  | "encryption"
  | "keygen"
  | "finish_pairing_initiator"
  | "finish_pairing_responder"
  | "empty_transport_uri"
  | "invalid_contact_message"
  | "invalid_pair_request_message"
  | "invalid_pair_response_message"
  | "prepair_hash_mismatch"
  | "missing_replica_id"
  | "unexpected_replica_id"
  | "incompatible_parameter_range"
  | "fingerprint_commitment_mismatch"
  | "empty_channels"
  | "duplicate_channel_id"
  | "invalid_threshold"
  | "empty_secret_data"
  | "vss_share_failed"
  | "invalid_weight"
  | "too_many_subshares"
  | "invalid_keep_version"
  | "empty_responses"
  | "empty_committed_derec_share"
  | "decode_committed_derec_share"
  | "decode_derec_share"
  | "secret_id_mismatch"
  | "reconstruction_failed"
  | "malformed_recovered_secret"
  | "ffi_null_ptr"
  | "ffi_bad_length"
  | "ffi_bad_utf8"
  | "ffi_bad_proto"
  | "ffi_invalid_enum"
  | "ffi_bad_shared_key"
  | "ffi_nul_in_string"
  | "transport_invalid"
  | "no_usable_endpoint"
  | "builder_missing"
  | "decode_error"
  | "envelope_decode_error"
  | "internal"
  | "invalid_auto_accept_policy"
  | "invalid_communication_info"
  | "invalid_contact_mode"
  | "invalid_discovery_target"
  | "invalid_flow_kind"
  | "invalid_flow_params"
  | "invalid_max_subshares"
  | "invalid_nonce"
  | "invalid_own_transport"
  | "invalid_parameter_range"
  | "invalid_peer_communication_info"
  | "invalid_protocol"
  | "invalid_recovered_secret"
  | "invalid_refusal_reason"
  | "invalid_replica_id"
  | "invalid_secret_id"
  | "invalid_sender_kind"
  | "invalid_shared_key_length"
  | "invalid_status"
  | "invalid_timeouts"
  | "invalid_transport_protocol"
  | "invalid_unpair_ack"
  | "serialization_error"
  | "serialize"
  | "wasm_deserialize_error"
  | "wasm_serialize_error";

export interface DeRecError {
  category: DeRecErrorCategory;
  code: DeRecErrorCode;
  message: string;
  status?: number;
  memo?: string;
  expected?: number;
  got?: number;
  /** The channel the failing inbound message arrived on, when `process()` could tell. */
  channel_id?: string;
  /**
   * On a failed `process()`: the events it produced before failing, such as
   * sharing-round and unpair timeouts. They are not reported again, so
   * handle them as you would a successful call's events.
   */
  events?: DeRecEvent[];
  /** On a `restore` `restore_conflict`: the pre-existing channels at canonical ids. */
  channel_ids?: string[];
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
        reply_to?: TransportProtocol[],
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
       * @param transport_protocols  Every endpoint this initiator serves, in
       *                             preference order. For `HashedKeys` mode
       *                             they MUST be ephemeral.
       * @param nonce  Correlation nonce embedded in the contact. Omitted or
       *               `null`, the library draws a random `u64` — the right
       *               choice for `InlineKeys` / `HashedKeys`, where the nonce
       *               is a security parameter. Required for `ContactMode.NoKeys`,
       *               where the caller typically picks a short human-typable
       *               value for manual entry. Must fit in a `u64`.
       */
      create_contact(
        channel_id: bigint,
        contact_mode: ContactMode | number,
        transport_protocols: TransportProtocol[],
        nonce?: bigint | number | null,
      ): CreateContactResult;
      /**
       * Serializes a `ContactMessage` to the bytes delivered out of band.
       * Throws on a contact that violates the invariants of its contact mode
       * or advertises no endpoint.
       */
      encode_contact(contact_message: ContactMessage): Uint8Array;
      /**
       * Parses out-of-band contact bytes back into a `ContactMessage`. Throws
       * on bytes that are not a contact, or a contact that violates the
       * invariants of its contact mode.
       */
      decode_contact(bytes: Uint8Array): ContactMessage;
      produce(
        kind: SenderKind,
        transport_protocols: TransportProtocol[],
        contact_message: ContactMessage,
        communication_info: CommunicationInfo | null,
        parameter_range: ParameterRange | null,
      ): PairingRequestProduceResult;

      /**
       * @param parameter_range  The range this side accepts, or `null` for
       *                         none. A request advertising a range that does
       *                         not overlap it is refused with
       *                         `incompatible_parameter_range`.
       */
      extract(
        envelope_bytes: Uint8Array,
        secret_key: Uint8Array,
        parameter_range: ParameterRange | null,
      ): { request: PairRequestMessage };

      /**
       * Scanner-side: build a plaintext `PrePairRequest` envelope when the
       * contact was sent in `HashedKeys` mode. The keys obtained via the
       * matching `PrePairResponse` MUST be checked against the contact's
       * binding hash with `pairing.response.process_pre_pair` before
       * proceeding to a normal `produce`.
       */
      /**
       * @param own_transports  Every endpoint this scanner serves for the
       *                        PrePair reply, in its own preference order.
       */
      produce_pre_pair(
        own_transports: TransportProtocol[],
        contact_message: ContactMessage,
      ): ProducePrePairResult;

      /**
       * Initiator-side: decode an inbound plaintext `PrePairRequest`
       * envelope.
       */
      extract_pre_pair(envelope_bytes: Uint8Array): PrePairRequestExtractResult;
    };
    response: {
      /**
       * @param parameter_range    The range this side accepts and advertises,
       *                           or `null` for none. A request advertising a
       *                           range that does not overlap it is refused
       *                           with `incompatible_parameter_range`.
       * @param unsafe_connection  Accept plaintext peer endpoints
       *                           (`http://`, `grpc://`). Development only.
       */
      produce(
        channel_id: bigint,
        request: PairRequestMessage,
        secret_key: Uint8Array,
        communication_info: CommunicationInfo | null,
        parameter_range: ParameterRange | null,
        unsafe_connection?: boolean,
      ): PairingResponseProduceResult;

      extract(envelope_bytes: Uint8Array, secret_key: Uint8Array): { response: PairResponseMessage };
      /**
       * @param parameter_range  The range this side accepts, or `null` for
       *                         none. A response advertising a range that
       *                         does not overlap it is refused with
       *                         `incompatible_parameter_range` before any key
       *                         is derived.
       */
      process(
        contact_message: ContactMessage,
        response: PairResponseMessage,
        secret_key: Uint8Array,
        parameter_range: ParameterRange | null,
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

      /**
       * Contact-creator side of a `NoKeys` pairing: generate key material and
       * answer the `PrePairRequest` with its public half.
       *
       * The caller MUST first match the request's `nonce` against the contact
       * it issued — the only thing that authenticates a `NoKeys` request — and
       * MUST persist `secret_key_material`. The resulting channel MUST stay
       * unusable until both sides confirm `pairing.fingerprint` out of band.
       */
      produce_pre_pair_no_keys(
        channel_id: bigint,
        request: PrePairRequestMessage,
      ): ProducePrePairNoKeysResult;

      /**
       * Scanner side of a `NoKeys` pairing: accept the contact creator's
       * public keys. There is no binding hash to check them against, so the
       * resulting channel MUST stay unusable until both sides confirm
       * `pairing.fingerprint` out of band. Throws on a non-`Ok` status, a
       * missing key or a `nonce` mismatch.
       */
      process_pre_pair_no_keys(
        contact_message: ContactMessage,
        response: PrePairResponseMessage,
      ): ProcessPrePairResult;
    };

    /**
     * The human-readable fingerprint of a pairing's 32-byte shared key. Both
     * ends derive the same value; comparing it out of band confirms the
     * pairing. A `NoKeys` pairing MUST be confirmed this way before use.
     * Throws on a key that is not 32 bytes.
     */
    fingerprint(shared_key: Uint8Array): string;
  };
  recovery: {
    request: {
      produce(
        channel_id: bigint,
        secret_id: bigint,
        version: number,
        shared_key: Uint8Array,
        /** See `discovery.request.produce.reply_to`. */
        reply_to?: TransportProtocol[],
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
        /** Every channel the secret is split to, each with its own weight
         *  (`1` for an ordinary helper). See {@link WeightedChannel}. */
        channels: WeightedChannel[],
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
        keep_version: number,
        description: string,
        shared_key: Uint8Array,
        /** See `discovery.request.produce.reply_to`. */
        reply_to?: TransportProtocol[],
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
        reply_to?: TransportProtocol[],
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
        reply_to?: TransportProtocol[],
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
