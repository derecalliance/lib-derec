// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.
// Protocol smoke tests: exercises pairing, sharing, and discovery+recovery
// using the low-level `DeRecProtocol` runtime (`start` / `process` / `accept`)
// backed by in-memory stores.
// This is a React Native port of the verified Node.js smoke test
// (`smoke-tests/nodejs/protocol.ts`), which is itself a port of the web one. The
// public surface is identical across all three, so the scenarios are carried
// over unchanged apart from three runtime differences:
//   - `TextEncoder`/`TextDecoder` do not exist in Hermes, so `./utf8` stands in.
//   - `setCommunicationInfo` and `setOwnTransports` return a `Promise` here
//     (they queue onto the protocol's serial worker rather than running on the
//     JavaScript thread), so the scenarios await them.
//   - `StateStore.loadAll` takes a fifth `kind` (`4` = PendingReplicaDiscovery).
// No UI: every `ActionRequired` event a peer receives is auto-accepted via
// `processAll`. The store implementations track channel links as a graph and
// resolve them by BFS closure, key shares for lookup, and record transport
// calls for assertions; they are Map-backed instead of localStorage-backed.

import { channelFilterMatches, ContactMode, DeRecProtocol, DeRecProtocolBuilder, FlowKind, SenderKind, StatusEnum, primitives, shareStoreRefusal } from "@derec-alliance/react-native";
import { utf8Decode, utf8Encode } from "./utf8";
import type {
  ChannelStatusName,
  ChannelStore,
  ContactMessage,
  DeRecError,
  DeRecEvent,
  DeRecProtocolConfig,
  HelperFilter,
  ParameterRange,
  ReplicaFilter,
  ReplicaRoleName,
  SecretStore,
  SenderKindName,
  Share,
  ShareStore,
  StateStore,
  Transport,
  UserSecretStore,
  UserSecrets,
} from "@derec-alliance/react-native";
import protocolConfigFixtures from "../../../library/tests/fixtures/protocol_config.json";

/**
 * The unrestricted filters, for assertions that want the whole listing.
 * Every field empty is exactly what the core means by "no restriction".
 */
const ANY_HELPERS: HelperFilter = { ids: [], status: [], role: null, exclude: [] };
const ANY_REPLICAS: ReplicaFilter = { ids: [], status: [], role: null, exclude: [] };


const kindName = (k: SenderKind): string => {
  switch (k) {
    case SenderKind.Owner:
      return "Owner";
    case SenderKind.Helper:
      return "Helper";
    case SenderKind.ReplicaSource:
      return "ReplicaSource";
    case SenderKind.ReplicaDestination:
      return "ReplicaDestination";
    default:
      return `Unknown(${k})`;
  }
};


// kind 0 = SharedKey (32 raw bytes), kind 1 = PairingSecret (ephemeral),
// kind 2 = PairingContact (ephemeral). Keyed by `${secretId}:${channelId}:${kind}`.
class InMemorySecretStore implements SecretStore {
  private readonly data = new Map<string, Uint8Array>();
  /** The `channelIds` of every `loadMany` call, in order. */
  readonly loadManyCalls: string[][] = [];

  private key(secretId: string, channelId: string, kind: 0 | 1 | 2): string {
    return `${secretId}:${channelId}:${kind}`;
  }

  async load(
    secretId: string,
    channelId: string,
    kind: 0 | 1 | 2,
  ): Promise<Uint8Array | null> {
    return this.data.get(this.key(secretId, channelId, kind)) ?? null;
  }

  async loadMany(
    secretId: string,
    channelIds: string[],
    kind: 0 | 1 | 2,
  ): Promise<Array<Uint8Array | null>> {
    this.loadManyCalls.push([...channelIds]);
    return channelIds.map(
      (id) => this.data.get(this.key(secretId, id, kind)) ?? null,
    );
  }

  async save(
    secretId: string,
    channelId: string,
    kind: 0 | 1 | 2,
    value: Uint8Array,
  ): Promise<void> {
    this.data.set(this.key(secretId, channelId, kind), value);
  }

  async remove(secretId: string, channelId: string, kind: 0 | 1 | 2): Promise<void> {
    this.data.delete(this.key(secretId, channelId, kind));
  }
}

// Stores opaque channel-record bytes plus the channel-link graph,
// partitioned by `secretId`.
class InMemoryChannelStore implements ChannelStore {
  // Two maps, mirroring the two primary keys the interface defines: a
  // helper channel is unique per channelId, while a replica-group member is
  // unique per replicaId and moves between channels during an admission
  // handover — so a member must stay findable when its channel changes.
  private readonly helpers = new Map<string, Uint8Array>();
  private readonly members = new Map<string, Uint8Array>();
  private readonly links = new Map<string, Set<string>>();

  private key(secretId: string, id: string): string {
    return `${secretId}:${id}`;
  }

  private mapFor(replicaId: string): Map<string, Uint8Array> {
    return replicaId === "0" ? this.helpers : this.members;
  }

  private idFor(channelId: string, replicaId: string): string {
    return replicaId === "0" ? channelId : replicaId;
  }

  async load(
    secretId: string,
    channelId: string,
    replicaId: string,
  ): Promise<Uint8Array | null> {
    return (
      this.mapFor(replicaId).get(
        this.key(secretId, this.idFor(channelId, replicaId)),
      ) ?? null
    );
  }

  async save(
    secretId: string,
    channelId: string,
    replicaId: string,
    bytes: Uint8Array,
  ): Promise<void> {
    this.mapFor(replicaId).set(
      this.key(secretId, this.idFor(channelId, replicaId)),
      bytes,
    );
  }

  async remove(
    secretId: string,
    channelId: string,
    replicaId: string,
  ): Promise<boolean> {
    return this.mapFor(replicaId).delete(
      this.key(secretId, this.idFor(channelId, replicaId)),
    );
  }

  // The listing callbacks return a JSON array of the inner records.
  //
  // The stored bytes are spliced as text rather than parsed and
  // re-serialized: channel and replica ids are u64, and round-tripping
  // them through JSON.parse would silently round every value above
  // 2**53 to the nearest double. A record is always the externally
  // tagged `{"<variant>":{...}}` serde emits, so stripping the wrapper
  // is a prefix/suffix slice.
  //
  // The filter is applied against a *parsed copy* — reading `status` and
  // `role` is safe, and the id comes from the map key, which is already the
  // exact decimal string. The bytes pushed to the output are always the
  // original slice, so the precision guarantee above still holds.
  private list(
    secretId: string,
    variant: "Helper" | "Replica",
    filter: HelperFilter | ReplicaFilter,
  ): Uint8Array {
    const source = variant === "Helper" ? this.helpers : this.members;
    const prefix = `${secretId}:`;
    const tag = `{"${variant}":`;
    const inner: string[] = [];
    for (const [k, v] of source) {
      if (!k.startsWith(prefix)) continue;
      const text = utf8Decode(v);
      if (!text.startsWith(tag)) continue;
      const body = text.slice(tag.length, -1);
      const id = k.slice(prefix.length);
      if (!matchesFilter(filter, id, body, variant)) continue;
      inner.push(body);
    }
    return utf8Encode(`[${inner.join(",")}]`);
  }

  async listHelpers(secretId: string, filter: HelperFilter): Promise<Uint8Array> {
    return this.list(secretId, "Helper", filter);
  }

  async listReplicas(secretId: string, filter: ReplicaFilter): Promise<Uint8Array> {
    return this.list(secretId, "Replica", filter);
  }

  private linkKey(secretId: string, channelId: string): string {
    return `${secretId}:${channelId}`;
  }

  async linkChannel(secretId: string, a: string, b: string): Promise<void> {
    if (a === b) return;
    const ka = this.linkKey(secretId, a);
    const kb = this.linkKey(secretId, b);
    if (!this.links.has(ka)) this.links.set(ka, new Set());
    if (!this.links.has(kb)) this.links.set(kb, new Set());
    this.links.get(ka)!.add(b);
    this.links.get(kb)!.add(a);
  }

  /** Transitive closure of `channelId`, including `channelId` itself. */
  async linkedChannels(secretId: string, channelId: string): Promise<string[]> {
    const visited = new Set<string>();
    const queue: string[] = [channelId];
    while (queue.length > 0) {
      const curr = queue.shift()!;
      if (visited.has(curr)) continue;
      visited.add(curr);
      for (const linked of this.links.get(this.linkKey(secretId, curr)) ?? []) {
        if (!visited.has(linked)) queue.push(linked);
      }
    }
    return Array.from(visited);
  }
}

// Pure keyed share store. It never sees the channel-link graph — recovery
// resolves the linked channel set via `ChannelStore.linkedChannels` and
// passes it to `loadMany` (scoped to one `secretId`). Discovery instead
// uses `loadAll`, which is the one legitimate "no secretId" load — it
// enumerates the helper's holdings before any secret is known. Versions
// are namespaced by `secretId`: the same `version` number can exist for
// two different secrets, so a version-only query would conflate them.
class InMemoryShareStore implements ShareStore {
  // Keyed by `${secretId}:${channelId}` → version → Share.
  private readonly data = new Map<string, Map<number, Share>>();
  private readonly ownerVersions = new Map<string, number>();

  private key(secretId: string, channelId: string): string {
    return `${secretId}:${channelId}`;
  }

  async load(
    secretId: string,
    channelId: string,
    versions: number[],
  ): Promise<Share[]> {
    const byVersion = this.data.get(this.key(secretId, channelId));
    if (!byVersion) return [];
    const filter = versions.length > 0 ? new Set(versions) : null;
    const result: Share[] = [];
    for (const [v, share] of byVersion) {
      if (filter && !filter.has(v)) continue;
      result.push(share);
    }
    return result;
  }

  async save(
    secretId: string,
    channelId: string,
    share: Share,
  ): Promise<void> {
    if (this.refuseSaves) throw shareStoreRefusal("too_frequent");
    if (this.failSaves) throw new Error("share store unavailable");
    const k = this.key(secretId, channelId);
    let byVersion = this.data.get(k);
    if (!byVersion) {
      byVersion = new Map();
      this.data.set(k, byVersion);
    }
    byVersion.set(share.version, share);
  }

  async loadMany(
    secretId: string,
    channelIds: string[],
    versions: number[],
  ): Promise<Share[]> {
    const filter = versions.length > 0 ? new Set(versions) : null;
    const result: Share[] = [];
    for (const channelId of channelIds) {
      const byVersion = this.data.get(this.key(secretId, channelId));
      if (!byVersion) continue;
      for (const [v, share] of byVersion) {
        if (filter && !filter.has(v)) continue;
        result.push(share);
      }
    }
    return result;
  }

  async loadAll(secretId: string, channelIds: string[]): Promise<Share[]> {
    const result: Share[] = [];
    for (const channelId of channelIds) {
      const byVersion = this.data.get(this.key(secretId, channelId));
      if (!byVersion) continue;
      for (const share of byVersion.values()) result.push(share);
    }
    return result;
  }

  async removeChannel(secretId: string, channelId: string): Promise<void> {
    this.data.delete(this.key(secretId, channelId));
  }

  readonly removeVersionsCalls: Array<{ secretId: string; channelId: string; versions: number[] }> = [];

  async removeVersions(secretId: string, channelId: string, versions: number[]): Promise<void> {
    this.removeVersionsCalls.push({ secretId, channelId, versions: [...versions] });
    const byVersion = this.data.get(this.key(secretId, channelId));
    if (!byVersion) return;
    for (const v of versions) byVersion.delete(v);
  }

  async keepList(): Promise<number[] | null> {
    return null;
  }

  /** Refuse with `too_frequent`, the way an app's rate limit would. */
  refuseSaves = false;
  refuseVerifications = false;
  /** Fail every save with a plain error, the way an unavailable backend would. */
  failSaves = false;

  async recordVerification(): Promise<void> {
    if (this.refuseVerifications) throw shareStoreRefusal("too_frequent");
  }

  async latestVersion(secretId: string): Promise<number | null> {
    return this.ownerVersions.get(secretId) ?? null;
  }

  setOwnerVersion(secretId: string, version: number): void {
    this.ownerVersions.set(secretId, version);
  }
}


/**
 * Keyed by `secretId` — at most one `UserSecrets` per id. The most recent
 * `start(ProtectSecret)` snapshot the protocol stored.
 */
class InMemoryUserSecretStore implements UserSecretStore {
  private readonly data = new Map<string, UserSecrets>();

  async loadLatest(secretId: string): Promise<UserSecrets | null> {
    return this.data.get(secretId) ?? null;
  }

  async saveLatest(secretId: string, value: UserSecrets): Promise<void> {
    this.data.set(secretId, value);
  }

  async remove(secretId: string): Promise<void> {
    this.data.delete(secretId);
  }
}


// Rows are keyed by `(secretId, kind, channel_id, version)` — extracted
// from the JSON blob so `loadAll(kind)` can filter without decoding
// every stored entry.
interface StateRecord {
  kind: number;
  channel_id?: string;
  secret_id?: string;
  version?: number;
}

class InMemoryStateStore implements StateStore {
  private readonly data = new Map<string, Uint8Array>();

  private compositeKey(
    secretId: string,
    rec: StateRecord,
  ): string {
    // secret_id is part of the key: a PendingRecovery row names the
    // secret being recovered, which differs from `secretId` when
    // recovering from an ephemeral instance, and two vaults can be
    // recovered concurrently at the same version.
    return [
      secretId,
      rec.kind,
      rec.channel_id ?? "",
      rec.secret_id ?? "",
      rec.version ?? "",
    ].join(":");
  }

  private parseBlob(bytes: Uint8Array): StateRecord {
    return JSON.parse(utf8Decode(bytes));
  }

  async save(secretId: string, itemJson: Uint8Array): Promise<void> {
    const rec = this.parseBlob(itemJson);
    this.data.set(this.compositeKey(secretId, rec), itemJson);
  }

  async load(secretId: string, keyJson: Uint8Array): Promise<Uint8Array | null> {
    const rec = this.parseBlob(keyJson);
    return this.data.get(this.compositeKey(secretId, rec)) ?? null;
  }

  async remove(secretId: string, keyJson: Uint8Array): Promise<boolean> {
    const rec = this.parseBlob(keyJson);
    return this.data.delete(this.compositeKey(secretId, rec));
  }

  async loadAll(secretId: string, kind: 0 | 1 | 2 | 3 | 4): Promise<Uint8Array[]> {
    const prefix = `${secretId}:${kind}:`;
    const out: Uint8Array[] = [];
    for (const [k, v] of this.data.entries()) {
      if (k.startsWith(prefix)) out.push(v);
    }
    return out;
  }
}


interface OutboundMessage {
  endpoint: { protocol: string; uri: string };
  message: Uint8Array;
}

class RecordingTransport implements Transport {
  private outbox: OutboundMessage[] = [];

  // The library hands over every endpoint the peer advertised, filtered but
  // unranked, and delivery to any one of them is success. A real transport
  // would try them in order and fall back; recording the first keeps the
  // outbox assertions below addressed by a single uri.
  async send(
    endpoints: ReadonlyArray<{ protocol: string; uri: string }>,
    message: Uint8Array,
  ): Promise<void> {
    const endpoint = endpoints[0];
    if (!endpoint) {
      throw new Error("transport: send called with no endpoints");
    }
    this.outbox.push({ endpoint, message });
  }

  /** Returns and clears all queued outbound messages. */
  drain(): OutboundMessage[] {
    return this.outbox.splice(0);
  }
}


interface Node {
  protocol: DeRecProtocol;
  transport: RecordingTransport;
  channelStore: InMemoryChannelStore;
  shareStore: InMemoryShareStore;
  secretStore: InMemorySecretStore;
  userSecretStore: InMemoryUserSecretStore;
  stateStore: InMemoryStateStore;
}

const THRESHOLD = 2;
const DEFAULT_TEST_SECRET_ID = 0xDE_2ECn;


function makeNode(
  name: string,
  endpointUri: string,
  options: {
    autoReplyTo?: boolean;
    autoAccept?: import("@derec-alliance/react-native").AutoAcceptPolicy;
    channelStore?: InMemoryChannelStore;
    replicaId?: bigint;
    secretId?: bigint;
    threshold?: number;
    unsafeConnection?: boolean;
    maxSubshares?: bigint;
    parameterRange?: Partial<ParameterRange>;
    autoRespondOnFailure?: boolean;
  } = {},
): Node {
  const channelStore = options.channelStore ?? new InMemoryChannelStore();
  const shareStore = new InMemoryShareStore();
  const secretStore = new InMemorySecretStore();
  const userSecretStore = new InMemoryUserSecretStore();
  const stateStore = new InMemoryStateStore();
  const transport = new RecordingTransport();
  // Exercises withStores, the one-call store bundle: every other builder
  // construction in this file still wires the five stores individually, so
  // both paths stay exercised.
  let builder = new DeRecProtocolBuilder(options.secretId ?? DEFAULT_TEST_SECRET_ID)
    .withStores({ channelStore, shareStore, secretStore, userSecretStore, stateStore })
    .withTransport(transport)
    .withOwnTransports([{ uri: endpointUri, protocol: "https" }])
    .withThreshold(options.threshold ?? THRESHOLD)
    .withCommunicationInfo({ name });
  if (options.autoReplyTo !== undefined) {
    builder = builder.withAutoReplyTo(options.autoReplyTo);
  }
  if (options.autoAccept !== undefined) {
    builder = builder.withAutoAccept(options.autoAccept);
  }
  if (options.replicaId !== undefined) {
    builder = builder.withReplicaId(options.replicaId);
  }
  if (options.unsafeConnection !== undefined) {
    builder = builder.withUnsafeConnection(options.unsafeConnection);
  }
  if (options.maxSubshares !== undefined) {
    builder = builder.withMaxSubshares(options.maxSubshares);
  }
  if (options.parameterRange !== undefined) {
    builder = builder.withParameterRange(options.parameterRange);
  }
  if (options.autoRespondOnFailure !== undefined) {
    builder = builder.withAutoRespondOnFailure(options.autoRespondOnFailure);
  }
  const protocol = builder.build();
  return { protocol, transport, channelStore, shareStore, secretStore, userSecretStore, stateStore };
}


function requireEvent<T extends DeRecEvent["type"]>(
  events: DeRecEvent[],
  type: T,
  context: string,
): Extract<DeRecEvent, { type: T }> {
  const ev = events.find((e) => e.type === type) as
    | Extract<DeRecEvent, { type: T }>
    | undefined;
  if (!ev) {
    throw new Error(
      `${context}: expected ${type} event, got [${events.map((e) => e.type).join(", ")}]`,
    );
  }
  return ev;
}


/**
 * Feed inbound bytes to a node and auto-accept every resulting
 * `ActionRequired` action (no UI confirmation in the smoke test). Returns the
 * flat list of events produced by `process` plus every `accept`.
 */
async function processAll(node: Node, bytes: Uint8Array): Promise<DeRecEvent[]> {
  const events = await node.protocol.process(bytes);
  const out: DeRecEvent[] = [...events];
  for (const ev of events) {
    if (ev.type === "ActionRequired") {
      out.push(...(await node.protocol.accept(ev.action)));
    }
  }
  return out;
}

/**
 * Asserts a StoreShare `ActionRequired` carries the request's `trace_id` and
 * a `share_size` equal to the length of the share the owner sent, read back
 * by decrypting `request` with the owner's key for the channel.
 */
async function assertStoreShareAction(
  owner: Node,
  action: Extract<DeRecEvent, { type: "ActionRequired" }>,
  request: Uint8Array,
  label: string,
): Promise<void> {
  if (action.action_kind !== "StoreShare") {
    throw new Error(`${label}: expected StoreShare action, got ${action.action_kind}`);
  }
  if (typeof action.trace_id !== "string" || action.trace_id.length === 0) {
    throw new Error(`${label}: ActionRequired.trace_id must be a non-empty string`);
  }
  const sharedKey = await owner.secretStore.load(
    String(owner.protocol.secretId()),
    action.channel_id,
    0,
  );
  if (!sharedKey) throw new Error(`${label}: owner shared_key missing`);
  const { request: sent } = primitives.sharing.request.extract(request, sharedKey);
  if (action.share_size !== sent.share.length) {
    throw new Error(
      `${label}: ActionRequired.share_size ${action.share_size} ≠ sent share length ${sent.share.length}`,
    );
  }
  console.log(
    `  [${label}] ActionRequired(StoreShare) trace_id=${action.trace_id} share_size=${action.share_size}  ✓`,
  );
}

/** `true` if two `Uint8Array`s are byte-for-byte identical. */
function byteArraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/** Drains exactly one queued outbound message or throws. */
function drainOne(node: Node, label: string): Uint8Array {
  const [msg] = node.transport.drain();
  if (!msg) throw new Error(`${label}: expected one outbound message, got none`);
  return msg.message;
}

/**
 * Performs a full pairing handshake.
 *
 * `contactCreator` calls `createContact(channelId)` and therefore acts as the
 * Helper side; `initiator` drives the flow with `FlowKind.Pairing` passing
 * `kind: SenderKind.Owner`.
 */
async function doPair(
  contactCreator: Node,
  initiator: Node,
  channelId: bigint,
  label: string,
): Promise<{ longTermChannelId: string }> {
  const contact: ContactMessage =
    await contactCreator.protocol.createContact(channelId, ContactMode.InlineKeys);
  console.log(
    `  [${label}/ContactCreator] createContact channel_id=${contact.channel_id}`,
  );

  const startEvents = await initiator.protocol.start(FlowKind.Pairing, {
    kind: SenderKind.Owner,
    contact,
  });
  const startPairing = requireEvent(
    startEvents,
    "PairingStarted",
    `${label}/Initiator`,
  );
  if (String(startPairing.channel_id) !== String(contact.channel_id)) {
    throw new Error(
      `${label}/Initiator: PairingStarted.channel_id ${startPairing.channel_id} must echo contact.channel_id ${contact.channel_id}`,
    );
  }
  if (startPairing.kind !== SenderKind.Owner) {
    throw new Error(
      `${label}/Initiator: PairingStarted.kind must equal the requested local role (Owner), got ${startPairing.kind}`,
    );
  }
  const pairRequest = drainOne(initiator, `${label}/Initiator`);
  console.log(
    `  [${label}/Initiator]     start(Pairing, kind=Owner) → PairingStarted(channel_id=${startPairing.channel_id}) PairRequest ${pairRequest.length}B`,
  );

  const creatorEvents = await processAll(contactCreator, pairRequest);
  const creatorPairing = requireEvent(
    creatorEvents,
    "PairingCompleted",
    `${label}/ContactCreator`,
  );
  const pairResponse = drainOne(contactCreator, `${label}/ContactCreator`);
  console.log(
    `  [${label}/ContactCreator] process(PairRequest) → PairingCompleted(kind=${kindName(creatorPairing.kind)}) PairResponse ${pairResponse.length}B`,
  );

  const initiatorEvents = await processAll(initiator, pairResponse);
  const initiatorPairing = requireEvent(
    initiatorEvents,
    "PairingCompleted",
    `${label}/Initiator`,
  );
  console.log(
    `  [${label}/Initiator]     process(PairResponse) → PairingCompleted(kind=${kindName(initiatorPairing.kind)})`,
  );
  // Both peers rotate to the same long-term id at handshake completion.
  // Every mode rekeys onto a long-term id derived from the shared key. The
  // responder cannot pick it — the initiator re-derives the same value and
  // rejects any other — so this holds whatever the contact mode.
  if (initiatorPairing.channel_id === String(channelId)) {
    throw new Error(
      `${label}: the long-term channel id must differ from the transient pairing id`,
    );
  }

  return { longTermChannelId: initiatorPairing.channel_id };
}


async function runPairingFlow(): Promise<void> {
  console.log("=== [Protocol] Pairing Flow ===\n");

  const owner = makeNode("Owner", "https://owner.example.com");
  const helper = makeNode("Helper", "https://helper.example.com");

  // Tick before anything is in flight: proves the binding is wired and that
  // an idle protocol is safe for a timer to poke.
  const idle = await owner.protocol.tick();
  if (idle.length !== 0) {
    throw new Error(`idle tick must produce no events, got ${idle.length}`);
  }
  console.log("  tick() on an idle protocol returns no events  ✓");

  await doPair(helper, owner, 1n, "Pairing");

  console.log("\n✓ Pairing flow passed.\n");
}


/**
 * `verifyFingerprint(wrong)` on a still-`Pending` channel must (a)
 * return `false` and (b) leave `Channel.status` as `"Pending"`. The
 * protocol must not downgrade or otherwise mutate the channel on a
 * failed match.
 */
async function runFingerprintMismatchFlow(): Promise<void> {
  console.log("=== [Protocol] Fingerprint mismatch ===\n");

  const channelId = 5151n;
  const sharedKey = new Uint8Array(32);
  for (let i = 0; i < 32; i++) sharedKey[i] = (i * 11 + 5) & 0xff;

  const node = makeNode("Owner", "https://owner.example.com");

  // Pre-seed a Pending channel + its 32-byte SharedKey. Mirrors the
  // post-replica-pair state where fingerprint verification is still
  // required to transition the channel to `Paired`.
  const replicaId = 0xcafe;
  const channelJson = {
    Replica: {
      channel_id: Number(channelId),
      replica_id: replicaId,
      transports: [{ uri: "https://peer.example.com", protocol: 0 }],
      communication_info: {},
      role: "Destination",
      status: "Pending",
      created_at: 1700000000,
    },
  };
  const nodeSid = String(node.protocol.secretId());
  await node.channelStore.save(
    nodeSid,
    String(channelId),
    String(replicaId),
    utf8Encode(JSON.stringify(channelJson)),
  );
  await node.secretStore.save(nodeSid, String(channelId), 0, sharedKey);

  const unmatched = await node.protocol.verifyFingerprint(channelId, "0000-0000-0000-0000");
  if (unmatched) {
    throw new Error("verifyFingerprint must return false for a wrong fingerprint");
  }

  // Critical invariant for 5.1: the stored channel record must still
  // report Pending; the protocol must not have touched it.
  const storedBytes = await node.channelStore.load(
    nodeSid,
    String(channelId),
    String(replicaId),
  );
  if (!storedBytes) throw new Error("member record missing after verify");
  const stored = JSON.parse(utf8Decode(storedBytes)).Replica;
  if (stored.status !== "Pending") {
    throw new Error(
      `verifyFingerprint(wrong) must leave the member status as Pending; got ${stored.status}`,
    );
  }
  console.log("  verifyFingerprint(wrong) returns false  ✓");
  console.log("  Channel.status stays Pending after mismatch  ✓");
  console.log("\n✓ Fingerprint mismatch passed.\n");
}


/**
 * HashedKeys variant of {@link doPair}.
 *
 * `contactCreator` advertises only a SHA-384 binding hash over its real keys.
 * `initiator` scans it, sends a plaintext `PrePairRequest`, validates the
 * `PrePairResponse` against the binding hash, and then auto-proceeds to a
 * regular encrypted `PairRequest`. The whole 4-leg chain is driven by feeding
 * each outbound message into the peer's `processAll` (which auto-accepts the
 * `ActionRequired::PrePair` and `ActionRequired::Pairing` events).
 */
/**
 * Drives the two contact modes that need a PrePair leg. They share the whole
 * wire choreography and differ only in what the contact carries: `HashedKeys`
 * commits to the keys with a SHA-384 hash, `NoKeys` carries nothing at all and
 * the creator generates keys on the fly, authenticating the request by nonce.
 */
async function doPairViaPrePair(
  contactCreator: Node,
  initiator: Node,
  channelId: bigint,
  label: string,
  mode: ContactMode.HashedKeys | ContactMode.NoKeys,
): Promise<{ longTermChannelId: string }> {
  const modeName = mode === ContactMode.HashedKeys ? "HashedKeys" : "NoKeys";
  const contact: ContactMessage =
    await contactCreator.protocol.createContact(channelId, mode);
  if (contact.contact_mode !== mode) {
    throw new Error(`${label}: contact must advertise contact_mode = ${modeName}`);
  }
  if (contact.mlkem_encapsulation_key !== undefined) {
    throw new Error(`${label}: ${modeName} contact must NOT carry the ML-KEM key inline`);
  }
  if (contact.ecies_public_key !== undefined) {
    throw new Error(`${label}: ${modeName} contact must NOT carry the ECIES key inline`);
  }
  if (mode === ContactMode.HashedKeys) {
    if (!contact.contact_binding_hash || contact.contact_binding_hash.length !== 48) {
      throw new Error(`${label}: HashedKeys contact must carry a 48-byte SHA-384 binding hash`);
    }
  } else if (contact.contact_binding_hash !== undefined) {
    throw new Error(
      `${label}: NoKeys contact must carry no binding hash — there is nothing to commit to`,
    );
  }
  console.log(
    `  [${label}/ContactCreator] createContact(${modeName}) channel_id=${contact.channel_id}`,
  );

  await initiator.protocol.start(FlowKind.Pairing, {
    kind: SenderKind.Owner,
    contact,
  });
  const prePairRequest = drainOne(initiator, `${label}/Initiator`);
  console.log(
    `  [${label}/Initiator]     start(Pairing, kind=Owner) → PrePairRequest ${prePairRequest.length}B`,
  );

  // Scanner → ContactCreator: PrePairRequest.
  // ContactCreator auto-accepts via processAll → emits no event, sends
  // PrePairResponse carrying its real keys.
  const creatorPrePairEvents = await processAll(contactCreator, prePairRequest);
  if (creatorPrePairEvents.some((e) => e.type === "PrePairRejected")) {
    throw new Error(
      `${label}/ContactCreator: happy path must not emit PrePairRejected`,
    );
  }
  const prePairResponse = drainOne(contactCreator, `${label}/ContactCreator`);
  console.log(
    `  [${label}/ContactCreator] processAll(PrePairRequest) → PrePairResponse ${prePairResponse.length}B (silent on this side)`,
  );

  // ContactCreator → Scanner: PrePairResponse. Scanner validates the
  // binding hash, synthesizes an inline-shaped contact, and silently
  // emits a regular PairRequest. No event surfaces on success.
  const initiatorPrePairEvents = await processAll(initiator, prePairResponse);
  if (initiatorPrePairEvents.some((e) => e.type === "PrePairRejected")) {
    throw new Error(
      `${label}/Initiator: happy path must not emit PrePairRejected`,
    );
  }
  const pairRequest = drainOne(initiator, `${label}/Initiator`);
  console.log(
    `  [${label}/Initiator]     process(PrePairResponse) → PairRequest ${pairRequest.length}B (PrePair validated silently)`,
  );

  // Scanner → ContactCreator: PairRequest. From here the flow is
  // identical to the InlineKeys path.
  const creatorPairEvents = await processAll(contactCreator, pairRequest);
  const creatorPairing = requireEvent(
    creatorPairEvents,
    "PairingCompleted",
    `${label}/ContactCreator`,
  );
  const pairResponse = drainOne(contactCreator, `${label}/ContactCreator`);
  console.log(
    `  [${label}/ContactCreator] process(PairRequest) → PairingCompleted(kind=${kindName(creatorPairing.kind)}) PairResponse ${pairResponse.length}B`,
  );

  const initiatorPairEvents = await processAll(initiator, pairResponse);
  const initiatorPairing = requireEvent(
    initiatorPairEvents,
    "PairingCompleted",
    `${label}/Initiator`,
  );
  console.log(
    `  [${label}/Initiator]     process(PairResponse) → PairingCompleted(kind=${kindName(initiatorPairing.kind)})`,
  );
  // Both peers rotate to the same long-term id at handshake completion —
  // return it so downstream assertions can key on it instead of the
  // transient pairing_channel_id.
  // Every mode rekeys onto a long-term id derived from the shared key. The
  // responder cannot pick it — the initiator re-derives the same value and
  // rejects any other — so this holds whatever the contact mode.
  if (initiatorPairing.channel_id === String(channelId)) {
    throw new Error(
      `${label}: the long-term channel id must differ from the transient pairing id`,
    );
  }

  return { longTermChannelId: initiatorPairing.channel_id };
}


/**
 * The third contact mode, which the SDK exposed but never exercised.
 *
 * `NoKeys` carries no key material and no commitment, so trust rests entirely
 * on the out-of-band channel that delivered the contact — the weakest of the
 * three, and therefore the one most worth covering.
 */
async function runNoKeysPairingFlow(): Promise<void> {
  console.log("=== [Protocol] NoKeys Pairing Flow ===\n");

  const owner = makeNode("Owner", "https://owner.example.com");
  const helper = makeNode("Helper", "https://helper.example.com");
  const { longTermChannelId } = await doPairViaPrePair(
    helper,
    owner,
    3n,
    "NoKeys",
    ContactMode.NoKeys,
  );

  const ownerSid = String(owner.protocol.secretId());
  const helperSid = String(helper.protocol.secretId());
  const ownerSharedKey = await owner.secretStore.load(ownerSid, longTermChannelId, 0);
  const helperSharedKey = await helper.secretStore.load(helperSid, longTermChannelId, 0);
  if (!ownerSharedKey || !helperSharedKey) {
    throw new Error("NoKeys pairing: both sides must have a stored shared key");
  }
  if (
    ownerSharedKey.length !== helperSharedKey.length ||
    !ownerSharedKey.every((b, i) => b === helperSharedKey[i])
  ) {
    throw new Error("NoKeys pairing: owner/helper shared keys do not match");
  }
  console.log(`  shared keys match (${ownerSharedKey.length}B)  ✓`);

  // The creator stores the contact under NoKeys so it can authenticate the
  // PrePairRequest by nonce. Once the handshake has rekeyed onto the long-term
  // channel that row is spent, and it used to outlive the handshake.
  const strandedContact = await helper.secretStore.load(helperSid, "3", 2);
  if (strandedContact) {
    throw new Error(
      "NoKeys pairing: the transient PairingContact must not outlive the handshake",
    );
  }
  console.log("  the spent transient PairingContact was dropped  ✓\n");

  // The gate. NoKeys inlines neither the keys nor a commitment to them, so
  // nothing binds what arrived over the plaintext PrePair leg to the contact
  // delivered out of band. Both sides hold the channel Pending until the
  // fingerprints — derived from the established shared key — are compared.
  const helperStatus = async (node: Node, sid: string): Promise<string> => {
    const bytes = await node.channelStore.load(sid, longTermChannelId, "0");
    if (!bytes) throw new Error("NoKeys pairing: channel record missing");
    return JSON.parse(utf8Decode(bytes)).Helper.status;
  };

  for (const [label, node, sid] of [
    ["owner", owner, ownerSid],
    ["helper", helper, helperSid],
  ] as const) {
    const status = await helperStatus(node, sid);
    if (status !== "Pending") {
      throw new Error(
        `NoKeys pairing: ${label} channel must be Pending before confirmation; got ${status}`,
      );
    }
  }
  console.log("  both sides hold the channel Pending until confirmed  ✓");

  const ownerFingerprint = await owner.protocol.getFingerprint(BigInt(longTermChannelId));
  const helperFingerprint = await helper.protocol.getFingerprint(BigInt(longTermChannelId));
  if (ownerFingerprint !== helperFingerprint) {
    throw new Error("NoKeys pairing: both sides must derive one fingerprint");
  }
  if (!(await owner.protocol.verifyFingerprint(BigInt(longTermChannelId), helperFingerprint))) {
    throw new Error("NoKeys pairing: owner verifyFingerprint must match");
  }
  if (!(await helper.protocol.verifyFingerprint(BigInt(longTermChannelId), ownerFingerprint))) {
    throw new Error("NoKeys pairing: helper verifyFingerprint must match");
  }

  for (const [label, node, sid] of [
    ["owner", owner, ownerSid],
    ["helper", helper, helperSid],
  ] as const) {
    const status = await helperStatus(node, sid);
    if (status !== "Paired") {
      throw new Error(
        `NoKeys pairing: ${label} channel must be Paired once confirmed; got ${status}`,
      );
    }
  }
  console.log("  confirming the fingerprint opens the channel on both sides  ✓\n");

  console.log("✓ NoKeys pairing flow passed.\n");
}


async function runHashedKeysPairingFlow(): Promise<void> {
  console.log("=== [Protocol] HashedKeys Pairing Flow ===\n");

  // Happy path: full 4-leg chain ends with PairingCompleted on both sides.
  const owner = makeNode("Owner", "https://owner.example.com");
  const helper = makeNode("Helper", "https://helper.example.com");
  const { longTermChannelId } = await doPairViaPrePair(
    helper,
    owner,
    1n,
    "HashedKeys",
    ContactMode.HashedKeys,
  );

  // Both sides must have a paired channel record + a shared key in their
  // secret store (kind 0 = SharedKey) under the rotated long-term
  // channel_id. The latter is the strongest end-to-end check that the
  // PrePair → Pair chain converged on the same key on both sides.
  const ownerSid = String(owner.protocol.secretId());
  const helperSid = String(helper.protocol.secretId());
  const ownerChannel = await owner.channelStore.load(ownerSid, longTermChannelId, "0");
  const helperChannel = await helper.channelStore.load(helperSid, longTermChannelId, "0");
  if (!ownerChannel || !helperChannel) {
    throw new Error("HashedKeys pairing: both sides must have a stored channel record");
  }
  const ownerSharedKey = await owner.secretStore.load(ownerSid, longTermChannelId, 0);
  const helperSharedKey = await helper.secretStore.load(helperSid, longTermChannelId, 0);
  if (!ownerSharedKey || !helperSharedKey) {
    throw new Error("HashedKeys pairing: both sides must have a stored shared key");
  }
  if (
    ownerSharedKey.length !== helperSharedKey.length ||
    !ownerSharedKey.every((b, i) => b === helperSharedKey[i])
  ) {
    throw new Error("HashedKeys pairing: owner/helper shared keys do not match");
  }
  console.log(`  shared keys match (${ownerSharedKey.length}B)  ✓\n`);

  // Negative: tampering the binding hash before the scanner starts must
  // surface `PREPAIR_HASH_MISMATCH` once the real keys arrive. This is
  // the security-relevant guarantee of HashedKeys — the scanner refuses
  // keys that don't match the commitment they originally accepted.
  console.log("  -- Negative: tampered binding hash --");

  const owner2 = makeNode("Owner", "https://owner.example.com");
  const helper2 = makeNode("Helper", "https://helper.example.com");

  const contact: ContactMessage =
    await helper2.protocol.createContact(2n, ContactMode.HashedKeys);
  if (!contact.contact_binding_hash) {
    throw new Error("tampered-hash test: contact_binding_hash must be present");
  }
  contact.contact_binding_hash[0] = contact.contact_binding_hash[0]! ^ 0xff;

  await owner2.protocol.start(FlowKind.Pairing, {
    kind: SenderKind.Owner,
    contact,
  });
  const tamperedPrePairRequest = drainOne(owner2, "TamperedHash/Owner");
  // Helper2 still produces a valid PrePairResponse — the tampering
  // happens on the scanner's stored contact, so the error surfaces on
  // the scanner side when validating the real keys against the tampered
  // commitment.
  await processAll(helper2, tamperedPrePairRequest);
  const tamperedPrePairResponse = drainOne(helper2, "TamperedHash/Helper");

  let caught: { code?: string; category?: string; message?: string } | null = null;
  try {
    await owner2.protocol.process(tamperedPrePairResponse);
  } catch (e) {
    caught = e as { code?: string; category?: string; message?: string };
  }
  if (!caught) {
    throw new Error("tampered binding hash must cause process(PrePairResponse) to throw");
  }
  // The message comes from the `PairingError::PrePairHashMismatch`
  // `#[error("...")]` annotation.
  if (!caught.message || !caught.message.includes("contact binding hash mismatch")) {
    throw new Error(
      `tampered binding hash must surface PrePairHashMismatch, got code=${caught.code} message=${caught.message}`,
    );
  }
  console.log(`  process(PrePairResponse) threw "${caught.message}" ✓\n`);

  console.log("✓ HashedKeys pairing flow passed.\n");
}


async function runSharingFlow(): Promise<void> {
  console.log("=== [Protocol] Sharing Flow ===\n");

  const ownerSecretId = 42n;
  const owner = makeNode("Owner", "https://owner.example.com", {
    secretId: ownerSecretId,
  });
  const helperA = makeNode("HelperA", "https://helper-a.example.com");
  const helperB = makeNode("HelperB", "https://helper-b.example.com");
  const channelIdA = 1n;
  const channelIdB = 2n;

  await doPair(helperA, owner, channelIdA, "Owner↔HelperA");
  await doPair(helperB, owner, channelIdB, "Owner↔HelperB");
  console.log();

  const secretData = utf8Encode("super-secret-value");
  owner.secretStore.loadManyCalls.length = 0;
  await owner.protocol.start(FlowKind.ProtectSecret, {
    secrets: [{ id: new Uint8Array([1]), name: "smoke", data: secretData }],
    description: "smoke-test secret",
  });

  const outbound = owner.transport.drain();
  if (outbound.length !== 2) {
    throw new Error(`expected 2 StoreShareRequests, got ${outbound.length}`);
  }
  // The broadcast reads every helper's SharedKey through one
  // SecretStore.loadMany call rather than one load per channel.
  const keyCalls = owner.secretStore.loadManyCalls;
  if (keyCalls.length !== 1 || keyCalls[0].length !== 2) {
    throw new Error(
      `ProtectSecret broadcast must call SecretStore.loadMany once with both helper channels, got ${JSON.stringify(keyCalls)}`,
    );
  }
  console.log(`  [Owner] ProtectSecret → one SecretStore.loadMany([${keyCalls[0].join(", ")}])`);
  console.log(
    `\n  [Owner] start(ProtectSecret) → ${outbound.length} StoreShareRequest(s)`,
  );

  const helpers: Array<[Node, string]> = [
    [helperA, "HelperA"],
    [helperB, "HelperB"],
  ];

  for (let i = 0; i < outbound.length; i++) {
    const request = outbound[i]!.message;
    const [helper, hLabel] = helpers[i]!;

    const helperEvents = await processAll(helper, request);
    const action = requireEvent(helperEvents, "ActionRequired", hLabel);
    await assertStoreShareAction(owner, action, request, hLabel);
    const stored = requireEvent(helperEvents, "ShareStored", hLabel);
    console.log(
      `  [${hLabel}] processAll(StoreShareRequest) → ShareStored(channel_id=${stored.channel_id}, version=${stored.version})`,
    );

    const response = drainOne(helper, hLabel);
    const ownerEvents = await owner.protocol.process(response);
    const confirmed = requireEvent(ownerEvents, "ShareConfirmed", "Owner");
    console.log(
      `  [Owner]  process(StoreShareResponse) → ShareConfirmed(channel_id=${confirmed.channel_id}, version=${confirmed.version})`,
    );
  }

  const tail = owner.transport.drain();
  const finalEvents =
    tail.length > 0 ? await owner.protocol.process(tail[0]!.message) : [];
  // SharingComplete is emitted once the final confirmation is processed; if it
  // already arrived in the loop above, re-running process on a drained tail is
  // a no-op. Accept either ordering.
  const sharing = [...finalEvents].find((e) => e.type === "SharingComplete") as
    | Extract<DeRecEvent, { type: "SharingComplete" }>
    | undefined;
  if (sharing) {
    console.log(
      `  [Owner]  SharingComplete(confirmed=${sharing.confirmed_count}, failed=${sharing.failed_count}, threshold_met=${sharing.threshold_met})`,
    );
  }

  console.log("\n✓ Sharing flow passed.\n");
}


/**
 * A responder whose `parameter_range` does not overlap the requester's
 * refuses the PairRequest: it reports `PairingRefused`, sends exactly one
 * rejecting PairResponse, and the requester's `process` fails with the
 * peer's `status` and `memo` on the thrown error. Mirrors
 * `run_pairing_rejects_incompatible_parameter_range` in the Rust smoke.
 */
async function runPairingRefusalFlow(): Promise<void> {
  console.log("=== [Protocol] Pairing Refusal Flow ===\n");

  // The memo is read by the requester, so its own range comes first.
  const expectedMemo =
    "`shareSize` range [10000000, 500000000] does not overlap the accepted range [1000000000, 5000000000]";

  const owner = makeNode("Owner", "https://owner.example.com", {
    parameterRange: { min_share_size: 1_000_000_000n, max_share_size: 5_000_000_000n },
  });
  const helper = makeNode("Helper", "https://helper.example.com", {
    parameterRange: { min_share_size: 10_000_000n, max_share_size: 500_000_000n },
  });

  const contact = await owner.protocol.createContact(1n, ContactMode.InlineKeys);
  await helper.protocol.start(FlowKind.Pairing, { kind: SenderKind.Helper, contact });
  const pairRequests = helper.transport.drain();
  if (pairRequests.length !== 1) {
    throw new Error(`the requester must send exactly one PairRequest, got ${pairRequests.length}`);
  }

  const ownerEvents = await owner.protocol.process(pairRequests[0]!.message);
  const refused = ownerEvents[0];
  if (ownerEvents.length !== 1 || refused?.type !== "PairingRefused") {
    throw new Error(
      `the responder must report exactly one PairingRefused, got [${ownerEvents.map((e) => e.type).join(", ")}]`,
    );
  }
  if (refused.status !== StatusEnum.IncompatibleParameterRange) {
    throw new Error(`PairingRefused.status must be IncompatibleParameterRange, got ${refused.status}`);
  }
  if (refused.memo !== expectedMemo) {
    throw new Error(`PairingRefused.memo must read from the requester's side, got ${refused.memo}`);
  }
  if (refused.error_code !== "incompatible_parameter_range") {
    throw new Error(`PairingRefused.error_code must be incompatible_parameter_range, got ${refused.error_code}`);
  }
  if (!refused.message) {
    throw new Error("PairingRefused.message must be non-empty");
  }
  console.log(
    "  [Owner]  process(PairRequest) → PairingRefused(IncompatibleParameterRange) with memo, error_code and message  ✓",
  );

  const pairResponses = owner.transport.drain();
  if (pairResponses.length !== 1) {
    throw new Error(`the responder must send exactly one rejecting PairResponse, got ${pairResponses.length}`);
  }

  let peerError: DeRecError | undefined;
  try {
    await helper.protocol.process(pairResponses[0]!.message);
  } catch (e) {
    peerError = e as DeRecError;
  }
  if (!peerError) {
    throw new Error("the requester must fail on a rejecting PairResponse");
  }
  if (peerError.code !== "non_ok_status") {
    throw new Error(`the requester's error must be non_ok_status, got ${peerError.code}`);
  }
  if (peerError.status !== StatusEnum.IncompatibleParameterRange) {
    throw new Error(`error.status must be IncompatibleParameterRange, got ${peerError.status}`);
  }
  if (peerError.memo !== expectedMemo) {
    throw new Error(`error.memo must carry the responder's memo, got ${peerError.memo}`);
  }
  console.log("  [Helper] process(PairResponse:rejected) → non_ok_status with status and memo  ✓");

  console.log("\n✓ Pairing refusal flow passed.\n");
}

/**
 * Weights are sticky: a publish the library starts on its own reads each
 * helper's weight back from its stored record. Helper A is published at
 * weight 2 against threshold 3; pairing helper C then triggers a publish in
 * which A still receives two subshares and C, named in no weights map,
 * receives one.
 */
async function runStickyWeightsFlow(): Promise<void> {
  console.log("=== [Protocol] Sticky Weights Flow ===\n");

  const ownerSecretId = 47n;
  const owner = makeNode("Owner", "https://owner.example.com", {
    secretId: ownerSecretId,
    threshold: 3,
  });
  const helperA = makeNode("HelperA", "https://helper-a.example.com");
  const helperB = makeNode("HelperB", "https://helper-b.example.com");
  const { longTermChannelId: channelA } = await doPair(helperA, owner, 1n, "Owner↔HelperA");
  const { longTermChannelId: channelB } = await doPair(helperB, owner, 2n, "Owner↔HelperB");
  console.log();

  const protectEvents = await owner.protocol.start(FlowKind.ProtectSecret, {
    secrets: [{ id: new Uint8Array([5]), name: "sticky weights", data: utf8Encode("sticky-weights-secret") }],
    description: "weighted round",
    weights: new Map([[BigInt(channelA), 2]]),
  });
  const started = new Map<string, number>();
  for (const ev of protectEvents) {
    if (ev.type === "ProtectSecretStarted") started.set(ev.channel_id, ev.weight);
  }
  if (started.get(channelA) !== 2 || started.get(channelB) !== 1) {
    throw new Error(`the round must send A=2, B=1 subshares, got A=${started.get(channelA)}, B=${started.get(channelB)}`);
  }
  console.log("  [Owner]  start(ProtectSecret, weights={A: 2}) → weight(A)=2, weight(B)=1  ✓");

  const helpersByUri = new Map<string, [Node, string]>([
    ["https://helper-a.example.com", [helperA, "HelperA"]],
    ["https://helper-b.example.com", [helperB, "HelperB"]],
  ]);
  let thresholdMet = false;
  for (const outbound of owner.transport.drain()) {
    const [helper, label] = helpersByUri.get(outbound.endpoint.uri)!;
    await processAll(helper, outbound.message);
    const ownerEvents = await processAll(owner, drainOne(helper, label));
    if (ownerEvents.some((e) => e.type === "SharingComplete" && e.threshold_met)) thresholdMet = true;
  }
  if (!thresholdMet) {
    throw new Error("A (2 subshares) and B (1 subshare) must meet threshold 3");
  }
  console.log("  [Owner]  SharingComplete(threshold_met=true) — 2+1 subshares ≥ 3  ✓");

  // The record is opaque bytes, but `weight` is a small integer, so parsing
  // it to read the weight is safe.
  const storedWeight = async (channelId: string): Promise<number | undefined> => {
    const bytes = await owner.channelStore.load(String(ownerSecretId), channelId, "0");
    return bytes ? JSON.parse(utf8Decode(bytes)).Helper.weight : undefined;
  };
  if ((await storedWeight(channelA)) !== 2) {
    throw new Error(`the stored record for A must carry weight 2, got ${await storedWeight(channelA)}`);
  }
  console.log("  [Owner]  the stored helper record for A carries weight 2  ✓");

  // Completing a pairing makes the library publish on its own, with no
  // weights map: every weight comes from the stored records.
  const helperC = makeNode("HelperC", "https://helper-c.example.com");
  const contact = await helperC.protocol.createContact(3n, ContactMode.InlineKeys);
  await owner.protocol.start(FlowKind.Pairing, { kind: SenderKind.Owner, contact });
  await processAll(helperC, drainOne(owner, "Owner"));
  const pairingEvents = await processAll(owner, drainOne(helperC, "HelperC"));
  const channelC = requireEvent(pairingEvents, "PairingCompleted", "Owner").channel_id;
  const republished = new Map<string, number>();
  for (const ev of pairingEvents) {
    if (ev.type === "ProtectSecretStarted") republished.set(ev.channel_id, ev.weight);
  }
  if (
    republished.size !== 3 ||
    republished.get(channelA) !== 2 ||
    republished.get(channelB) !== 1 ||
    republished.get(channelC) !== 1
  ) {
    throw new Error(
      `the pairing publish must reuse the stored weights (A=2, B=1, C=1), got ${JSON.stringify([...republished])}`,
    );
  }
  console.log("  [Owner]  pairing C → auto-publish with weight(A)=2, weight(B)=1, weight(C)=1  ✓");

  if ((await storedWeight(channelA)) !== 2) {
    throw new Error(`the stored record for A must still carry weight 2, got ${await storedWeight(channelA)}`);
  }
  console.log("  [Owner]  the stored helper record for A still carries weight 2  ✓");

  console.log("\n✓ Sticky weights flow passed.\n");
}

/**
 * The threshold is sticky. Each version's threshold is recorded on the
 * owner's stored shares and reported by `ShareVerified.threshold` after a
 * later round changed it; helpers record none; and the publish the library
 * starts after a pairing splits at the stored threshold, not the builder's.
 */
async function runStickyThresholdFlow(): Promise<void> {
  console.log("=== [Protocol] Sticky Threshold Flow ===\n");

  const secretId = 49n;
  // The builder says 2.
  const owner = makeNode("Owner", "https://owner.example.com", { secretId, threshold: 2 });
  const helperA = makeNode("HelperA", "https://helper-a.example.com", { secretId });
  const helperB = makeNode("HelperB", "https://helper-b.example.com", { secretId });
  const helperC = makeNode("HelperC", "https://helper-c.example.com", { secretId });
  const helperD = makeNode("HelperD", "https://helper-d.example.com", { secretId });
  const { longTermChannelId: channelA } = await doPair(helperA, owner, 71n, "Owner↔HelperA");
  const { longTermChannelId: channelB } = await doPair(helperB, owner, 72n, "Owner↔HelperB");
  const { longTermChannelId: channelC } = await doPair(helperC, owner, 73n, "Owner↔HelperC");
  console.log();
  const channels = [channelA, channelB, channelC];

  const helpersByUri = new Map<string, [Node, string]>([
    ["https://helper-a.example.com", [helperA, "HelperA"]],
    ["https://helper-b.example.com", [helperB, "HelperB"]],
    ["https://helper-c.example.com", [helperC, "HelperC"]],
    ["https://helper-d.example.com", [helperD, "HelperD"]],
  ]);
  const roundTrip = async (): Promise<DeRecEvent[]> => {
    const ownerEvents: DeRecEvent[] = [];
    for (const { endpoint, message } of owner.transport.drain()) {
      const [helper, label] = helpersByUri.get(endpoint.uri)!;
      await processAll(helper, message);
      ownerEvents.push(...(await owner.protocol.process(drainOne(helper, label))));
    }
    return ownerEvents;
  };
  const protect = async (threshold?: number): Promise<number> => {
    const events = await owner.protocol.start(FlowKind.ProtectSecret, {
      secrets: [{ id: new Uint8Array([7]), name: "sticky", data: new Uint8Array([4, 5, 6]) }],
      ...(threshold === undefined ? {} : { threshold }),
    });
    const version = requireEvent(events, "ProtectSecretStarted", "Owner").version;
    await roundTrip();
    return version;
  };
  const stored = async (node: Node, channelId: string, version: number): Promise<number | null | undefined> => {
    const shares = await node.shareStore.load(secretId.toString(), channelId, [version]);
    if (shares.length !== 1) {
      throw new Error(`expected one stored share for channel ${channelId} at v${version}, got ${shares.length}`);
    }
    return shares[0]!.threshold;
  };

  // v1 at the builder's 2, v2 at an explicit 3.
  const v1 = await protect();
  const v2 = await protect(3);
  for (const channelId of channels) {
    const t1 = await stored(owner, channelId, v1);
    const t2 = await stored(owner, channelId, v2);
    if (t1 !== 2 || t2 !== 3) {
      throw new Error(`the owner's shares must record v1 t=2, v2 t=3, got ${t1}, ${t2}`);
    }
  }
  console.log("  [Owner]  stored shares record threshold v1=2, v2=3  ✓");
  for (const [helper, channelId] of [[helperA, channelA], [helperB, channelB], [helperC, channelC]] as const) {
    const held = await stored(helper, channelId, v1);
    if (held != null) {
      throw new Error(`a helper's stored share must carry no threshold, got ${held}`);
    }
  }
  console.log("  [Helpers] stored shares carry no threshold  ✓");
  const snapshot = await owner.userSecretStore.loadLatest(secretId.toString());
  if (snapshot?.threshold !== 3) {
    throw new Error(`the snapshot must store t=3, got ${snapshot?.threshold}`);
  }
  console.log("  [Owner]  UserSecrets.threshold is 3  ✓");

  await owner.protocol.start(FlowKind.VerifyShares, { secretId, version: v1 });
  const verified: Array<number | undefined> = [];
  for (const ev of await roundTrip()) {
    if (ev.type === "ShareVerified" && ev.version === v1) verified.push(ev.threshold);
  }
  if (verified.length !== 3 || verified.some((t) => t !== 2)) {
    throw new Error(`ShareVerified for v1 must report t=2, got ${JSON.stringify(verified)}`);
  }
  console.log("  [Owner]  ShareVerified.threshold reports v1's t=2 after v2 changed it  ✓");

  // Pairing HelperD makes the library publish on its own.
  const { longTermChannelId: channelD } = await doPair(helperD, owner, 74n, "Owner↔HelperD");
  await roundTrip();
  for (const channelId of [...channels, channelD]) {
    const t = await stored(owner, channelId, v2 + 1);
    if (t !== 3) {
      throw new Error(`the library-started publish must split at the stored t=3, got ${t}`);
    }
  }
  console.log("  [Owner]  the pairing publish splits at the stored t=3, not the builder's 2  ✓");

  console.log("\n✓ Sticky threshold flow passed.\n");
}

/**
 * The owner records each helper's subshare count on its stored shares;
 * helpers record none. `ShareVerified.subshares` reports the count of the
 * verified version, and a later re-weight leaves an older version's counts
 * intact.
 */
async function runShareSubsharesFlow(): Promise<void> {
  console.log("=== [Protocol] Share Subshares Flow ===\n");

  const secretId = 48n;
  const owner = makeNode("Owner", "https://owner.example.com", { secretId, threshold: 3 });
  const helperA = makeNode("HelperA", "https://helper-a.example.com", { secretId });
  const helperB = makeNode("HelperB", "https://helper-b.example.com", { secretId });
  const { longTermChannelId: channelA } = await doPair(helperA, owner, 61n, "Owner↔HelperA");
  const { longTermChannelId: channelB } = await doPair(helperB, owner, 62n, "Owner↔HelperB");
  console.log();

  const helpersByUri = new Map<string, [Node, string]>([
    ["https://helper-a.example.com", [helperA, "HelperA"]],
    ["https://helper-b.example.com", [helperB, "HelperB"]],
  ]);
  const roundTrip = async (): Promise<DeRecEvent[]> => {
    const ownerEvents: DeRecEvent[] = [];
    for (const { endpoint, message } of owner.transport.drain()) {
      const [helper, label] = helpersByUri.get(endpoint.uri)!;
      await processAll(helper, message);
      ownerEvents.push(...(await owner.protocol.process(drainOne(helper, label))));
    }
    return ownerEvents;
  };
  const protect = async (weights: Map<bigint, number>): Promise<number> => {
    const events = await owner.protocol.start(FlowKind.ProtectSecret, {
      secrets: [{ id: new Uint8Array([6]), name: "subshares", data: new Uint8Array([1, 2, 3]) }],
      description: "weighted round",
      weights,
    });
    const version = requireEvent(events, "ProtectSecretStarted", "Owner").version;
    await roundTrip();
    return version;
  };
  const stored = async (node: Node, channelId: string, version: number): Promise<number | null | undefined> => {
    const shares = await node.shareStore.load(secretId.toString(), channelId, [version]);
    if (shares.length !== 1) {
      throw new Error(`expected one stored share for channel ${channelId} at v${version}, got ${shares.length}`);
    }
    return shares[0]!.subshares;
  };
  const verified = async (version: number): Promise<string> => {
    await owner.protocol.start(FlowKind.VerifyShares, { secretId, version });
    const counts = new Map<string, number | undefined>();
    for (const ev of await roundTrip()) {
      if (ev.type === "ShareVerified" && ev.version === version) counts.set(ev.channel_id, ev.subshares);
    }
    return `A=${counts.get(channelA)}, B=${counts.get(channelB)}`;
  };

  const v1 = await protect(new Map([[BigInt(channelA), 2]]));
  const ownerA = await stored(owner, channelA, v1);
  const ownerB = await stored(owner, channelB, v1);
  if (ownerA !== 2 || ownerB !== 1) {
    throw new Error(`the owner's v1 shares must record A=2, B=1, got A=${ownerA}, B=${ownerB}`);
  }
  console.log("  [Owner]  stored shares record subshares A=2, B=1  ✓");
  const heldA = await stored(helperA, channelA, v1);
  const heldB = await stored(helperB, channelB, v1);
  if (heldA != null || heldB != null) {
    throw new Error(`a helper's stored share must carry no subshare count, got A=${heldA}, B=${heldB}`);
  }
  console.log("  [Helpers] stored shares carry no subshares  ✓");

  const first = await verified(v1);
  if (first !== "A=2, B=1") {
    throw new Error(`ShareVerified must report A=2, B=1 for v1, got ${first}`);
  }
  console.log("  [Owner]  ShareVerified.subshares reports A=2, B=1  ✓");

  const v2 = await protect(new Map([[BigInt(channelB), 2]]));
  if ((await stored(owner, channelA, v2)) !== 1 || (await stored(owner, channelB, v2)) !== 2) {
    throw new Error("the owner's v2 shares must record the re-weighted counts A=1, B=2");
  }
  const again = await verified(v1);
  if (again !== "A=2, B=1") {
    throw new Error(`after re-weighting, verifying v1 must still report A=2, B=1, got ${again}`);
  }
  console.log("  [Owner]  re-weighted v2 (A=1, B=2); verifying v1 still reports A=2, B=1  ✓");

  console.log("\n✓ Share subshares flow passed.\n");
}

/**
 * `withMaxSubshares` caps a sharing round's total subshares. A cap below the
 * threshold makes `build()` throw `invalid_input`; a round whose weights
 * total more than the cap fails `start(ProtectSecret)` with
 * `too_many_subshares` before anything is sent.
 */
async function runMaxSubsharesFlow(): Promise<void> {
  console.log("=== [Protocol] Max Subshares Cap ===\n");

  const ownerSecretId = 45n;
  let buildCode: string | undefined;
  try {
    makeNode("Owner", "https://owner.example.com", {
      secretId: ownerSecretId,
      threshold: 3,
      maxSubshares: 2n,
    });
  } catch (e) {
    buildCode = (e as { code?: string }).code;
  }
  if (buildCode !== "invalid_input") {
    throw new Error(`a cap below the threshold must fail build() with invalid_input, got ${buildCode ?? "no error"}`);
  }
  console.log("  [Owner]  build() refuses a cap below the threshold (invalid_input)  ✓");

  const owner = makeNode("Owner", "https://owner.example.com", {
    secretId: ownerSecretId,
    threshold: 3,
    maxSubshares: 3n,
  });
  const helperA = makeNode("HelperA", "https://helper-a.example.com");
  const helperB = makeNode("HelperB", "https://helper-b.example.com");
  const { longTermChannelId: channelA } = await doPair(helperA, owner, 1n, "Owner↔HelperA");
  const { longTermChannelId: channelB } = await doPair(helperB, owner, 2n, "Owner↔HelperB");
  owner.transport.drain();

  let startCode: string | undefined;
  try {
    await owner.protocol.start(FlowKind.ProtectSecret, {
      secrets: [{ id: new Uint8Array([5]), name: "capped secret", data: new Uint8Array([1, 2, 3]) }],
      description: "over the cap",
      weights: new Map([
        [BigInt(channelA), 2],
        [BigInt(channelB), 2],
      ]),
    });
  } catch (e) {
    startCode = (e as { code?: string }).code;
  }
  if (startCode !== "too_many_subshares") {
    throw new Error(`4 subshares over a cap of 3 must fail with too_many_subshares, got ${startCode ?? "no error"}`);
  }
  if (owner.transport.drain().length !== 0) {
    throw new Error("a round over the cap must send nothing");
  }
  console.log("  [Owner]  start(ProtectSecret) over the cap fails with too_many_subshares and sends nothing  ✓");
  console.log("\n✓ Max subshares cap passed.\n");
}

/**
 * A weighted round: four helpers, threshold 3, helper-0 at weight 2.
 *
 * Helper-0 receives two subshares and every other helper one, as the
 * dispatch events report. Once every helper confirms, the round meets the
 * threshold, and the secret is then recovered from helper-0 and helper-1
 * alone: two helpers holding three subshares. The protocol library has no
 * protobuf decoder in TypeScript, so the weight is proven structurally —
 * through what it lets `RecoverSecret` reconstruct — rather than by
 * decoding the committed share bytes.
 */
async function runWeightedHelpersFlow(): Promise<void> {
  console.log("=== [Protocol] Weighted Helpers Flow ===\n");

  const ownerSecretId = 44n;
  const owner = makeNode("Owner", "https://owner.example.com", {
    secretId: ownerSecretId,
    threshold: 3,
  });
  const helper0 = makeNode("Helper0", "https://helper-0.example.com");
  const helper1 = makeNode("Helper1", "https://helper-1.example.com");
  const helper2 = makeNode("Helper2", "https://helper-2.example.com");
  const helper3 = makeNode("Helper3", "https://helper-3.example.com");

  const { longTermChannelId: channel0 } = await doPair(helper0, owner, 1n, "Owner↔Helper0");
  const { longTermChannelId: channel1 } = await doPair(helper1, owner, 2n, "Owner↔Helper1");
  const { longTermChannelId: channel2 } = await doPair(helper2, owner, 3n, "Owner↔Helper2");
  const { longTermChannelId: channel3 } = await doPair(helper3, owner, 4n, "Owner↔Helper3");
  console.log();

  // Weights are keyed by the long-term channel id pairing rekeys onto, not
  // the transient pairing id passed to `doPair`.
  const secretData = utf8Encode("two helpers, three subshares");
  const protectEvents = await owner.protocol.start(FlowKind.ProtectSecret, {
    secrets: [{ id: new Uint8Array([3]), name: "weighted secret", data: secretData }],
    description: "weighted round",
    weights: new Map([[BigInt(channel0), 2]]),
  });

  const weightByChannel = new Map<string, number>();
  let version: number | undefined;
  for (const ev of protectEvents) {
    if (ev.type === "ProtectSecretStarted") {
      weightByChannel.set(ev.channel_id, ev.weight);
      version = ev.version;
    }
  }
  const expectedWeight: Record<string, number> = {
    [channel0]: 2,
    [channel1]: 1,
    [channel2]: 1,
    [channel3]: 1,
  };
  for (const [channelId, weight] of Object.entries(expectedWeight)) {
    if (weightByChannel.get(channelId) !== weight) {
      throw new Error(
        `ProtectSecretStarted: expected weight ${weight} for channel ${channelId}, got ${weightByChannel.get(channelId)}`,
      );
    }
  }
  if (version === undefined) {
    throw new Error("the round must report the version it published");
  }
  console.log(
    `  [Owner]  start(ProtectSecret, weights={helper0: 2}) → weight(helper0)=2, weight(others)=1  ✓`,
  );

  const helpersByChannel: Array<[string, Node, string]> = [
    [channel0, helper0, "Helper0"],
    [channel1, helper1, "Helper1"],
    [channel2, helper2, "Helper2"],
    [channel3, helper3, "Helper3"],
  ];
  let sharingComplete: Extract<DeRecEvent, { type: "SharingComplete" }> | undefined;
  for (const outbound of owner.transport.drain()) {
    const helperIndex = Number(outbound.endpoint.uri.match(/helper-(\d)/)?.[1]);
    const [, helper, label] = helpersByChannel[helperIndex]!;
    const helperEvents = await processAll(helper, outbound.message);
    requireEvent(helperEvents, "ShareStored", label);
    const response = drainOne(helper, label);
    const ownerEvents = await owner.protocol.process(response);
    const complete = ownerEvents.find((e) => e.type === "SharingComplete") as
      | Extract<DeRecEvent, { type: "SharingComplete" }>
      | undefined;
    if (complete) sharingComplete = complete;
  }
  if (!sharingComplete || !sharingComplete.threshold_met) {
    throw new Error("five confirmed subshares across 4 helpers must meet threshold 3");
  }
  console.log(`  [Owner]  SharingComplete(threshold_met=true) — 2+1+1+1 subshares ≥ 3  ✓`);

  // Drop helper-2 and helper-3 from the Owner's roster so RecoverSecret
  // fans out only to helper-0 (2 subshares) and helper-1 (1 subshare): three
  // subshares total, exactly the threshold.
  const ownerSid = String(owner.protocol.secretId());
  await owner.channelStore.remove(ownerSid, channel2, "0");
  await owner.channelStore.remove(ownerSid, channel3, "0");

  await owner.protocol.start(FlowKind.RecoverSecret, {
    secretId: ownerSecretId,
    version,
  });
  const recoverRequests = owner.transport.drain();
  if (recoverRequests.length !== 2) {
    throw new Error(`expected 2 GetShareRequests (helper0 + helper1 only), got ${recoverRequests.length}`);
  }

  let recovered: Extract<DeRecEvent, { type: "SecretRecovered" }>["secret"] | undefined;
  for (const outbound of recoverRequests) {
    const isHelper0 = outbound.endpoint.uri.includes("helper-0");
    const helper = isHelper0 ? helper0 : helper1;
    const label = isHelper0 ? "Helper0" : "Helper1";
    await processAll(helper, outbound.message);
    const response = drainOne(helper, label);
    const ownerEvents = await owner.protocol.process(response);
    const recoveredEvent = ownerEvents.find((e) => e.type === "SecretRecovered") as
      | Extract<DeRecEvent, { type: "SecretRecovered" }>
      | undefined;
    if (recoveredEvent) recovered = recoveredEvent.secret;
  }
  if (!recovered) {
    throw new Error("helper-0 (2 subshares) and helper-1 (1 subshare) must recover the secret");
  }
  const recoveredSecret = recovered.secrets.find((s) => s.id.length === 1 && s.id[0] === 3);
  if (!recoveredSecret || !byteArraysEqual(recoveredSecret.data, secretData)) {
    throw new Error("recovered secret must carry the protected bytes");
  }
  console.log(
    `  [Owner]  RecoverSecret from helper0+helper1 alone (2+1=3 subshares) → recovered "${recoveredSecret.name}"  ✓`,
  );

  console.log("\n✓ Weighted helpers flow passed.\n");
}


// VSS sharing requires threshold ≥ 2, so this scenario pairs the Owner with
// TWO helpers and reconstructs the secret from both shares. Mirrors the Rust
// `smoke-tests/rust/src/protocol.rs::run_discovery_and_recovery_flow`.
async function runDiscoveryAndRecoveryFlow(): Promise<void> {
  console.log("=== [Protocol] Discovery & Recovery Flow ===\n");

  const ownerSecretId = 123n;
  const owner = makeNode("Owner", "https://owner.example.com", {
    secretId: ownerSecretId,
  });
  // Helpers serving this owner are bound to the same secret id — every
  // store on the helper side partitions by that id, matching the
  // one-protocol-per-secret trait surface.
  const helperA = makeNode("HelperA", "https://helper-a.example.com", {
    secretId: ownerSecretId,
  });
  const helperB = makeNode("HelperB", "https://helper-b.example.com", {
    secretId: ownerSecretId,
  });
  const channelA = 1n;
  const channelB = 2n;
  const recoveryChannelA = 100n;
  const recoveryChannelB = 101n;

  const description = "wallet seed phrase";
  const secretBytes = utf8Encode("correct horse battery staple");


  console.log("  -- Setup: initial pairing & sharing --\n");

  const { longTermChannelId: originalRekeyedA } = await doPair(helperA, owner, channelA, "InitialA");
  const { longTermChannelId: originalRekeyedB } = await doPair(helperB, owner, channelB, "InitialB");
  console.log();

  await owner.protocol.start(FlowKind.ProtectSecret, {
    secrets: [{ id: new Uint8Array([1]), name: "wallet", data: secretBytes }],
    description,
  });
  const outbound = owner.transport.drain();
  if (outbound.length !== 2) {
    throw new Error(`expected 2 StoreShareRequests, got ${outbound.length}`);
  }
  console.log(`  [Owner]  start(ProtectSecret) → ${outbound.length} StoreShareRequest(s)`);

  const helpers: Array<[Node, string]> = [
    [helperA, "HelperA"],
    [helperB, "HelperB"],
  ];
  for (let i = 0; i < outbound.length; i++) {
    const request = outbound[i]!.message;
    const [helper, hLabel] = helpers[i]!;
    const helperEvents = await processAll(helper, request);
    requireEvent(helperEvents, "ShareStored", hLabel);
    const response = drainOne(helper, hLabel);
    const ownerEvents = await owner.protocol.process(response);
    requireEvent(ownerEvents, "ShareConfirmed", "Owner");
  }
  console.log("  Secret distributed and confirmed by both helpers.\n");

  // The Owner has lost local state, so it re-pairs with each helper on a
  // brand-new channel. The Owner is the pairing initiator. Each helper LINKS
  // its original channel to its new recovery channel so the linked-set lookup
  // resolves the original share at recovery time.
  //
  // Simulate state loss explicitly so the pair-completion auto-publish hook
  // has nothing to replay against the new channels.
  await owner.userSecretStore.remove(ownerSecretId.toString());

  console.log("  -- Recovery: re-pair on fresh channels --\n");

  // Post-pair channel_id rekey rotates the transient contact
  // channel_id to a fresh long-term id. Capture the rotated id from
  // each side's PairingCompleted so Discovery targets and helper-side
  // link graph both use the id that actually resolves in the stores.
  const rekeyedByLabel: Record<"HelperA" | "HelperB", string> = { HelperA: "", HelperB: "" };
  for (const [helper, fresh, label] of [
    [helperA, recoveryChannelA, "HelperA"] as const,
    [helperB, recoveryChannelB, "HelperB"] as const,
  ]) {
    const contact: ContactMessage = await helper.protocol.createContact(fresh, ContactMode.InlineKeys);
    console.log(`  [${label}] createContact (recovery) channel_id=${contact.channel_id}`);

    await owner.protocol.start(FlowKind.Pairing, {
      kind: SenderKind.Owner,
      contact,
    });
    const recReq = drainOne(owner, "Owner");
    const helperPairEvents = await processAll(helper, recReq);
    const helperPairing = requireEvent(helperPairEvents, "PairingCompleted", label);
    const recResp = drainOne(helper, label);
    const ownerPairEvents = await processAll(owner, recResp);
    const ownerPairing = requireEvent(ownerPairEvents, "PairingCompleted", "Owner");
    if (ownerPairing.kind !== SenderKind.Owner) {
      throw new Error(`expected kind=Owner, got ${kindName(ownerPairing.kind)}`);
    }
    // Both sides rotated to the same long-term id.
    if (helperPairing.channel_id !== ownerPairing.channel_id) {
      throw new Error(
        `${label}: helper (${helperPairing.channel_id}) and owner (${ownerPairing.channel_id}) rotated to different long-term ids`,
      );
    }
    const rekeyed = helperPairing.channel_id;
    rekeyedByLabel[label] = rekeyed;

    // Link the original (rekeyed) channel to the rotated recovery id so
    // helper-side linked_channels() reaches the original share rows
    // when Discovery/Recovery arrives on the recovery channel.
    const origRekeyed = label === "HelperA" ? originalRekeyedA : originalRekeyedB;
    await helper.channelStore.linkChannel(
      String(helper.protocol.secretId()),
      origRekeyed,
      rekeyed,
    );
    console.log(`  [${label}] re-paired: contact=${fresh} → rekeyed=${rekeyed}`);
  }

  // Simulate Owner-side state loss: drop the original channels so recovery
  // only fans out to the recovery channels. Without this, the Owner would
  // receive duplicate shares (one per original + one per linked recovery
  // channel) and Lagrange interpolation would collide on x-coordinates.
  // The originals are keyed by their rekeyed long-term ids, not the
  // transient contact ids they were minted from.
  const ownerSid = String(owner.protocol.secretId());
  await owner.channelStore.remove(ownerSid, originalRekeyedA, "0");
  await owner.channelStore.remove(ownerSid, originalRekeyedB, "0");
  console.log(`\n  [Owner]  removed original channels ${originalRekeyedA}, ${originalRekeyedB} to simulate state loss\n`);


  console.log("  -- Discovery: Owner asks each helper what it holds --\n");

  await owner.protocol.start(FlowKind.Discovery, {
    target: [BigInt(rekeyedByLabel.HelperA), BigInt(rekeyedByLabel.HelperB)],
  });

  // Drain all owner outbound and route each request to the matching helper.
  const discRequests = owner.transport.drain();
  if (discRequests.length !== 2) {
    throw new Error(`expected 2 DiscoveryRequests, got ${discRequests.length}`);
  }
  for (const env of discRequests) {
    const cidStr = env.endpoint.uri;
    const helper = cidStr.includes("helper-a") ? helperA : helperB;
    const label = cidStr.includes("helper-a") ? "HelperA" : "HelperB";
    await processAll(helper, env.message);
    const resp = drainOne(helper, label);
    await owner.protocol.process(resp);
  }

  // Owner should have seen SecretsDiscovered for the secret on at least one
  // recovery channel.
  // (Events accumulated across the loop above are not captured here; we
  // assert recovery success instead, which implies discovery succeeded.)


  console.log("  -- Recovery: collect shares and reconstruct --\n");

  await owner.protocol.start(FlowKind.RecoverSecret, {
    secretId: ownerSecretId,
    version: 1,
  });

  const recRequests = owner.transport.drain();
  if (recRequests.length !== 2) {
    throw new Error(`expected 2 GetShareRequests, got ${recRequests.length}`);
  }

  let recovered: Extract<DeRecEvent, { type: "SecretRecovered" }>["secret"] | null = null;
  for (const env of recRequests) {
    const isA = env.endpoint.uri.includes("helper-a");
    const helper = isA ? helperA : helperB;
    const label = isA ? "HelperA" : "HelperB";
    await processAll(helper, env.message);
    const resp = drainOne(helper, label);
    const events = await owner.protocol.process(resp);
    for (const ev of events) {
      if (ev.type === "SecretRecovered") {
        recovered = ev.secret;
      }
    }
  }

  if (!recovered) {
    throw new Error("Recovery failed: no SecretRecovered event");
  }

  // The library now decodes the protect-side wrapping for us —
  // `recovered.secrets` is the typed list of `UserSecret` the owner
  // originally protected. Assert id + name + data all round-trip.
  const recoveredUserSecret = recovered.secrets.find(
    (s) => s.id.length === 1 && s.id[0] === 1,
  );
  if (!recoveredUserSecret) {
    throw new Error(
      "recovered Secret must include the UserSecret with the original id [0x01]",
    );
  }
  if (!byteArraysEqual(recoveredUserSecret.data, secretBytes)) {
    throw new Error(
      `recovered UserSecret.data must round-trip; got ${recoveredUserSecret.data.length}B`,
    );
  }
  if (recoveredUserSecret.name !== "wallet") {
    throw new Error(
      `recovered UserSecret.name must round-trip; got "${recoveredUserSecret.name}"`,
    );
  }
  console.log(
    `  [Owner]  SecretRecovered → UserSecret "${recoveredUserSecret.name}" (${recoveredUserSecret.data.length}B) round-trips ✓`,
  );

  console.log("\n  -- Restore: rebuild a fresh peer from the recovered Secret --\n");

  // Its builder says 5; restore must put back the threshold the secret was
  // split with.
  const restored = makeNode("RestoredOwner", "https://restored.example.com", {
    secretId: ownerSecretId,
    threshold: 5,
  });
  if (recovered.threshold !== THRESHOLD) {
    throw new Error(`the recovered roster must carry t=${THRESHOLD}, got ${recovered.threshold}`);
  }
  await restored.protocol.restore(recovered, 1);

  const restoredSnapshot = await restored.userSecretStore.loadLatest(
    ownerSecretId.toString(),
  );
  if (!restoredSnapshot) {
    throw new Error("restore did not commit a UserSecrets snapshot");
  }
  if (restoredSnapshot.version !== 1) {
    throw new Error(
      `restored snapshot version mismatch: ${restoredSnapshot.version} ≠ 1`,
    );
  }
  if (restoredSnapshot.threshold !== THRESHOLD) {
    throw new Error(
      `restore must keep t=${THRESHOLD}, not the builder's 5, got ${restoredSnapshot.threshold}`,
    );
  }
  console.log(`  [Restored] restore keeps t=${THRESHOLD} over the builder's 5 ✓`);
  const restoredUserSecret = restoredSnapshot.secrets.find(
    (s) => s.id.length === 1 && s.id[0] === 1,
  );
  if (!restoredUserSecret || !byteArraysEqual(restoredUserSecret.data, secretBytes)) {
    throw new Error("restored snapshot must carry the protected UserSecret");
  }
  for (const helper of recovered.helpers) {
    const channel = await restored.channelStore.load(
      ownerSecretId.toString(),
      helper.channel_id,
      "0",
    );
    if (!channel) {
      throw new Error(
        `restore did not write helper channel ${helper.channel_id}`,
      );
    }
  }
  console.log(
    `  [Restored] restore(recovered, 1) → snapshot v1 (${restoredSnapshot.secrets.length} secret) + ${recovered.helpers.length} helper channel(s) ✓`,
  );

  // A second restore over the channels the first one wrote, with no snapshot
  // to trip `already_restored`, must name exactly those channels.
  const conflicting = makeNode("ConflictingOwner", "https://conflicting.example.com", {
    secretId: ownerSecretId,
    channelStore: restored.channelStore,
  });
  let conflict: DeRecError | undefined;
  try {
    await conflicting.protocol.restore(recovered, 1);
  } catch (e) {
    conflict = e as DeRecError;
  }
  if (conflict?.code !== "restore_conflict") {
    throw new Error(
      `restore over existing channels must reject with restore_conflict; got ${JSON.stringify(conflict)}`,
    );
  }
  const expectedConflicts = recovered.helpers.map((h) => h.channel_id).sort();
  const reportedConflicts = [...(conflict.channel_ids ?? [])].sort();
  if (JSON.stringify(reportedConflicts) !== JSON.stringify(expectedConflicts)) {
    throw new Error(
      `restore_conflict channel_ids mismatch: ${JSON.stringify(reportedConflicts)} ≠ ${JSON.stringify(expectedConflicts)}`,
    );
  }
  console.log(
    `  [Conflicting] restore(recovered, 1) → restore_conflict, channel_ids=${JSON.stringify(reportedConflicts)} ✓`,
  );

  console.log("\n✓ Discovery & Recovery flow passed.\n");
}

// Verifies that an Owner-initiated unpair (Required-ack mode, the default)
// produces a successful round-trip:
//   1. Owner → Helper: UnpairRequest
//   2. Helper processes → ActionRequired(Unpair) → accept() → Unpaired event
//      + UnpairResponse(Ok) outbound
//   3. Owner processes the response → Unpaired event + local state dropped
async function runUnpairingFlow(): Promise<void> {
  console.log("=== [Protocol] Unpairing Flow ===\n");

  const owner = makeNode("Owner", "https://owner.example.com");
  const helper = makeNode("Helper", "https://helper.example.com");
  const channelId = 7n;

  const { longTermChannelId } = await doPair(helper, owner, channelId, "Unpair");
  console.log();

  await owner.protocol.start(FlowKind.Unpair, {
    channel_id: longTermChannelId,
    memo: "decommissioning",
  });
  const unpairRequest = drainOne(owner, "Owner");
  console.log(
    `  [Owner]  start(Unpair) → UnpairRequest ${unpairRequest.length}B`,
  );

  const helperEvents = await processAll(helper, unpairRequest);
  const unpairAction = requireEvent(helperEvents, "ActionRequired", "Helper");
  if (unpairAction.unpair_memo !== "decommissioning") {
    throw new Error(
      `ActionRequired(Unpair).unpair_memo must carry the announced memo; got ${unpairAction.unpair_memo}`,
    );
  }
  const helperUnpaired = requireEvent(helperEvents, "Unpaired", "Helper");
  if (helperUnpaired.channel_id !== longTermChannelId) {
    throw new Error(
      `Helper Unpaired channel_id mismatch: ${helperUnpaired.channel_id} ≠ ${longTermChannelId}`,
    );
  }
  const unpairResponse = drainOne(helper, "Helper");
  console.log(
    `  [Helper] processAll(UnpairRequest) → Unpaired + UnpairResponse ${unpairResponse.length}B`,
  );

  const ownerEvents = await processAll(owner, unpairResponse);
  const ownerUnpaired = requireEvent(ownerEvents, "Unpaired", "Owner");
  if (ownerUnpaired.channel_id !== longTermChannelId) {
    throw new Error(
      `Owner Unpaired channel_id mismatch: ${ownerUnpaired.channel_id} ≠ ${longTermChannelId}`,
    );
  }
  console.log(`  [Owner]  processAll(UnpairResponse) → Unpaired`);

  console.log("\n✓ Unpairing flow passed.\n");
}


/**
 * Asserts the `autoReplyTo` constructor flag: with it `true`, every outbound
 * channel-mode request must carry `request.replyToTransports` led by its own
 * transport on the inner request body. Covers half (1) of the replyTo
 * contract; half (2) (responder honours an inbound `replyToTransports`) is
 * exercised by the Rust binding smoke test against the orchestrator handler
 * logic.
 */
async function runReplyToFlow(): Promise<void> {
  console.log("=== [Protocol] replyTo Flow ===\n");

  const channelId = 9n;
  const ownerUri = "https://owner-reply.example.com";
  const helperUri = "https://helper-reply.example.com";

  const helper = makeNode("Helper", helperUri);
  const owner = makeNode("Owner", ownerUri, { autoReplyTo: true });

  const { longTermChannelId } = await doPair(helper, owner, channelId, "ReplyTo");

  // Trigger an outbound Discovery request; it will be queued on the
  // owner's transport awaiting delivery.
  await owner.protocol.start(FlowKind.Discovery, { target: BigInt(longTermChannelId) });
  const outbound = owner.transport.drain();
  if (outbound.length !== 1) {
    throw new Error(
      `expected exactly 1 outbound Discovery request, got ${outbound.length}`,
    );
  }
  const outboundMsg = outbound[0]!;
  if (outboundMsg.endpoint.uri !== helperUri) {
    throw new Error(
      `outbound destination must still be the channel's stored helper endpoint, got ${outboundMsg.endpoint.uri}`,
    );
  }

  // Decrypt the request body via the primitive `extract` and verify
  // `request.reply_to.uri === ownerUri`. The shared key is sitting in the
  // owner's secret store under kind=0 (SharedKey).
  const sharedKey = await owner.secretStore.load(
    String(owner.protocol.secretId()),
    longTermChannelId,
    0,
  );
  if (!sharedKey) {
    throw new Error("owner shared_key must be present after pairing");
  }
  const { request: decoded } = primitives.discovery.request.extract(
    outboundMsg.message,
    sharedKey,
  );
  // reply_to is a list now: auto_reply_to advertises every endpoint this
  // device serves, leading with its own transport.
  if (!decoded.reply_to?.length || decoded.reply_to[0]!.uri !== ownerUri) {
    throw new Error(
      `auto_reply_to must stamp replyTo leading with ownerUri (${ownerUri}) on the inner request body, got ${JSON.stringify(decoded.reply_to)}`,
    );
  }

  // Sanity: a node WITHOUT autoReplyTo must emit `reply_to === undefined`.
  const helper2 = makeNode("Helper2", helperUri);
  const ownerDefault = makeNode("OwnerDefault", ownerUri); // no autoReplyTo
  const { longTermChannelId: defaultLongTermChannelId } =
    await doPair(helper2, ownerDefault, channelId, "ReplyTo/Default");
  await ownerDefault.protocol.start(FlowKind.Discovery, { target: BigInt(defaultLongTermChannelId) });
  const defaultOutbound = ownerDefault.transport.drain();
  const defaultMsg = defaultOutbound[0]!;
  const defaultSharedKey = await ownerDefault.secretStore.load(
    String(ownerDefault.protocol.secretId()),
    defaultLongTermChannelId,
    0,
  );
  if (!defaultSharedKey) throw new Error("default owner shared_key missing");
  const { request: defaultDecoded } = primitives.discovery.request.extract(
    defaultMsg.message,
    defaultSharedKey,
  );
  if (defaultDecoded.reply_to?.length) {
    throw new Error(
      `without auto_reply_to, request.reply_to must be empty; got ${JSON.stringify(defaultDecoded.reply_to)}`,
    );
  }

  console.log("  ✓ auto_reply_to stamps replyTo on outbound requests");
  console.log("  ✓ default (no auto_reply_to) leaves replyTo unset");
  console.log("\n✓ replyTo flow passed.\n");
}

/**
 * Owner↔Destination replica pair, followed by a full ProtectSecret
 * fan-out that includes the Destination as one of the targets. Mirrors
 * `smoke-tests/rust/src/protocol.rs::run_protect_secret_with_replica_targets_flow`
 * — pair, cross-confirm fingerprints, distribute, and assert the typed
 * `ReplicaSecretReceived` event carries the decoded `Secret`
 * (secret.secrets / .helpers / .replicas / .owner_replica_id) plus the
 * helper share map.
 */
async function runReplicaPairingAndSecretSyncFlow(): Promise<void> {
  console.log("=== [Protocol] Replica pairing + secret sync ===\n");

  const ownerReplicaId = 0xAAAA_AAAA_AAAA_AAAAn;
  const destReplicaId = 0xBBBB_BBBB_BBBB_BBBBn;
  const ownerUri = "https://owner.example.com";
  const helperAUri = "https://helper-a.example.com";
  const helperBUri = "https://helper-b.example.com";
  const destUri = "https://replica-destination.example.com";

  const secretId = 0xC0FFEEn;
  const owner = makeNode("Owner", ownerUri, {
    replicaId: ownerReplicaId,
    secretId,
  });
  const helperA = makeNode("HelperA", helperAUri);
  const helperB = makeNode("HelperB", helperBUri);
  const destination = makeNode("Destination", destUri, { replicaId: destReplicaId });

  const helperAChannel = 1n;
  const helperBChannel = 2n;
  const destChannel = 3n;

  // 1. Classic Owner↔Helper pairs (share targets).
  const { longTermChannelId: rekeyedHelperA } =
    await doPair(helperA, owner, helperAChannel, "Owner↔HelperA");
  const { longTermChannelId: rekeyedHelperB } =
    await doPair(helperB, owner, helperBChannel, "Owner↔HelperB");

  // 2. Owner creates contact, Destination scans as ReplicaDestination.
  const replicaContact: ContactMessage =
    await owner.protocol.createContact(destChannel, ContactMode.InlineKeys);
  await destination.protocol.start(FlowKind.Pairing, {
    kind: SenderKind.ReplicaDestination,
    contact: replicaContact,
  });
  const destPairRequest = drainOne(destination, "Destination");
  const ownerPairEvents = await processAll(owner, destPairRequest);
  const ownerReplicaCompleted = requireEvent(
    ownerPairEvents,
    "PairingCompleted",
    "Owner/replica",
  );
  const rekeyedDestChannel = BigInt(ownerReplicaCompleted.channel_id);
  const ownerReplicaPaired = requireEvent(
    ownerPairEvents,
    "ReplicaPaired",
    "Owner/replica",
  );
  if (BigInt(ownerReplicaPaired.peer_replica_id) !== destReplicaId) {
    throw new Error(
      `Owner-side ReplicaPaired must carry destination replica_id=${destReplicaId}, got ${ownerReplicaPaired.peer_replica_id}`,
    );
  }
  const ownerPairResponse = drainOne(owner, "Owner");
  const destPairEvents = await processAll(destination, ownerPairResponse);
  requireEvent(destPairEvents, "PairingCompleted", "Destination/replica");
  const destReplicaPaired = requireEvent(
    destPairEvents,
    "ReplicaPaired",
    "Destination/replica",
  );
  if (BigInt(destReplicaPaired.peer_replica_id) !== ownerReplicaId) {
    throw new Error(
      `Destination-side ReplicaPaired must carry owner replica_id=${ownerReplicaId}, got ${destReplicaPaired.peer_replica_id}`,
    );
  }
  console.log(
    `  replica pair handshake: owner sees peer=${ownerReplicaPaired.peer_replica_id}, dest sees peer=${destReplicaPaired.peer_replica_id}  ✓`,
  );

  // Replica channels start `Pending` after pair handshake completion
  // and stay outside the publish set until fingerprint verification.

  // 3. Cross-confirm fingerprints — channel is `Pending` until both
  //    sides verify, and ProtectSecret refuses to target a Pending
  //    replica channel. Use the rekeyed long-term id both sides
  //    rotated to at PairingCompleted.
  const ownerFp = await owner.protocol.getFingerprint(rekeyedDestChannel);
  const destFp = await destination.protocol.getFingerprint(rekeyedDestChannel);
  if (ownerFp !== destFp) {
    throw new Error(
      `replica fingerprint mismatch: owner=${ownerFp} dest=${destFp}`,
    );
  }
  const ownerConfirmed = await owner.protocol.verifyFingerprint(rekeyedDestChannel, destFp);
  const destConfirmed = await destination.protocol.verifyFingerprint(rekeyedDestChannel, ownerFp);
  if (!ownerConfirmed || !destConfirmed) {
    throw new Error(
      `verifyFingerprint must return true on both sides (owner=${ownerConfirmed}, dest=${destConfirmed})`,
    );
  }
  console.log(`  fingerprint cross-confirmed (${ownerFp.length} chars)  ✓`);

  // verifyFingerprint auto-publishes an empty-secret roster snapshot
  // to every paired peer (2 helpers + 1 replica) so the newly-Paired
  // Destination receives the current state without an explicit
  // ProtectSecret call. Drain that round here — the assertions below
  // target the subsequent explicit publish.
  const autoPublish = owner.transport.drain();
  if (autoPublish.length !== 3) {
    throw new Error(
      `verifyFingerprint auto-publish must fan out to 2 helpers + 1 replica (v=1, empty secrets), got ${autoPublish.length}`,
    );
  }

  // 4. ProtectSecret across both helpers + the destination. Three
  //    envelopes leave the owner: two VSS shares (one per helper) and
  //    one ReplicaSecretPayload composite (for the destination).
  const secretData = utf8Encode("secret-payload-for-replica-and-helper");
  await owner.protocol.start(FlowKind.ProtectSecret, {
    secrets: [{ id: new Uint8Array([0x01]), name: "shared-secret", data: secretData }],
    description: "replica + helper distribution",
  });

  const outbound = owner.transport.drain();
  if (outbound.length !== 3) {
    throw new Error(
      `expected 3 outbound StoreShareRequests (2 helpers + 1 destination), got ${outbound.length}`,
    );
  }
  const destEnvelope = outbound.find((m) => m.endpoint.uri === destUri);
  if (!destEnvelope) {
    throw new Error("one outbound envelope must route to the destination");
  }
  console.log(`  ProtectSecret fanned out 3 envelopes (2 helpers + 1 destination)  ✓`);

  // 5. Feed the destination envelope to its peer; expect the typed
  //    sync event with the full decoded secret. This is the destination's
  //    first sync for this secret_id, so it installs rather than updates.
  const destEvents = await processAll(destination, destEnvelope.message);
  const received = destEvents.find((e) => e.type === "ReplicaSecretInstalled") as
    | Extract<DeRecEvent, { type: "ReplicaSecretInstalled" }>
    | undefined;
  if (!received) {
    throw new Error(
      `Destination did not emit ReplicaSecretInstalled; got [${destEvents.map((e) => e.type).join(", ")}]`,
    );
  }
  if (BigInt(received.from_replica_id) !== ownerReplicaId) {
    throw new Error(
      `from_replica_id must echo owner's replica_id (${ownerReplicaId}), got ${received.from_replica_id}`,
    );
  }
  if (BigInt(received.secret_id) !== secretId) {
    throw new Error(`secret_id mismatch: expected ${secretId}, got ${received.secret_id}`);
  }
  // On a push the sender is also the publisher of the version.
  if (received.author_replica_id === null || BigInt(received.author_replica_id) !== ownerReplicaId) {
    throw new Error(
      `author_replica_id must name the publisher (${ownerReplicaId}), got ${received.author_replica_id}`,
    );
  }
  // The destination's snapshot records that publisher; replica conflict
  // detection reads it back from the application's UserSecretStore.
  const destSnapshot = await destination.userSecretStore.loadLatest(
    String(destination.protocol.secretId()),
  );
  if (
    destSnapshot?.author_replica_id === undefined ||
    BigInt(destSnapshot.author_replica_id) !== ownerReplicaId
  ) {
    throw new Error(
      `destination UserSecretStore must hold author_replica_id=${ownerReplicaId}, got ${destSnapshot?.author_replica_id}`,
    );
  }
  if (received.secret.secrets.length !== 1) {
    throw new Error(
      `secret.secrets.length expected 1, got ${received.secret.secrets.length}`,
    );
  }
  const receivedBytes = received.secret.secrets[0]!.data;
  if (
    receivedBytes.length !== secretData.length ||
    !receivedBytes.every((b, i) => b === secretData[i])
  ) {
    throw new Error("secret.secrets[0].data must round-trip the original secret bytes");
  }
  if (received.secret.helpers.length !== 2) {
    throw new Error(
      `secret.helpers.length expected 2, got ${received.secret.helpers.length}`,
    );
  }
  // The roster names every member including the writer, so the source is
  // identified by its role rather than by a separate field.
  const members = received.secret.replicas?.members ?? [];
  if (members.length !== 2) {
    throw new Error(`secret.replicas.members expected 2, got ${members.length}`);
  }
  const sources = members.filter((m) => m.role === "Source");
  if (sources.length !== 1 || BigInt(sources[0]!.replica_id) !== ownerReplicaId) {
    throw new Error(
      `the roster must name exactly one Source, and it must be the owner (${ownerReplicaId})`,
    );
  }
  const destInfo = members.find((m) => m.role === "Destination")!;
  if (BigInt(destInfo.replica_id) !== destReplicaId) {
    throw new Error(
      `the roster's Destination member expected ${destReplicaId}, got ${destInfo.replica_id}`,
    );
  }
  if (received.shares.length !== 2) {
    throw new Error(
      `shares.length expected 2 (one per helper), got ${received.shares.length}`,
    );
  }
  console.log(
    `  ReplicaSecretInstalled: secret=${received.secret.secrets.length}secret/${received.secret.helpers.length}helpers/${(received.secret.replicas?.members.length ?? 0)}members, shares=${received.shares.length}  ✓`,
  );

  // Drain helper outboxes from v=1 so the next round sees only v=2.
  helperA.transport.drain();
  helperB.transport.drain();

  // Secret version updates: the owner mutates the secret and re-runs
  // `ProtectSecret`. Version progression is now anchored to
  // `IUserSecretStore.loadLatest()` (the snapshot the previous
  // round wrote), so each successful publish naturally bumps by 1.
  //
  // Sequence in this test:
  //   v=1: verify_fingerprint auto-publish (already drained above)
  //   v=2: first explicit ProtectSecret (the `received` round above)
  //   v=3: this second explicit ProtectSecret
  const secretDataV2 = utf8Encode("secret-payload-after-update");
  await owner.protocol.start(FlowKind.ProtectSecret, {
    secrets: [{ id: new Uint8Array([0x01]), name: "shared-secret", data: secretDataV2 }],
    description: "v2 replica + helper distribution",
  });

  const outbound2 = owner.transport.drain();
  if (outbound2.length !== 3) {
    throw new Error(`v2: expected 3 outbound envelopes, got ${outbound2.length}`);
  }
  const destEnvelope2 = outbound2.find((m) => m.endpoint.uri === destUri);
  if (!destEnvelope2) {
    throw new Error("v2: no envelope routed to the destination");
  }
  const destEvents2 = await destination.protocol.process(destEnvelope2.message);
  const received2 = destEvents2.find((e) => e.type === "ReplicaSecretReceived") as
    | (DeRecEvent & { type: "ReplicaSecretReceived" })
    | undefined;
  if (!received2) {
    throw new Error(
      `v2: destination did not emit ReplicaSecretReceived; got [${destEvents2.map((e) => e.type).join(", ")}]`,
    );
  }
  if (received2.version !== 3) {
    throw new Error(`v2: expected version=3, got ${received2.version}`);
  }
  if (received2.author_replica_id === null || BigInt(received2.author_replica_id) !== ownerReplicaId) {
    throw new Error(
      `v2: author_replica_id must name the publisher (${ownerReplicaId}), got ${received2.author_replica_id}`,
    );
  }
  const v2Data = received2.secret.secrets[0]?.data;
  if (
    received2.secret.secrets.length !== 1 ||
    !v2Data ||
    v2Data.length !== secretDataV2.length ||
    !Array.from(secretDataV2).every((b, i) => b === v2Data[i])
  ) {
    throw new Error("v2: secret.secrets[0].data must round-trip the updated bytes");
  }
  console.log(
    `  ReplicaSecretReceived v=2: secret bytes updated, share count = ${received2.shares.length}  ✓`,
  );

  // Replica recovery transitivity: the Destination received
  // `secret.helpers[*].shared_key` inside the secret. Those keys must be
  // byte-identical to what each helper has stored locally for the
  // owner channel, because a Destination acting as a recovery delegate
  // uses them to authenticate as the Source toward each helper.
  const helperAStored = await helperA.secretStore.load(
    String(helperA.protocol.secretId()),
    rekeyedHelperA,
    0,
  );
  const helperBStored = await helperB.secretStore.load(
    String(helperB.protocol.secretId()),
    rekeyedHelperB,
    0,
  );
  if (!helperAStored || !helperBStored) {
    throw new Error("helpers must have stored their shared keys");
  }
  const secretHelperA = received2.secret.helpers.find(
    (h) => h.channel_id === rekeyedHelperA,
  );
  const secretHelperB = received2.secret.helpers.find(
    (h) => h.channel_id === rekeyedHelperB,
  );
  if (!secretHelperA || !secretHelperB) {
    throw new Error("secret.helpers missing entry for one of the helpers");
  }
  const keysEqual = (a: Uint8Array | number[], b: Uint8Array | number[]) => {
    const aBytes = a instanceof Uint8Array ? a : new Uint8Array(a);
    const bBytes = b instanceof Uint8Array ? b : new Uint8Array(b);
    if (aBytes.length !== bBytes.length) return false;
    for (let i = 0; i < aBytes.length; i++) {
      if (aBytes[i] !== bBytes[i]) return false;
    }
    return true;
  };
  if (!keysEqual(helperAStored, secretHelperA.shared_key)) {
    throw new Error(
      "secret.helpers[HelperA].shared_key must match what HelperA stores locally",
    );
  }
  if (!keysEqual(helperBStored, secretHelperB.shared_key)) {
    throw new Error(
      "secret.helpers[HelperB].shared_key must match what HelperB stores locally",
    );
  }
  console.log(
    "  secret.helpers[*].shared_key matches each helper's stored key — destination can act in source's stead  ✓",
  );

  // The secret also carries `secret.secrets[*].data` unencrypted, so
  // the Destination can fall back to its stored secret without
  // contacting any helper. The recovery model is "any one of: helper
  // quorum, secret on a single destination" — both paths recover the
  // same secret bytes.
  const v2DataCheck = received2.secret.secrets[0]?.data;
  if (
    !v2DataCheck ||
    v2DataCheck.length !== secretDataV2.length ||
    !Array.from(secretDataV2).every((b, i) => b === v2DataCheck[i])
  ) {
    throw new Error(
      "secret.secrets[0].data must be the raw recovered bytes",
    );
  }
  console.log(
    "  secret.secrets[0].data is the raw recovered secret — destination-only recovery is viable  ✓",
  );

  console.log("\n✓ Replica pairing + secret sync flow passed.\n");
}


/**
 * Asserts the `UpdateChannelInfo` flow end-to-end: owner mutates its
 * local communication_info + transport endpoint, broadcasts the change,
 * and both sides emit `ChannelInfoUpdated` events. Mirrors the Rust
 * binding's `run_update_channel_info_flow`.
 */
async function runUpdateChannelInfoFlow(): Promise<void> {
  console.log("=== [Protocol] UpdateChannelInfo Flow ===\n");

  const channelId = 42n;
  const helper = makeNode("Helper", "https://helper.example.com");
  const owner = makeNode("Owner", "https://owner.OLD.example.com");

  const { longTermChannelId } = await doPair(helper, owner, channelId, "UpdateChannelInfo");
  console.log();

  const newUri = "https://owner.NEW.example.com";
  const newInfo = { name: "Owner-renamed", email: "owner.new@example.com" };

  // Mutate local state, then propagate. Both setters queue onto the
  // protocol's serial worker, so they are awaited before the flow that must
  // observe them starts.
  await owner.protocol.setCommunicationInfo(newInfo);
  await owner.protocol.setOwnTransports([{ uri: newUri, protocol: "https" }]);

  await owner.protocol.start(FlowKind.UpdateChannelInfo, {
    target: BigInt(longTermChannelId),
    communication_info: newInfo,
    own_transports: [{ uri: newUri, protocol: "https" }],
  });
  const updateRequest = drainOne(owner, "Owner");
  console.log(`  [Owner] start(UpdateChannelInfo) → request ${updateRequest.length}B`);

  const helperEvents = await processAll(helper, updateRequest);
  const updateAction = requireEvent(helperEvents, "ActionRequired", "Helper");
  if (JSON.stringify(updateAction.updated_transports) !== JSON.stringify([{ uri: newUri, protocol: "https" }])) {
    throw new Error(
      `ActionRequired(UpdateChannelInfo).updated_transports must match the announced endpoints; got ${JSON.stringify(updateAction.updated_transports)}`,
    );
  }
  const announcedInfo = updateAction.updated_communication_info ?? {};
  if (
    Object.keys(announcedInfo).length !== Object.keys(newInfo).length ||
    Object.entries(newInfo).some(([k, v]) => announcedInfo[k] !== v)
  ) {
    throw new Error(
      `ActionRequired(UpdateChannelInfo).updated_communication_info must match the announced map; got ${JSON.stringify(updateAction.updated_communication_info)}`,
    );
  }
  console.log("  [Helper] ActionRequired(UpdateChannelInfo) carries the announced transports + communication_info  ✓");
  const helperUpdated = helperEvents.find((e) => e.type === "ChannelInfoUpdated");
  if (!helperUpdated) {
    throw new Error(
      `Helper must emit ChannelInfoUpdated; got [${helperEvents.map((e) => e.type).join(", ")}]`,
    );
  }
  console.log(`  [Helper] processAll(update) → ChannelInfoUpdated  ✓`);

  const updateResponse = drainOne(helper, "Helper");
  const ownerEvents = await processAll(owner, updateResponse);
  const ownerUpdated = ownerEvents.find((e) => e.type === "ChannelInfoUpdated");
  if (!ownerUpdated) {
    throw new Error(
      `Owner must emit ChannelInfoUpdated; got [${ownerEvents.map((e) => e.type).join(", ")}]`,
    );
  }
  console.log(`  [Owner]  process(response) → ChannelInfoUpdated  ✓`);

  const helperStoredBytes = await helper.channelStore.load(
    String(helper.protocol.secretId()),
    longTermChannelId,
    "0",
  );
  if (!helperStoredBytes) {
    throw new Error("helper channel record must still exist after UpdateChannelInfo");
  }
  const helperStored = JSON.parse(utf8Decode(helperStoredBytes)).Helper;
  if (helperStored.transports[0].uri !== newUri) {
    throw new Error(
      `helper's stored transports[0].uri must reflect the announced update; got ${helperStored.transports[0].uri}`,
    );
  }
  for (const [k, v] of Object.entries(newInfo)) {
    if (helperStored.communication_info[k] !== v) {
      throw new Error(
        `helper's stored communication_info[${k}] must mirror the announced map; got ${helperStored.communication_info[k]}`,
      );
    }
  }
  console.log("  helper's stored transport.uri + communication_info mirror the update  ✓");

  console.log("\n✓ UpdateChannelInfo flow passed.\n");
}


/**
 * Asserts the two sad paths around the constructor `replicaId` argument:
 * (1) a node without it must refuse to initiate any replica-mode flow,
 * (2) and must reject an inbound replica-mode PairRequest from a
 * configured peer. Mirrors the Rust binding's
 * `run_replica_id_wiring_flow` scenarios 2 + 3.
 */
async function runReplicaIdWiringSadPathsFlow(): Promise<void> {
  console.log("=== [Protocol] Replica id wiring sad-paths ===\n");

  const configuredReplicaId = 0xCAFE_BABE_DEAD_BEEFn;

  // -- Scenario A: initiator without replica_id refuses to scan a
  //    contact as ReplicaDestination.
  const contactCreator = makeNode("ContactCreator", "https://creator.example.com", { replicaId: configuredReplicaId });
  const unconfiguredScanner = makeNode("Scanner", "https://scanner.example.com");

  const contact = await contactCreator.protocol.createContact(500n, ContactMode.InlineKeys);

  let caught: unknown = null;
  try {
    await unconfiguredScanner.protocol.start(FlowKind.Pairing, {
      kind: SenderKind.ReplicaDestination,
      contact,
    });
  } catch (e) {
    caught = e;
  }
  if (caught === null) {
    throw new Error("scanner without replica_id must refuse to start a replica pair");
  }
  if (unconfiguredScanner.transport.drain().length !== 0) {
    throw new Error("no outbound traffic should have been queued");
  }
  console.log("  scanner without replica_id refuses to start replica pair  ✓");

  // -- Scenario B: configured initiator's PairRequest is refused by
  //    an unconfigured responder.
  const unconfiguredCreator = makeNode("CreatorB", "https://creator2.example.com");
  const configuredScanner = makeNode("ScannerB", "https://scanner2.example.com", { replicaId: configuredReplicaId });

  const contact2 = await unconfiguredCreator.protocol.createContact(501n, ContactMode.InlineKeys);
  await configuredScanner.protocol.start(FlowKind.Pairing, {
    kind: SenderKind.ReplicaDestination,
    contact: contact2,
  });
  const pairRequest = drainOne(configuredScanner, "ScannerB");

  let caught2: unknown = null;
  try {
    await unconfiguredCreator.protocol.process(pairRequest);
  } catch (e) {
    caught2 = e;
  }
  if (caught2 === null) {
    throw new Error("unconfigured responder must refuse a replica-mode PairRequest");
  }
  console.log("  responder without replica_id refuses inbound replica PairRequest  ✓");

  console.log("\n✓ Replica id wiring sad-paths passed.\n");
}



/**
 * A helper's share store refuses with `shareStoreRefusal("too_frequent")`,
 * first a share and then a verification. The helper still answers, so the
 * owner observes `ShareRejected` and `ShareVerifyRejected` with status
 * TOO_FREQUENT, and the helper's `process`/`accept` calls resolve.
 */
async function runShareStoreRefusalFlow(): Promise<void> {
  console.log("=== [Protocol] Share store refusal Flow ===\n");

  const secretId = 45n;
  const owner = makeNode("Owner", "https://owner.example.com", { secretId });
  const helperA = makeNode("HelperA", "https://helper-a.example.com", { secretId });
  const helperB = makeNode("HelperB", "https://helper-b.example.com", { secretId });
  const pairedA = await doPair(helperA, owner, 51n, "Owner↔HelperA");
  await doPair(helperB, owner, 52n, "Owner↔HelperB");

  const helpersByUri = new Map<string, [Node, string]>([
    ["https://helper-a.example.com", [helperA, "HelperA"]],
    ["https://helper-b.example.com", [helperB, "HelperB"]],
  ]);
  const roundTrip = async (): Promise<DeRecEvent[]> => {
    const ownerEvents: DeRecEvent[] = [];
    for (const { endpoint, message } of owner.transport.drain()) {
      const [helper, label] = helpersByUri.get(endpoint.uri)!;
      await processAll(helper, message);
      ownerEvents.push(...(await owner.protocol.process(drainOne(helper, label))));
    }
    return ownerEvents;
  };
  const protect = async (data: string): Promise<number> => {
    const events = await owner.protocol.start(FlowKind.ProtectSecret, {
      secrets: [{ id: new Uint8Array([9]), name: "rate-limited", data: utf8Encode(data) }],
      description: data,
    });
    return requireEvent(events, "ProtectSecretStarted", "Owner").version;
  };

  const version = await protect("first version");
  await roundTrip();

  helperA.shareStore.refuseSaves = true;
  const nextVersion = await protect("second version");
  const shareRejected = (await roundTrip()).filter(
    (e): e is Extract<DeRecEvent, { type: "ShareRejected" }> => e.type === "ShareRejected",
  );
  if (
    shareRejected.length !== 1 ||
    shareRejected[0]!.channel_id !== pairedA.longTermChannelId ||
    shareRejected[0]!.version !== nextVersion ||
    shareRejected[0]!.status !== StatusEnum.TooFrequent
  ) {
    throw new Error(`expected one ShareRejected(TOO_FREQUENT) from HelperA, got ${JSON.stringify(shareRejected)}`);
  }
  console.log("  [HelperA] save → too_frequent; [Owner] ShareRejected(status=TOO_FREQUENT)  ✓");

  helperA.shareStore.refuseSaves = false;
  helperA.shareStore.refuseVerifications = true;
  await owner.protocol.start(FlowKind.VerifyShares, { secretId, version });
  const verifyEvents = await roundTrip();
  const verifyRejected = verifyEvents.filter(
    (e): e is Extract<DeRecEvent, { type: "ShareVerifyRejected" }> => e.type === "ShareVerifyRejected",
  );
  if (
    verifyRejected.length !== 1 ||
    verifyRejected[0]!.channel_id !== pairedA.longTermChannelId ||
    verifyRejected[0]!.status !== StatusEnum.TooFrequent
  ) {
    throw new Error(`expected one ShareVerifyRejected(TOO_FREQUENT) from HelperA, got ${JSON.stringify(verifyRejected)}`);
  }
  if (verifyEvents.filter((e) => e.type === "ShareVerified").length !== 1) {
    throw new Error("HelperB must still prove possession");
  }
  console.log("  [HelperA] recordVerification → too_frequent; [Owner] ShareVerifyRejected(status=TOO_FREQUENT)  ✓");

  console.log("\n✓ Share store refusal flow passed.\n");
}

/**
 * With `auto_respond_on_failure` left off (the default), a request whose
 * handling fails is not answered by the library. It is reported as a
 * `RequestFailed` event carrying a token, and `reject` on that token sends the
 * one response the peer is owed. The failure is a share store backend error on
 * an accepted StoreShare; the owner observes exactly one `ShareRejected`
 * carrying the status passed to `reject`.
 */
async function runRequestFailedTokenFlow(): Promise<void> {
  console.log("=== [Protocol] Failed request answered through its token ===\n");

  const secretId = 46n;
  const owner = makeNode("Owner", "https://owner.example.com", { secretId });
  const helperA = makeNode("HelperA", "https://helper-a.example.com", { secretId });
  const helperB = makeNode("HelperB", "https://helper-b.example.com", { secretId });
  const pairedA = await doPair(helperA, owner, 61n, "Owner↔HelperA");
  await doPair(helperB, owner, 62n, "Owner↔HelperB");

  helperA.shareStore.failSaves = true;
  const started = await owner.protocol.start(FlowKind.ProtectSecret, {
    secrets: [{ id: new Uint8Array([10]), name: "failing", data: utf8Encode("payload") }],
    description: "failing",
  });
  const version = requireEvent(started, "ProtectSecretStarted", "Owner").version;

  const ownerEvents: DeRecEvent[] = [];
  const failed: Array<Extract<DeRecEvent, { type: "RequestFailed" }>> = [];
  for (const { endpoint, message } of owner.transport.drain()) {
    if (endpoint.uri === "https://helper-b.example.com") {
      await processAll(helperB, message);
      ownerEvents.push(...(await owner.protocol.process(drainOne(helperB, "HelperB"))));
    } else if (endpoint.uri === "https://helper-a.example.com") {
      for (const ev of await processAll(helperA, message)) {
        if (ev.type === "RequestFailed") failed.push(ev);
      }
    } else {
      throw new Error(`no peer for destination uri ${endpoint.uri}`);
    }
  }

  const rf = failed[0];
  if (
    failed.length !== 1 ||
    !rf ||
    rf.channel_id !== pairedA.longTermChannelId ||
    rf.action_kind !== "StoreShare" ||
    rf.responded ||
    rf.status !== StatusEnum.Fail ||
    rf.memo !== "request could not be processed" ||
    rf.error_code !== "store_error" ||
    !rf.action ||
    rf.action.length === 0
  ) {
    throw new Error(`HelperA must report one unanswered RequestFailed(StoreShare) with a token, got ${JSON.stringify(failed)}`);
  }
  const unsent = helperA.transport.drain();
  if (unsent.length !== 0) {
    throw new Error(`with auto_respond_on_failure off, HelperA must not answer by itself; sent ${unsent.length}`);
  }
  console.log(`  [HelperA] save fails → RequestFailed(action_kind=${rf.action_kind}, responded=false, status=${rf.status}, memo="${rf.memo}", error_code=${rf.error_code}) with a token, nothing sent  ✓`);

  await helperA.protocol.reject(rf.action, rf.status, rf.memo);
  const replies = helperA.transport.drain();
  if (replies.length !== 1) {
    throw new Error(`reject(token) must send exactly one response; sent ${replies.length}`);
  }
  ownerEvents.push(...(await owner.protocol.process(replies[0]!.message)));

  const rejected = ownerEvents.filter(
    (e): e is Extract<DeRecEvent, { type: "ShareRejected" }> => e.type === "ShareRejected",
  );
  if (
    rejected.length !== 1 ||
    rejected[0]!.channel_id !== pairedA.longTermChannelId ||
    rejected[0]!.version !== version ||
    rejected[0]!.status !== StatusEnum.Fail ||
    rejected[0]!.memo !== rf.memo
  ) {
    throw new Error(`expected one ShareRejected(FAIL, event memo) from HelperA, got ${JSON.stringify(rejected)}`);
  }
  console.log("  [HelperA] reject(token, event.status, event.memo) → one response; [Owner] ShareRejected(status=FAIL, same memo)  ✓");

  console.log("\n✓ Failed request token flow passed.\n");
}

/**
 * A share outside the helper's configured size range is refused by the
 * helper's library before any `ActionRequired`: the helper reports
 * `ShareRefused(SIZE_LIMIT_EXCEEDED)`, stores nothing, and the owner observes
 * `ShareRejected` with the same status and memo.
 */
async function runShareRefusedFlow(): Promise<void> {
  console.log("=== [Protocol] Share refused by the helper's size range ===\n");

  const secretId = 0x7171n;
  const owner = makeNode("Owner", "https://owner.example.com", { secretId });
  const helperA = makeNode("HelperA", "https://helper-a.example.com", {
    secretId,
    parameterRange: { max_share_size: 64n },
  });
  const helperB = makeNode("HelperB", "https://helper-b.example.com", { secretId });
  const pairedA = await doPair(helperA, owner, 81n, "Owner↔HelperA");
  await doPair(helperB, owner, 82n, "Owner↔HelperB");

  const started = await owner.protocol.start(FlowKind.ProtectSecret, {
    secrets: [{ id: new Uint8Array([11]), name: "oversized", data: utf8Encode("larger than 64 bytes once split") }],
    description: "oversized",
  });
  const version = requireEvent(started, "ProtectSecretStarted", "Owner").version;

  const ownerEvents: DeRecEvent[] = [];
  let helperAEvents: DeRecEvent[] = [];
  for (const { endpoint, message } of owner.transport.drain()) {
    if (endpoint.uri === "https://helper-b.example.com") {
      await processAll(helperB, message);
      ownerEvents.push(...(await owner.protocol.process(drainOne(helperB, "HelperB"))));
    } else if (endpoint.uri === "https://helper-a.example.com") {
      helperAEvents = await helperA.protocol.process(message);
      ownerEvents.push(...(await owner.protocol.process(drainOne(helperA, "HelperA"))));
    } else {
      throw new Error(`no peer for destination uri ${endpoint.uri}`);
    }
  }

  const refused = helperAEvents[0];
  if (
    helperAEvents.length !== 1 ||
    refused?.type !== "ShareRefused" ||
    refused.channel_id !== pairedA.longTermChannelId ||
    refused.version !== version ||
    refused.status !== StatusEnum.SizeLimitExceeded ||
    refused.memo.length === 0
  ) {
    throw new Error(`HelperA must report exactly one ShareRefused(SIZE_LIMIT_EXCEEDED), got ${JSON.stringify(helperAEvents)}`);
  }
  if ((await helperA.shareStore.load(secretId.toString(), refused.channel_id, [])).length !== 0) {
    throw new Error("HelperA must store nothing for a refused share");
  }
  console.log(`  [HelperA] process(StoreShareRequest) → ShareRefused(status=SIZE_LIMIT_EXCEEDED, memo="${refused.memo}"), nothing stored  ✓`);

  const rejected = ownerEvents.filter(
    (e): e is Extract<DeRecEvent, { type: "ShareRejected" }> => e.type === "ShareRejected",
  );
  if (
    rejected.length !== 1 ||
    rejected[0]!.channel_id !== pairedA.longTermChannelId ||
    rejected[0]!.version !== version ||
    rejected[0]!.status !== StatusEnum.SizeLimitExceeded ||
    rejected[0]!.memo !== refused.memo
  ) {
    throw new Error(`expected one ShareRejected(SIZE_LIMIT_EXCEEDED, same memo) from HelperA, got ${JSON.stringify(rejected)}`);
  }
  console.log("  [Owner] ShareRejected(status=SIZE_LIMIT_EXCEEDED, same memo)  ✓");

  console.log("\n✓ Share refused flow passed.\n");
}

/**
 * With `auto_respond_on_failure` on, the library answers a request whose
 * handling fails by itself: `RequestFailed` reports `responded: true` and
 * carries no token, and the owner observes one `ShareRejected` with no
 * `reject` call.
 */
async function runAutoRespondOnFailureFlow(): Promise<void> {
  console.log("=== [Protocol] Failed request answered by the library ===\n");

  const secretId = 0x7272n;
  const owner = makeNode("Owner", "https://owner.example.com", { secretId });
  const helperA = makeNode("HelperA", "https://helper-a.example.com", {
    secretId,
    autoRespondOnFailure: true,
  });
  const helperB = makeNode("HelperB", "https://helper-b.example.com", { secretId });
  const pairedA = await doPair(helperA, owner, 83n, "Owner↔HelperA");
  await doPair(helperB, owner, 84n, "Owner↔HelperB");

  helperA.shareStore.failSaves = true;
  const started = await owner.protocol.start(FlowKind.ProtectSecret, {
    secrets: [{ id: new Uint8Array([12]), name: "failing", data: utf8Encode("payload") }],
    description: "failing",
  });
  const version = requireEvent(started, "ProtectSecretStarted", "Owner").version;

  const ownerEvents: DeRecEvent[] = [];
  const failed: Array<Extract<DeRecEvent, { type: "RequestFailed" }>> = [];
  for (const { endpoint, message } of owner.transport.drain()) {
    if (endpoint.uri === "https://helper-b.example.com") {
      await processAll(helperB, message);
      ownerEvents.push(...(await owner.protocol.process(drainOne(helperB, "HelperB"))));
    } else if (endpoint.uri === "https://helper-a.example.com") {
      for (const ev of await processAll(helperA, message)) {
        if (ev.type === "RequestFailed") failed.push(ev);
      }
    } else {
      throw new Error(`no peer for destination uri ${endpoint.uri}`);
    }
  }

  const rf = failed[0];
  if (
    failed.length !== 1 ||
    !rf ||
    rf.channel_id !== pairedA.longTermChannelId ||
    rf.action_kind !== "StoreShare" ||
    !rf.responded ||
    rf.action !== undefined ||
    rf.status !== StatusEnum.Fail ||
    rf.memo !== "request could not be processed" ||
    rf.error_code.length === 0
  ) {
    throw new Error(`HelperA must report one answered RequestFailed(StoreShare) without a token, got ${JSON.stringify(failed)}`);
  }
  const answers = helperA.transport.drain();
  if (answers.length !== 1) {
    throw new Error(`with auto_respond_on_failure on, HelperA must answer once by itself; sent ${answers.length}`);
  }
  console.log(`  [HelperA] save fails → RequestFailed(responded=true, no action, status=${rf.status}, error_code=${rf.error_code}), one response sent  ✓`);

  ownerEvents.push(...(await owner.protocol.process(answers[0]!.message)));
  const rejected = ownerEvents.filter(
    (e): e is Extract<DeRecEvent, { type: "ShareRejected" }> => e.type === "ShareRejected",
  );
  if (
    rejected.length !== 1 ||
    rejected[0]!.channel_id !== pairedA.longTermChannelId ||
    rejected[0]!.version !== version ||
    rejected[0]!.status !== StatusEnum.Fail ||
    rejected[0]!.memo !== "request could not be processed"
  ) {
    throw new Error(`expected one ShareRejected(FAIL, "request could not be processed") from HelperA, got ${JSON.stringify(rejected)}`);
  }
  console.log('  [Owner] ShareRejected(status=FAIL, memo="request could not be processed") with no reject()  ✓');

  console.log("\n✓ Auto-respond on failure flow passed.\n");
}

/**
 * `start(ProtectSecret)` refuses a weight that is not below the threshold,
 * and a weight naming a channel that is not a paired helper, with
 * `invalid_weight` before anything is sent.
 */
async function runInvalidWeightAtStartFlow(): Promise<void> {
  console.log("=== [Protocol] start(ProtectSecret) refuses an invalid weight ===\n");

  const secretId = 0x7373n;
  const owner = makeNode("Owner", "https://owner.example.com", { secretId });
  const helperA = makeNode("HelperA", "https://helper-a.example.com", { secretId });
  const helperB = makeNode("HelperB", "https://helper-b.example.com", { secretId });
  const pairedA = await doPair(helperA, owner, 85n, "Owner↔HelperA");
  await doPair(helperB, owner, 86n, "Owner↔HelperB");
  owner.transport.drain();

  const expectInvalidWeight = async (weights: Map<bigint | string, number>, what: string) => {
    let error: DeRecError | undefined;
    try {
      await owner.protocol.start(FlowKind.ProtectSecret, {
        secrets: [{ id: new Uint8Array([13]), name: "weighted", data: utf8Encode("invalid-weight") }],
        weights,
      });
    } catch (e) {
      error = e as DeRecError;
    }
    if (error?.code !== "invalid_weight") {
      throw new Error(`${what} must fail with invalid_weight, got ${JSON.stringify(error)}`);
    }
    const sent = owner.transport.drain();
    if (sent.length !== 0) {
      throw new Error(`${what} must send nothing; sent ${sent.length}`);
    }
    console.log(`  ${what} → invalid_weight, nothing sent  ✓`);
  };

  await expectInvalidWeight(new Map([[pairedA.longTermChannelId, THRESHOLD]]), "a weight equal to the threshold");
  await expectInvalidWeight(new Map([[0xBADn, 1]]), "a weight for an unpaired channel");

  console.log("\n✓ Invalid weight at start flow passed.\n");
}

/**
 * A channel whose share for the version was never confirmed has no proof on
 * the owner: `start(VerifyShares)` fails that channel locally with
 * `VerifySharesFailed(NoProof)` and sends it no challenge, while a channel
 * that confirmed is challenged as usual.
 */
async function runVerifyNoProofFlow(): Promise<void> {
  console.log("=== [Protocol] VerifyShares without a proof fails with NoProof ===\n");

  const secretId = 0x7474n;
  const owner = makeNode("Owner", "https://owner.example.com", { secretId });
  const helperA = makeNode("HelperA", "https://helper-a.example.com", { secretId });
  const helperB = makeNode("HelperB", "https://helper-b.example.com", { secretId });
  const pairedA = await doPair(helperA, owner, 87n, "Owner↔HelperA");
  const pairedB = await doPair(helperB, owner, 88n, "Owner↔HelperB");

  const helpersByUri = new Map<string, [Node, string]>([
    ["https://helper-a.example.com", [helperA, "HelperA"]],
    ["https://helper-b.example.com", [helperB, "HelperB"]],
  ]);
  helperA.shareStore.refuseSaves = true;
  const started = await owner.protocol.start(FlowKind.ProtectSecret, {
    secrets: [{ id: new Uint8Array([14]), name: "unconfirmed", data: utf8Encode("no-proof") }],
  });
  const version = requireEvent(started, "ProtectSecretStarted", "Owner").version;
  for (const { endpoint, message } of owner.transport.drain()) {
    const [helper, label] = helpersByUri.get(endpoint.uri)!;
    await processAll(helper, message);
    await owner.protocol.process(drainOne(helper, label));
  }

  const events = await owner.protocol.start(FlowKind.VerifyShares, { secretId, version });
  const noProof = events.filter(
    (e): e is Extract<DeRecEvent, { type: "VerifySharesFailed" }> => e.type === "VerifySharesFailed",
  );
  if (
    noProof.length !== 1 ||
    noProof[0]!.channel_id !== pairedA.longTermChannelId ||
    noProof[0]!.version !== version ||
    noProof[0]!.reason !== "NoProof"
  ) {
    throw new Error(`expected one VerifySharesFailed(NoProof) for HelperA, got [${events.map((e) => e.type).join(", ")}]`);
  }
  if (!events.some((e) => e.type === "VerifySharesStarted" && e.channel_id === pairedB.longTermChannelId)) {
    throw new Error("HelperB, which confirmed, must still be challenged");
  }
  const sent = owner.transport.drain();
  if (sent.length !== 1 || sent[0]!.endpoint.uri !== "https://helper-b.example.com") {
    throw new Error(`only HelperB may be challenged; sent to [${sent.map((m) => m.endpoint.uri).join(", ")}]`);
  }
  console.log(`  [Owner] v${version}: HelperA VerifySharesFailed(reason=NoProof), no challenge; HelperB challenged  ✓`);

  console.log("\n✓ VerifyShares NoProof flow passed.\n");
}

/**
 * Verdicts on verification responses that do not prove the share: an answer
 * to a challenge a newer one replaced is ignored as `StaleResponse`, a proof
 * over bytes that differ from the owner's is `ShareVerifyInvalid`, and a
 * message whose plaintext envelope timestamp differs from the encrypted inner
 * one is ignored as `TimestampMismatch`.
 */
async function runVerificationResponseVerdictsFlow(): Promise<void> {
  console.log("=== [Protocol] Verification response verdicts ===\n");

  const secretId = 0x7575n;
  const owner = makeNode("Owner", "https://owner.example.com", { secretId });
  const helperA = makeNode("HelperA", "https://helper-a.example.com", { secretId });
  const helperB = makeNode("HelperB", "https://helper-b.example.com", { secretId });
  const { longTermChannelId: channelA } = await doPair(helperA, owner, 89n, "Owner↔HelperA");
  await doPair(helperB, owner, 90n, "Owner↔HelperB");

  const helpersByUri = new Map<string, [Node, string]>([
    ["https://helper-a.example.com", [helperA, "HelperA"]],
    ["https://helper-b.example.com", [helperB, "HelperB"]],
  ]);
  const started = await owner.protocol.start(FlowKind.ProtectSecret, {
    secrets: [{ id: new Uint8Array([15]), name: "verdicts", data: utf8Encode("verdicts") }],
  });
  const version = requireEvent(started, "ProtectSecretStarted", "Owner").version;
  for (const { endpoint, message } of owner.transport.drain()) {
    const [helper, label] = helpersByUri.get(endpoint.uri)!;
    await processAll(helper, message);
    await owner.protocol.process(drainOne(helper, label));
  }

  const challenge = async (): Promise<{ traceId: string; message: Uint8Array }> => {
    const events = await owner.protocol.start(FlowKind.VerifyShares, {
      secretId,
      version,
      target: BigInt(channelA),
    });
    const verifyStarted = requireEvent(events, "VerifySharesStarted", "Owner");
    return { traceId: verifyStarted.trace_id, message: drainOne(owner, "Owner") };
  };
  const answer = async (request: Uint8Array): Promise<Uint8Array> => {
    await processAll(helperA, request);
    return drainOne(helperA, "HelperA");
  };

  // A second challenge replaces the first; the first one's answer is stale.
  const first = await challenge();
  const second = await challenge();
  const firstAnswer = await answer(first.message);
  const secondAnswer = await answer(second.message);
  const stale = await owner.protocol.process(firstAnswer);
  const ignored = stale[0];
  if (
    stale.length !== 1 ||
    ignored?.type !== "MessageIgnored" ||
    ignored.reason !== "StaleResponse" ||
    ignored.channel_id !== channelA ||
    ignored.trace_id !== first.traceId
  ) {
    throw new Error(`the replaced challenge's answer must be MessageIgnored(StaleResponse, trace ${first.traceId}), got ${JSON.stringify(stale)}`);
  }
  const current = await owner.protocol.process(secondAnswer);
  if (!current.some((e) => e.type === "ShareVerified" && e.channel_id === channelA && e.version === version)) {
    throw new Error(`the current challenge's answer must still verify, got [${current.map((e) => e.type).join(", ")}]`);
  }
  console.log("  [Owner] answer to a replaced challenge → MessageIgnored(StaleResponse); current answer → ShareVerified  ✓");

  // HelperA's stored share no longer matches the bytes the owner holds a
  // proof of, as after storage corruption. The stored record is the
  // StoreShareRequestMessage, whose field 1 is the committed share.
  const helperSid = secretId.toString();
  const [stored] = await helperA.shareStore.load(helperSid, channelA, [version]);
  if (!stored) throw new Error("HelperA must hold a share for the version");
  const tampered = rewriteProtoField(stored.bytes, 1, (share) => {
    const copy = share.slice();
    copy[copy.length >> 1] ^= 0xff;
    return copy;
  });
  await helperA.shareStore.save(helperSid, channelA, { ...stored, bytes: tampered });
  const invalid = await owner.protocol.process(await answer((await challenge()).message));
  const verdict = invalid[0];
  if (
    invalid.length !== 1 ||
    verdict?.type !== "ShareVerifyInvalid" ||
    verdict.channel_id !== channelA ||
    verdict.version !== version
  ) {
    throw new Error(`a proof over corrupted bytes must be ShareVerifyInvalid, got ${JSON.stringify(invalid)}`);
  }
  console.log("  [Owner] proof over HelperA's corrupted share → ShareVerifyInvalid  ✓");

  // The plaintext envelope timestamp (DeRecMessage field 5) is moved off the
  // encrypted inner one.
  const mismatchedEnvelope = rewriteProtoField((await challenge()).message, 5, (timestamp) => {
    const { seconds, nanos } = decodeTimestamp(timestamp);
    return encodeTimestamp(seconds, (nanos + 1) % 1_000_000_000);
  });
  const mismatched = await helperA.protocol.process(mismatchedEnvelope);
  const tsIgnored = mismatched[0];
  if (
    mismatched.length !== 1 ||
    tsIgnored?.type !== "MessageIgnored" ||
    tsIgnored.reason !== "TimestampMismatch" ||
    tsIgnored.channel_id !== channelA
  ) {
    throw new Error(`a mismatched envelope timestamp must be MessageIgnored(TimestampMismatch), got ${JSON.stringify(mismatched)}`);
  }
  if (helperA.transport.drain().length !== 0) {
    throw new Error("a message ignored for its timestamp must not be answered");
  }
  console.log("  [HelperA] envelope timestamp ≠ inner timestamp → MessageIgnored(TimestampMismatch), nothing sent  ✓");

  console.log("\n✓ Verification response verdicts flow passed.\n");
}

/**
 * A replica destination refuses a copy of the secret whose share map does not
 * verify: it reports `ReplicaSecretRefused(VERIFICATION_FAILED)` and writes
 * nothing. The copy is served by a catch-up, built from the source's share
 * store, whose committed share for one helper is corrupted first; a catch-up
 * copy is itself an answer, so nothing is sent back.
 */
async function runReplicaSecretRefusedFlow(): Promise<void> {
  console.log("\n=== [Protocol] Replica destination refuses an unverifiable copy ===\n");

  const secretId = 0x7676n;
  const SOURCE_REPLICA_ID = 0x5151_5151n;
  const source = {
    node: makeNode("Source", "https://source.example.com", { secretId, replicaId: SOURCE_REPLICA_ID }),
    uri: "https://source.example.com",
  };
  const destination = {
    node: makeNode("Destination", "https://destination.example.com", { secretId, replicaId: 0xde58_de58n }),
    uri: "https://destination.example.com",
  };
  const helperA = { node: makeNode("HelperA", "https://helper-a.example.com", { secretId }), uri: "https://helper-a.example.com" };
  const helperB = { node: makeNode("HelperB", "https://helper-b.example.com", { secretId }), uri: "https://helper-b.example.com" };
  const { longTermChannelId: channelA } = await doPair(helperA.node, source.node, 91n, "Source↔HelperA");
  await doPair(helperB.node, source.node, 92n, "Source↔HelperB");
  await source.node.protocol.start(FlowKind.ProtectSecret, {
    secrets: [{ id: new Uint8Array([16]), name: "replicated", data: utf8Encode("replicated secret") }],
  });
  await pumpAll([source, helperA, helperB]);

  // The destination has not confirmed the fingerprint, so the copy the
  // source publishes on confirming its own side is ignored.
  const { rekeyed } = await pairReplicaHandshake(source, destination, 93n);
  const destinationFp = await destination.node.protocol.getFingerprint(rekeyed);
  if (!(await source.node.protocol.verifyFingerprint(rekeyed, destinationFp))) {
    throw new Error("source.verifyFingerprint must return true");
  }
  await pumpAll([source, destination, helperA, helperB]);

  const latest = await source.node.userSecretStore.loadLatest(secretId.toString());
  if (!latest) throw new Error("the source must hold a snapshot");
  const [stored] = await source.node.shareStore.load(secretId.toString(), channelA, [latest.version]);
  if (!stored) throw new Error(`the source must hold HelperA's committed share for v${latest.version}`);
  // The last bytes of a CommittedDeRecShare are its Merkle path's last hash.
  const corrupted = stored.bytes.slice();
  corrupted[corrupted.length - 1] ^= 0xff;
  await source.node.shareStore.save(secretId.toString(), channelA, { ...stored, bytes: corrupted });

  const sourceFp = await source.node.protocol.getFingerprint(rekeyed);
  if (!(await destination.node.protocol.verifyFingerprint(rekeyed, sourceFp))) {
    throw new Error("destination.verifyFingerprint must return true");
  }
  await destination.node.protocol.start(FlowKind.ReplicaDiscovery);
  const catchUp = await pumpAll([destination, source]);
  const refused = catchUp.filter(
    (e): e is Extract<DeRecEvent, { type: "ReplicaSecretRefused" }> => e.type === "ReplicaSecretRefused",
  );
  if (
    refused.length !== 1 ||
    refused[0]!.from_replica_id !== SOURCE_REPLICA_ID.toString() ||
    refused[0]!.version !== latest.version ||
    refused[0]!.status !== StatusEnum.VerificationFailed ||
    refused[0]!.memo.length === 0
  ) {
    throw new Error(`the destination must report one ReplicaSecretRefused(VERIFICATION_FAILED), got ${JSON.stringify(catchUp)}`);
  }
  if (catchUp.some((e) => e.type === "ReplicaSecretInstalled" || e.type === "ReplicaSecretReceived")) {
    throw new Error("a refused copy must not be installed");
  }
  if ((await destination.node.userSecretStore.loadLatest(secretId.toString())) !== null) {
    throw new Error("the destination must write nothing for a refused copy");
  }
  console.log(`  [Destination] catch-up copy with an unverifiable share → ReplicaSecretRefused(status=VERIFICATION_FAILED, memo="${refused[0]!.memo}"), nothing written  ✓`);

  console.log("\n✓ Replica secret refused flow passed.\n");
}

function readVarint(bytes: Uint8Array, start: number): [bigint, number] {
  let value = 0n;
  let shift = 0n;
  for (let pos = start; pos < bytes.length; pos++) {
    const byte = bytes[pos]!;
    value |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) return [value, pos + 1];
    shift += 7n;
  }
  throw new Error("truncated protobuf varint");
}

function writeVarint(value: bigint): number[] {
  const out: number[] = [];
  do {
    let byte = Number(value & 0x7fn);
    value >>= 7n;
    if (value > 0n) byte |= 0x80;
    out.push(byte);
  } while (value > 0n);
  return out;
}

/**
 * Replaces the value of the length-delimited protobuf field `field`, copying
 * every other field's bytes unchanged. No SDK call writes a malformed or
 * tampered message, so the flows that need one edit the wire bytes here.
 */
function rewriteProtoField(
  message: Uint8Array,
  field: number,
  rewrite: (value: Uint8Array) => Uint8Array,
): Uint8Array {
  const out: number[] = [];
  let found = false;
  let pos = 0;
  while (pos < message.length) {
    const [key, afterKey] = readVarint(message, pos);
    const wireType = Number(key & 7n);
    let end: number;
    if (wireType === 0) {
      end = readVarint(message, afterKey)[1];
    } else if (wireType === 1) {
      end = afterKey + 8;
    } else if (wireType === 5) {
      end = afterKey + 4;
    } else if (wireType === 2) {
      const [length, afterLength] = readVarint(message, afterKey);
      end = afterLength + Number(length);
      if (Number(key >> 3n) === field) {
        const value = rewrite(message.slice(afterLength, end));
        out.push(...writeVarint(key), ...writeVarint(BigInt(value.length)), ...value);
        found = true;
        pos = end;
        continue;
      }
    } else {
      throw new Error(`unsupported protobuf wire type ${wireType}`);
    }
    out.push(...message.slice(pos, end));
    pos = end;
  }
  if (!found) throw new Error(`protobuf field ${field} not found`);
  return Uint8Array.from(out);
}

/** `google.protobuf.Timestamp`: `seconds` is field 1, `nanos` field 2. */
function decodeTimestamp(bytes: Uint8Array): { seconds: bigint; nanos: number } {
  let seconds = 0n;
  let nanos = 0;
  let pos = 0;
  while (pos < bytes.length) {
    const [key, afterKey] = readVarint(bytes, pos);
    const [value, next] = readVarint(bytes, afterKey);
    if (key === 0x08n) seconds = value;
    if (key === 0x10n) nanos = Number(value);
    pos = next;
  }
  return { seconds, nanos };
}

function encodeTimestamp(seconds: bigint, nanos: number): Uint8Array {
  const out: number[] = [];
  if (seconds !== 0n) out.push(0x08, ...writeVarint(seconds));
  if (nanos !== 0) out.push(0x10, ...writeVarint(BigInt(nanos)));
  return Uint8Array.from(out);
}

export async function runProtocolSmoke(): Promise<void> {
  console.log("━━━ [Protocol] Starting ━━━\n");

  await runPairingFlow();
  await runPairingRefusalFlow();
  await runFingerprintMismatchFlow();
  await runHashedKeysPairingFlow();
  await runNoKeysPairingFlow();
  runUnsafeConnectionConfigFlow();
  runConfigSurfaceFlow();
  await runWithConfigFlow();
  await runSharingFlow();
  await runWeightedHelpersFlow();
  await runStickyWeightsFlow();
  await runShareSubsharesFlow();
  await runStickyThresholdFlow();
  await runMaxSubsharesFlow();
  await runShareStoreRefusalFlow();
  await runRequestFailedTokenFlow();
  await runShareRefusedFlow();
  await runAutoRespondOnFailureFlow();
  await runInvalidWeightAtStartFlow();
  await runVerifyNoProofFlow();
  await runVerificationResponseVerdictsFlow();
  await runReplicaSecretRefusedFlow();
  await runDiscoveryAndRecoveryFlow();
  await runUnpairingFlow();
  await runUpdateChannelInfoFlow();
  await runReplyToFlow();
  await runReplicaIdWiringSadPathsFlow();
  await runReplicaPairingAndSecretSyncFlow();
  await runUnconfirmedDestinationIgnoresTheCopyFlow();
  await runReplicaSyncVersionProgressionFlow();
  await runAutoAcceptFlow();
  await runExpiredChannelCleanupFlow();

  console.log("━━━ [Protocol] All passed. ━━━\n");
}

// Drives a sharing round with both helpers configured to auto-accept
// `storeShare`. Asserts that each helper's `process(...)` directly
// emits `AutoAccepted` + `ShareStored` (no `ActionRequired` for the
// auto-accepted action), and that the owner still receives
// `ShareConfirmed` from both.
async function runAutoAcceptFlow(): Promise<void> {
  console.log("\n=== [Protocol] Auto-accept flow ===\n");
  const ownerSecretId = 0xAAAAn;
  const policy = { storeShare: true } as const;

  const owner = makeNode("Owner", "https://owner.example.com", {
    secretId: ownerSecretId,
  });
  const helperA = makeNode("HelperA", "https://helper-a.example.com", {
    secretId: ownerSecretId,
    autoAccept: policy,
  });
  const helperB = makeNode("HelperB", "https://helper-b.example.com", {
    secretId: ownerSecretId,
    autoAccept: policy,
  });

  const channelIdA = 1n;
  const channelIdB = 2n;
  await doPair(helperA, owner, channelIdA, "Owner↔HelperA");
  await doPair(helperB, owner, channelIdB, "Owner↔HelperB");

  await owner.protocol.start(FlowKind.ProtectSecret, {
    secrets: [
      { id: new Uint8Array([0xAA]), name: "auto-accept smoke", data: utf8Encode("nodejs-auto-accept") },
    ],
    description: "nodejs auto-accept smoke",
  });
  const outbound = owner.transport.drain();
  if (outbound.length !== 2) {
    throw new Error(`expected 2 StoreShareRequests, got ${outbound.length}`);
  }

  const helpers: Array<[Node, string]> = [
    [helperA, "HelperA"],
    [helperB, "HelperB"],
  ];
  for (let i = 0; i < outbound.length; i++) {
    const request = outbound[i]!.message;
    const [helper, hLabel] = helpers[i]!;
    // With auto-accept on, plain process(...) returns AutoAccepted +
    // ShareStored directly — no follow-up accept() call is needed.
    const helperEvents = await helper.protocol.process(request);

    const autoAccepted = requireEvent(helperEvents, "AutoAccepted", hLabel);
    if (autoAccepted.action_kind !== "StoreShare") {
      throw new Error(
        `${hLabel}: AutoAccepted.action_kind=${autoAccepted.action_kind}; expected "StoreShare"`,
      );
    }
    if (helperEvents.find((e: DeRecEvent) => e.type === "ActionRequired")) {
      throw new Error(`${hLabel}: auto-accept should suppress ActionRequired; got one anyway`);
    }
    const stored = requireEvent(helperEvents, "ShareStored", hLabel);

    const response = drainOne(helper, hLabel);
    const ownerEvents = await owner.protocol.process(response);
    const confirmed = requireEvent(ownerEvents, "ShareConfirmed", "Owner");
    console.log(`  [${hLabel}] AutoAccepted(StoreShare) → ShareStored(v=${stored.version}) → ShareConfirmed(v=${confirmed.version})  ✓`);
  }

  console.log("\n✓ Auto-accept flow passed.\n");
}

/**
 * Walks the canonical 0→8 sequence that proves the multi-device sync
 * invariant: every roster change or user-secret update bumps the
 * secret version, every paired Replica Destination receives the fresh
 * snapshot, and Helpers only receive VSS shares once the threshold
 * is met.
 *
 * 0. new()                                          → user_secret_store empty
 * 1. pair replica A                                 → v=1, replicas=1
 * 2. ProtectSecret([s1])                            → v=2, secrets=1
 * 3. pair replica B (bootstrap with s1)             → v=3, replicas=2
 * 4. pair helper #1 (below threshold)               → v=4, helpers=1
 * 5. pair helper #2 (below threshold)               → v=5, helpers=2
 * 6. ProtectSecret([s1, s2])                        → v=6, secrets=2
 * 7. pair helper #3 (threshold met, VSS split)      → v=7, helpers=3 + shares
 * 8. pair replica C (full bootstrap + fresh shares) → v=8, replicas=3 + shares
 */
async function runReplicaSyncVersionProgressionFlow(): Promise<void> {
  console.log("\n=== [Protocol] Replica sync — version progression v0→v8 ===\n");

  const PROTECTED_SECRET_ID = 0xABBAn;
  const TH = 3;
  const OWNER_URI = "https://owner.example.com";
  const REPLICA_A_URI = "https://replica-a.example.com";
  const REPLICA_B_URI = "https://replica-b.example.com";
  const REPLICA_C_URI = "https://replica-c.example.com";
  const HELPER_1_URI = "https://helper-1.example.com";
  const HELPER_2_URI = "https://helper-2.example.com";
  const HELPER_3_URI = "https://helper-3.example.com";

  const owner = makeNode("Owner", OWNER_URI, {
    secretId: PROTECTED_SECRET_ID,
    threshold: TH,
    replicaId: 0x0001n,
  });
  const replicaA = makeNode("ReplicaA", REPLICA_A_URI, {
    secretId: PROTECTED_SECRET_ID,
    threshold: TH,
    replicaId: 0x000An,
  });
  const replicaB = makeNode("ReplicaB", REPLICA_B_URI, {
    secretId: PROTECTED_SECRET_ID,
    threshold: TH,
    replicaId: 0x000Bn,
  });
  const replicaC = makeNode("ReplicaC", REPLICA_C_URI, {
    secretId: PROTECTED_SECRET_ID,
    threshold: TH,
    replicaId: 0x000Cn,
  });
  const helper1 = makeNode("Helper1", HELPER_1_URI, {
    secretId: PROTECTED_SECRET_ID,
    threshold: TH,
  });
  const helper2 = makeNode("Helper2", HELPER_2_URI, {
    secretId: PROTECTED_SECRET_ID,
    threshold: TH,
  });
  const helper3 = makeNode("Helper3", HELPER_3_URI, {
    secretId: PROTECTED_SECRET_ID,
    threshold: TH,
  });

  const ownerEntry = { node: owner, uri: OWNER_URI };
  const replicaAEntry = { node: replicaA, uri: REPLICA_A_URI };
  const replicaBEntry = { node: replicaB, uri: REPLICA_B_URI };
  const replicaCEntry = { node: replicaC, uri: REPLICA_C_URI };
  const helper1Entry = { node: helper1, uri: HELPER_1_URI };
  const helper2Entry = { node: helper2, uri: HELPER_2_URI };
  const helper3Entry = { node: helper3, uri: HELPER_3_URI };
  const replicaScope = [ownerEntry, replicaAEntry, replicaBEntry, replicaCEntry];
  const allScope = [
    ownerEntry,
    replicaAEntry,
    replicaBEntry,
    replicaCEntry,
    helper1Entry,
    helper2Entry,
    helper3Entry,
  ];

  const cidA = 1n;
  const cidB = 3n;
  const cidC = 8n;
  const cidH1 = 11n;
  const cidH2 = 12n;
  const cidH3 = 13n;

  // Channel-id rekey rotates the transient contact id to a fresh
  // long-term id at PairingCompleted. Track the mapping so downstream
  // event lookups (findReplicaEvent, ShareStored matches, fingerprint
  // verification) target the id that actually resolves in the stores.
  const rekeyed = new Map<bigint, bigint>();
  const rk = (cid: bigint): bigint => {
    const r = rekeyed.get(cid);
    if (r === undefined) throw new Error(`no rekeyed id for transient cid=${cid}`);
    return r;
  };
  const captureRekey = (events: DeRecEvent[]) => {
    for (const ev of events) {
      if (ev.type === "PairingCompleted") {
        rekeyed.set(BigInt(ev.pairing_channel_id), BigInt(ev.channel_id));
      }
    }
  };

  // Step 0 — brand-new instance.
  if ((await owner.userSecretStore.loadLatest(PROTECTED_SECRET_ID.toString())) !== null) {
    throw new Error("step 0: brand-new instance must have no user_secrets snapshot");
  }
  console.log("  step 0: user_secret_store latest = null  ✓");

  // Step 1 — pair replica A → v=1.
  const { rekeyed: rekA } = await pairReplicaHandshake(ownerEntry, replicaAEntry, cidA);
  rekeyed.set(cidA, rekA);
  await crossConfirmFingerprintAt(ownerEntry, replicaAEntry, rk(cidA));
  let events = await pumpAll(replicaScope);
  captureRekey(events);
  let recvA = findReplicaEvent(events, rk(cidA));
  if (!recvA) throw new Error("step 1: A must observe a sync");
  if (!recvA.installed) throw new Error("step 1: A had no snapshot, so this installs the secret");
  if (recvA.version !== 1) throw new Error(`step 1: expected v=1, got ${recvA.version}`);
  if (recvA.secret.helpers.length !== 0) throw new Error("step 1: helpers must be empty");
  if (recvA.secret.secrets.length !== 0) throw new Error("step 1: secrets must be empty");
  if ((recvA.secret.replicas?.members.length ?? 0) !== 2) throw new Error("step 1: roster must be 2 (source + A)");
  if (recvA.shares.length !== 0) throw new Error("step 1: shares must be empty");
  await assertLatestVersion(owner, PROTECTED_SECRET_ID, 1);
  console.log("  step 1: pair replica A → v=1, secret(h=0,s=0,r=1,shares=0)  ✓");

  // Step 2 — ProtectSecret([s1]) → v=2.
  const s1 = { id: new Uint8Array([0x01]), name: "secret-one", data: utf8Encode("first-user-secret") };
  await owner.protocol.start(FlowKind.ProtectSecret, {
    secrets: [s1],
    description: "v=2 explicit publish",
  });
  events = await pumpAll(replicaScope);
  captureRekey(events);
  recvA = findReplicaEvent(events, rk(cidA));
  if (!recvA || recvA.version !== 2) {
    throw new Error(`step 2: A must observe v=2, got ${recvA?.version}`);
  }
  const recvA2Secret = recvA.secret.secrets[0];
  if (recvA.secret.secrets.length !== 1 || !recvA2Secret || !equalBytes(recvA2Secret.data, s1.data)) {
    throw new Error("step 2: secret.secrets[0].data must equal s1");
  }
  if ((recvA.secret.replicas?.members.length ?? 0) !== 2) throw new Error("step 2: roster must be 2 (source + A)");
  if (recvA.shares.length !== 0) throw new Error("step 2: shares must be empty");
  await assertLatestVersion(owner, PROTECTED_SECRET_ID, 2);
  console.log("  step 2: ProtectSecret([s1]) → v=2, secret(h=0,s=1,r=1,shares=0)  ✓");

  // Step 3 — pair replica B → v=3 (B bootstraps with s1).
  const { rekeyed: rekB } = await pairReplicaHandshake(ownerEntry, replicaBEntry, cidB);
  rekeyed.set(cidB, rekB);
  await crossConfirmFingerprintAt(ownerEntry, replicaBEntry, rk(cidB));
  events = await pumpAll(replicaScope);
  captureRekey(events);
  recvA = findReplicaEvent(events, rk(cidA));
  const recvB = findReplicaEvent(events, rk(cidB));
  if (!recvA || recvA.version !== 3) throw new Error(`step 3: A must observe v=3`);
  if (!recvB || recvB.version !== 3) throw new Error(`step 3: B must observe v=3 (bootstrap)`);
  for (const [label, recv] of [["A", recvA], ["B", recvB]] as const) {
    if (recv.secret.helpers.length !== 0) throw new Error(`step 3 ${label}: helpers must be empty`);
    const secret = recv.secret.secrets[0];
    if (recv.secret.secrets.length !== 1 || !secret || !equalBytes(secret.data, s1.data)) {
      throw new Error(`step 3 ${label}: secret must still carry s1`);
    }
    if ((recv.secret.replicas?.members.length ?? 0) !== 3) throw new Error(`step 3 ${label}: roster must be 3`);
    if (recv.shares.length !== 0) throw new Error(`step 3 ${label}: shares must be empty`);
  }
  await assertLatestVersion(owner, PROTECTED_SECRET_ID, 3);
  console.log("  step 3: pair replica B → v=3, secret(h=0,s=1,r=2,shares=0) on A+B  ✓");

  // Step 4 — pair helper #1 → v=4 (below threshold).
  await helperStartPairAt(ownerEntry, helper1Entry, cidH1);
  events = await pumpAll(allScope);
  captureRekey(events);
  if (events.some((e) => e.type === "ShareStored")) {
    throw new Error("step 4: no helper may store a share (1 < threshold 3)");
  }
  await assertHydrated(replicaAEntry.node, PROTECTED_SECRET_ID, "A", 4, 1, 1, 3);
  await assertHydrated(replicaBEntry.node, PROTECTED_SECRET_ID, "B", 4, 1, 1, 3);
  await assertLatestVersion(owner, PROTECTED_SECRET_ID, 4);
  console.log("  step 4: pair helper #1 → v=4, secret(h=1,s=1,r=2,shares=0)  ✓");

  // Step 5 — pair helper #2 → v=5.
  await helperStartPairAt(ownerEntry, helper2Entry, cidH2);
  events = await pumpAll(allScope);
  captureRekey(events);
  if (events.some((e) => e.type === "ShareStored")) {
    throw new Error("step 5: still below threshold");
  }
  await assertHydrated(replicaAEntry.node, PROTECTED_SECRET_ID, "A", 5, 2, 1, 3);
  await assertHydrated(replicaBEntry.node, PROTECTED_SECRET_ID, "B", 5, 2, 1, 3);
  await assertLatestVersion(owner, PROTECTED_SECRET_ID, 5);
  console.log("  step 5: pair helper #2 → v=5, secret(h=2,s=1,r=2,shares=0)  ✓");

  // Step 6 — ProtectSecret([s1, s2]) → v=6.
  const s2 = { id: new Uint8Array([0x02]), name: "secret-two", data: utf8Encode("second-user-secret") };
  await owner.protocol.start(FlowKind.ProtectSecret, {
    secrets: [s1, s2],
    description: "v=6 explicit publish",
  });
  events = await pumpAll(allScope);
  captureRekey(events);
  if (events.some((e) => e.type === "ShareStored")) {
    throw new Error("step 6: still below threshold");
  }
  await assertHydrated(replicaAEntry.node, PROTECTED_SECRET_ID, "A", 6, 2, 2, 3);
  await assertHydrated(replicaBEntry.node, PROTECTED_SECRET_ID, "B", 6, 2, 2, 3);
  // Both user secrets reached the destination, not just the count.
  const snapshotA = await replicaAEntry.node.userSecretStore.loadLatest(
    PROTECTED_SECRET_ID.toString(),
  );
  if (!snapshotA?.secrets.some((u) => equalBytes(u.data, s1.data))) {
    throw new Error("step 6: A's snapshot must carry s1");
  }
  if (!snapshotA?.secrets.some((u) => equalBytes(u.data, s2.data))) {
    throw new Error("step 6: A's snapshot must carry s2");
  }
  await assertLatestVersion(owner, PROTECTED_SECRET_ID, 6);
  console.log("  step 6: ProtectSecret([s1, s2]) → v=6, secret(h=2,s=2,r=2,shares=0)  ✓");

  // Step 7 — pair helper #3 → v=7, threshold met, VSS split runs.
  await helperStartPairAt(ownerEntry, helper3Entry, cidH3);
  events = await pumpAll(allScope);
  captureRekey(events);
  for (const [label, cid] of [["helper-1", cidH1], ["helper-2", cidH2], ["helper-3", cidH3]] as const) {
    const stored = events.some(
      (e) => e.type === "ShareStored" && BigInt(e.channel_id) === rk(cid) && e.version === 7,
    );
    if (!stored) throw new Error(`step 7: ${label} must emit ShareStored at v=7`);
  }
  await assertHydrated(replicaAEntry.node, PROTECTED_SECRET_ID, "A", 7, 3, 2, 3);
  await assertHydrated(replicaBEntry.node, PROTECTED_SECRET_ID, "B", 7, 3, 2, 3);
  await assertLatestVersion(owner, PROTECTED_SECRET_ID, 7);
  console.log("  step 7: pair helper #3 → v=7, secret(h=3,s=2,r=2,shares=3); all 3 helpers ShareStored  ✓");

  // Step 8 — pair replica C → v=8, full bootstrap + fresh helper VSS.
  const { rekeyed: rekC } = await pairReplicaHandshake(ownerEntry, replicaCEntry, cidC);
  rekeyed.set(cidC, rekC);
  await crossConfirmFingerprintAt(ownerEntry, replicaCEntry, rk(cidC));
  events = await pumpAll(allScope);
  captureRekey(events);
  for (const [label, cid] of [["helper-1", cidH1], ["helper-2", cidH2], ["helper-3", cidH3]] as const) {
    const stored = events.some(
      (e) => e.type === "ShareStored" && BigInt(e.channel_id) === rk(cid) && e.version === 8,
    );
    if (!stored) throw new Error(`step 8: ${label} must emit ShareStored at v=8`);
  }
  const recvC = findReplicaEvent(events, rk(cidC));
  if (!recvC || recvC.version !== 8) throw new Error(`step 8: C must observe v=8`);
  if (!recvC.installed) throw new Error("step 8: C is new to the secret, so this installs it");
  if (recvC.shares.length !== 3) throw new Error("step 8 C: shares must be 3");
  await assertHydrated(replicaAEntry.node, PROTECTED_SECRET_ID, "A", 8, 3, 2, 4);
  await assertHydrated(replicaBEntry.node, PROTECTED_SECRET_ID, "B", 8, 3, 2, 4);
  await assertHydrated(replicaCEntry.node, PROTECTED_SECRET_ID, "C", 8, 3, 2, 4);
  await assertLatestVersion(owner, PROTECTED_SECRET_ID, 8);
  console.log("  step 8: pair replica C → v=8, secret(h=3,s=2,r=3,shares=3) on A+B+C; all helpers refreshed  ✓");

  console.log("\n✓ Replica sync version progression flow passed.");
}

async function assertLatestVersion(owner: Node, secretId: bigint, expected: number) {
  const snapshot = await owner.userSecretStore.loadLatest(secretId.toString());
  if (!snapshot || snapshot.version !== expected) {
    throw new Error(
      `expected user_secret_store version=${expected}, got ${snapshot?.version}`,
    );
  }
}

async function runUnconfirmedDestinationIgnoresTheCopyFlow(): Promise<void> {
  console.log("\n=== [Protocol] Unconfirmed replica destination ===\n");

  const source = {
    node: makeNode("Source", "https://source.example.com", { replicaId: 0x5050_5050n }),
    uri: "https://source.example.com",
  };
  const destination = {
    node: makeNode("Destination", "https://destination.example.com", { replicaId: 0xde57_de57n }),
    uri: "https://destination.example.com",
  };

  const { rekeyed } = await pairReplicaHandshake(source, destination, 31n);
  const destinationFp = await destination.node.protocol.getFingerprint(rekeyed);
  if (!(await source.node.protocol.verifyFingerprint(rekeyed, destinationFp))) {
    throw new Error("source.verifyFingerprint must return true");
  }

  const early = await pumpAll([source, destination]);
  const ignored = early.find(
    (e) =>
      e.type === "MessageIgnored" &&
      e.reason === "PendingVerification" &&
      BigInt(e.channel_id) === rekeyed,
  );
  if (!ignored) {
    throw new Error(
      `a copy sent before the destination confirms must be ignored, got [${early.map((e) => e.type).join(", ")}]`,
    );
  }
  if (
    early.some(
      (e) =>
        e.type === "ReplicaSecretInstalled" ||
        e.type === "ReplicaSecretReceived" ||
        e.type === "ReplicaSecretAcked",
    )
  ) {
    throw new Error("nothing may be installed or acknowledged before the destination confirms");
  }
  console.log("  copy sent before the destination confirmed was ignored  ✓");

  const sourceFp = await source.node.protocol.getFingerprint(rekeyed);
  if (!(await destination.node.protocol.verifyFingerprint(rekeyed, sourceFp))) {
    throw new Error("destination.verifyFingerprint must return true");
  }
  await destination.node.protocol.start(FlowKind.ReplicaDiscovery);
  const catchUp = await pumpAll([destination, source]);
  if (!catchUp.some((e) => e.type === "ReplicaSecretInstalled")) {
    throw new Error(
      `after confirming, ReplicaDiscovery must install the copy, got [${catchUp.map((e) => e.type).join(", ")}]`,
    );
  }
  console.log("  destination pulled the copy with ReplicaDiscovery after confirming  ✓");

  console.log("\n✓ Unconfirmed replica destination flow passed.\n");
}

async function pairReplicaHandshake(
  owner: AddressedNode,
  replica: AddressedNode,
  channelId: bigint,
): Promise<{ rekeyed: bigint }> {
  const contact = await owner.node.protocol.createContact(
    channelId,
    ContactMode.InlineKeys,
  );
  await replica.node.protocol.start(FlowKind.Pairing, {
    kind: SenderKind.ReplicaDestination,
    contact,
  });
  const events = await pumpAll([owner, replica]);
  // Both sides' PairingCompleted echo `pairing_channel_id === contact.channel_id`;
  // the rotated long-term id is on `channel_id`. Filter by pairing_channel_id
  // so we pick THIS handshake even if other pairs are happening on the same peers.
  const completed = events.find(
    (e) =>
      e.type === "PairingCompleted" &&
      BigInt(e.pairing_channel_id) === channelId,
  );
  if (!completed || completed.type !== "PairingCompleted") {
    throw new Error(
      `pairReplicaHandshake(cid=${channelId}): missing PairingCompleted with matching pairing_channel_id`,
    );
  }
  return { rekeyed: BigInt(completed.channel_id) };
}

async function crossConfirmFingerprint(owner: Node, replica: Node, channelId: bigint) {
  const ownerFp = await owner.protocol.getFingerprint(channelId);
  const replicaFp = await replica.protocol.getFingerprint(channelId);
  if (ownerFp !== replicaFp) {
    throw new Error(`fingerprint mismatch: owner=${ownerFp} replica=${replicaFp}`);
  }
  if (!(await owner.protocol.verifyFingerprint(channelId, replicaFp))) {
    throw new Error("owner.verifyFingerprint must return true");
  }
  if (!(await replica.protocol.verifyFingerprint(channelId, ownerFp))) {
    throw new Error("replica.verifyFingerprint must return true");
  }
}

async function helperStartPair(owner: Node, helper: Node, channelId: bigint) {
  const contact = await owner.protocol.createContact(channelId, ContactMode.InlineKeys);
  await helper.protocol.start(FlowKind.Pairing, {
    kind: SenderKind.Helper,
    contact,
  });
}

/** Convenience: pass `AddressedNode` so the test body reads uniformly. */
async function crossConfirmFingerprintAt(
  owner: AddressedNode,
  replica: AddressedNode,
  channelId: bigint,
) {
  await crossConfirmFingerprint(owner.node, replica.node, channelId);
}

async function helperStartPairAt(
  owner: AddressedNode,
  helper: AddressedNode,
  channelId: bigint,
) {
  await helperStartPair(owner.node, helper.node, channelId);
}

/**
 * Drain every node's outbox and route each message to whichever node
 * owns the destination URI, recursing until the network goes silent.
 * URIs must be unique across the input slice.
 */
type AddressedNode = { node: Node; uri: string };

async function pumpAll(entries: AddressedNode[]): Promise<DeRecEvent[]> {
  const collected: DeRecEvent[] = [];
  for (;;) {
    let progressed = false;
    for (const src of entries) {
      const messages = src.node.transport.drain();
      for (const m of messages) {
        const dest = entries.find((e) => e.uri === m.endpoint.uri);
        if (!dest) {
          throw new Error(
            `pumpAll: no peer for destination uri ${m.endpoint.uri}`,
          );
        }
        const events = await processAll(dest.node, m.message);
        collected.push(...events);
        progressed = true;
      }
    }
    if (!progressed) return collected;
  }
}


/**
 * Assert a replica hydrated a round: its own snapshot and stores now match
 * what the source published.
 *
 * Checked against the peer's stores rather than its events because members
 * share one group channel once they have hydrated — the arrival channel no
 * longer identifies who received what, and the stores are the thing the group
 * model actually promises.
 */
async function assertHydrated(
  peer: { userSecretStore: InMemoryUserSecretStore; channelStore: InMemoryChannelStore },
  secretId: bigint,
  label: string,
  version: number,
  helpers: number,
  secrets: number,
  members: number,
): Promise<void> {
  const sid = secretId.toString();
  const snapshot = await peer.userSecretStore.loadLatest(sid);
  if (!snapshot) throw new Error(`replica ${label} must hold a snapshot`);
  if (snapshot.version !== version) {
    throw new Error(`replica ${label} must hold v=${version}, got ${snapshot.version}`);
  }
  if ((snapshot.secrets?.length ?? 0) !== secrets) {
    throw new Error(
      `replica ${label} secret count: expected ${secrets}, got ${snapshot.secrets?.length ?? 0}`,
    );
  }

  const storedHelpers = JSON.parse(
    utf8Decode(await peer.channelStore.listHelpers(sid, ANY_HELPERS)),
  );
  if (storedHelpers.length !== helpers) {
    throw new Error(
      `replica ${label} must have materialised ${helpers} helper channel(s), got ${storedHelpers.length}`,
    );
  }

  const roster = JSON.parse(
    utf8Decode(await peer.channelStore.listReplicas(sid, ANY_REPLICAS)),
  );
  if (roster.length !== members) {
    throw new Error(`replica ${label} roster size: expected ${members}, got ${roster.length}`);
  }
  const sources = roster.filter((m: { role: string }) => m.role === "Source").length;
  if (sources !== 1) {
    throw new Error(`replica ${label} roster must name exactly one source, got ${sources}`);
  }
}

/**
 * Look up the sync event for a channel.
 *
 * Matches both arrival events and records which fired: a device's first sync
 * for a `secret_id` installs the secret, every later one updates it.
 */
function findReplicaEvent(events: DeRecEvent[], channelId: bigint) {
  for (const ev of events) {
    if (
      (ev.type === "ReplicaSecretReceived" || ev.type === "ReplicaSecretInstalled") &&
      BigInt(ev.channel_id) === channelId
    ) {
      return {
        version: ev.version,
        secret: ev.secret,
        shares: ev.shares,
        installed: ev.type === "ReplicaSecretInstalled",
      };
    }
  }
  return undefined;
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}


// Exercises the expired-channel cleanup surface.
//
// The contradictory pair — `enabled: false` alongside a non-zero timeout —
// is the point: the wrapper must forward both values verbatim and let the
// library decide that a disabled policy ignores its timeout. A wrapper that
// interpreted the flag locally (dropping the timeout, or substituting its
// own default) would still pass a happy-path test, so the config is chosen
// to fail if any interpretation crept into the JS layer.
async function runExpiredChannelCleanupFlow(): Promise<void> {
  console.log("[Protocol] expired-channel cleanup");

  const builder = new DeRecProtocolBuilder(DEFAULT_TEST_SECRET_ID)
    .withChannelStore(new InMemoryChannelStore())
    .withShareStore(new InMemoryShareStore())
    .withSecretStore(new InMemorySecretStore())
    .withUserSecretStore(new InMemoryUserSecretStore())
    .withStateStore(new InMemoryStateStore())
    .withTransport(new RecordingTransport())
    .withOwnTransports([{ uri: "https://cleanup.example.com", protocol: "https" }])
    .withThreshold(THRESHOLD)
    .withTimeouts({ expired_channels: { enabled: false, timeout_in_secs: 900 } });
  const protocol = builder.build();

  // The caller-driven sweep works regardless of the disabled policy — that
  // is what disabled means. No pending channels exist yet, so the result is
  // an empty array rather than an error.
  const removed = await protocol.removeExpiredChannels(0);
  if (!Array.isArray(removed) || removed.length !== 0) {
    throw new Error(
      `expected no removed channels on a fresh protocol, got ${JSON.stringify(removed)}`,
    );
  }

  console.log("  cleanup: disabled policy forwarded with its timeout; manual sweep callable ✓");
}


/**
 * Compile-time proof that both new flows are reachable from TypeScript without
 * widening `start`.
 *
 * `ReplicaDiscovery` (7) and `UnpairReplica` (8) were in the `FlowKind` enum and
 * accepted at runtime, but `start` declared overloads only up to kind 6, so
 * dispatching them meant casting to a looser signature. This function is never
 * called — it exists so `tsc` fails if those overloads are dropped again.
 */
export function _startOverloadsCoverEveryFlowKind(protocol: DeRecProtocol): void {
  void (() => protocol.start(FlowKind.ReplicaDiscovery));
  void (() => protocol.start(FlowKind.ReplicaDiscovery, {}));
  void (() =>
    protocol.start(FlowKind.UnpairReplica, {
      replica_id: "51966",
      memo: "retired device",
    }));
  void (() => protocol.start(FlowKind.UnpairReplica, { replica_id: "51966" }));
}

/**
 * `unsafeConnection` must survive the WASM boundary and actually change behaviour.
 *
 * Its own test because the failure is silent: an unset field on the Rust side
 * defaults to `false`, so a name mismatch would make the setting a no-op with
 * every other test still green — the same shape as the enum variants that
 * were declared in `index.d.ts` but `undefined` at run time.
 */
export function runUnsafeConnectionConfigFlow(): void {
  console.log("=== [Protocol] unsafe_connection config ===\n");

  const builds = (uri: string, unsafeConnection: boolean): boolean => {
    try {
      makeNode("Dev", uri, { unsafeConnection });
      return true;
    } catch {
      return false;
    }
  };

  if (!builds("http://127.0.0.1:8080", false)) {
    throw new Error("loopback plaintext must build with unsafeConnection=false");
  }
  console.log("  loopback http accepted with unsafeConnection=false  ✓");

  if (builds("http://192.168.1.42:8080", false)) {
    throw new Error("LAN plaintext must be refused with unsafeConnection=false");
  }
  console.log("  LAN http refused with unsafeConnection=false  ✓");

  if (!builds("http://192.168.1.42:8080", true)) {
    throw new Error(
      "LAN plaintext must build with unsafeConnection=true — the setting is not reaching the library",
    );
  }
  console.log("  LAN http accepted with unsafeConnection=true  ✓");

  console.log("\n✓ unsafe_connection config passed.\n");
}

/**
 * The config knobs and validation rules an application reaches through this
 * SDK. Each crosses the FFI as a JSON field, where a name mismatch would
 * silently drop the setting rather than fail — so each assertion here is
 * checking the value actually arrived.
 */
export function runConfigSurfaceFlow(): void {
  console.log("=== [Protocol] config surface ===\n");

  const base = () =>
    new DeRecProtocolBuilder(DEFAULT_TEST_SECRET_ID)
      .withChannelStore(new InMemoryChannelStore())
      .withShareStore(new InMemoryShareStore())
      .withSecretStore(new InMemorySecretStore())
      .withUserSecretStore(new InMemoryUserSecretStore())
      .withStateStore(new InMemoryStateStore())
      .withTransport(new RecordingTransport())
      .withThreshold(THRESHOLD);

  // ParameterRange reaches the library. Bounds that cannot intersect any peer
  // range would still build — this proves only that the field is carried,
  // which is what no SDK could do before it was declared.
  base()
    .withOwnTransports([{ uri: "https://owner.example.com", protocol: "https" }])
    .withParameterRange({
      min_share_size: 1n,
      max_share_size: 1n << 20n,
      min_time_between_verifications: 1n,
      max_time_between_verifications: 3600n,
    })
    .build();
  console.log("  withParameterRange accepted  ✓");

  // A device serves at most one endpoint per protocol: two HTTPS entries
  // contradict rather than extend, so the set is refused even though each
  // entry is individually well-formed.
  let refused = false;
  try {
    base()
      .withOwnTransports([
        { uri: "https://a.example", protocol: "https" },
        { uri: "https://b.example", protocol: "https" },
      ])
      .build();
  } catch {
    refused = true;
  }
  if (!refused) {
    throw new Error(
      "two endpoints of one protocol must be refused — the one-per-protocol rule is not reaching the library",
    );
  }
  console.log("  two endpoints of one protocol refused  ✓");

  // Distinct protocols are what the list is for.
  base()
    .withOwnTransports([
      { uri: "https://a.example", protocol: "https" },
      { uri: "grpcs://a.example:443", protocol: "grpc" },
    ])
    .build();
  console.log("  distinct protocols accepted  ✓");

  console.log("\n✓ config surface passed.\n");
}

/**
 * `withConfig` end to end: the shared fixture's full config builds a
 * protocol that runs an existing flow. This binding validates nothing of
 * its own — a misspelled key, or an array (whose entries surface as
 * unrecognized numeric-string keys), is forwarded into the same config JSON
 * `build()` sends to `protocol_new`, and the library's `deny_unknown_fields`
 * is what refuses it.
 */
async function runWithConfigFlow(): Promise<void> {
  console.log("=== [Protocol] withConfig ===\n");

  const base = () =>
    new DeRecProtocolBuilder(DEFAULT_TEST_SECRET_ID)
      .withChannelStore(new InMemoryChannelStore())
      .withShareStore(new InMemoryShareStore())
      .withSecretStore(new InMemorySecretStore())
      .withUserSecretStore(new InMemoryUserSecretStore())
      .withStateStore(new InMemoryStateStore())
      .withTransport(new RecordingTransport());

  const protocol = base().withConfig(protocolConfigFixtures.full as DeRecProtocolConfig).build();
  const events = await protocol.start(FlowKind.Discovery, {});
  if (!Array.isArray(events)) {
    throw new Error("start(Discovery) on a withConfig-built protocol must return an event array");
  }
  console.log("  the fixture's full config builds and runs Discovery  ✓");

  let misspelled: { code?: string; message?: string } | null = null;
  try {
    base().withConfig({ treshold: 3 } as unknown as DeRecProtocolConfig).build();
  } catch (e) {
    misspelled = e as { code?: string; message?: string };
  }
  if (!misspelled?.message?.includes("unknown field")) {
    throw new Error(
      `a misspelled withConfig key must reach the library and be refused, got code=${misspelled?.code} message=${misspelled?.message}`,
    );
  }
  console.log("  a misspelled withConfig key reaches the library and is refused  ✓");

  let arrayError: { code?: string; message?: string } | null = null;
  try {
    base().withConfig([1, 2, 3] as unknown as DeRecProtocolConfig).build();
  } catch (e) {
    arrayError = e as { code?: string; message?: string };
  }
  if (!arrayError?.message?.includes("unknown field")) {
    throw new Error(
      `an array passed to withConfig must be refused by the library, got code=${arrayError?.code} message=${arrayError?.message}`,
    );
  }
  console.log("  an array passed to withConfig is refused  ✓");

  console.log("\n✓ withConfig passed.\n");
}

/**
 * Apply a listing filter to one stored record.
 *
 * Empty means "do not restrict", `exclude` is applied last, and the
 * restrictions combine with AND — the contract the core documents on
 * `ChannelFilter`. A store that ignores this still compiles; it would just
 * ship rows the core asked it not to.
 */
function matchesFilter(
  filter: HelperFilter | ReplicaFilter,
  id: string,
  body: string,
  variant: "Helper" | "Replica",
): boolean {
  // Parsed only to read the two enum fields; the caller emits `body` itself.
  const record = JSON.parse(body) as {
    status?: string;
    role?: string;
    peer_role?: string;
  };
  const role = (variant === "Helper" ? record.peer_role : record.role) ?? "";
  // The SDK ships this predicate so every store need not re-derive the
  // empty-means-unrestricted / exclude-after-ids rules.
  return channelFilterMatches(
    filter,
    id,
    (record.status ?? "Paired") as ChannelStatusName,
    role as SenderKindName | ReplicaRoleName,
  );
}
