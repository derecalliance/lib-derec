// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.
// Protocol smoke tests: exercises pairing, sharing, and discovery+recovery
// using the low-level `DeRecProtocol` runtime (`start` / `process` / `accept`)
// backed by in-memory stores.
// No UI: every `ActionRequired` event a peer receives is auto-accepted via
// `processAll`. The store implementations track channel links as a graph and
// resolve them by BFS closure, key shares for lookup, and record transport
// calls for assertions; they are Map-backed instead of localStorage-backed.

import { channelFilterMatches, ContactMode, DeRecProtocol, DeRecProtocolBuilder, envelope, FlowKind, SenderKind, StatusEnum, generate_replica_id, primitives, shareStoreRefusal } from "@derec-alliance/web";
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
  RecoveryHelper,
  SecretStore,
  SenderKindName,
  Share,
  ShareStore,
  StateStore,
  Transport,
  UserSecretStore,
  UserSecrets,
} from "@derec-alliance/web";
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


// Keyed by `${secretId}:${channelId}:${kind}`.
class InMemorySecretStore implements SecretStore {
  private readonly data = new Map<string, Uint8Array>();

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
      const text = new TextDecoder().decode(v);
      if (!text.startsWith(tag)) continue;
      const body = text.slice(tag.length, -1);
      const id = k.slice(prefix.length);
      if (!matchesFilter(filter, id, body, variant)) continue;
      inner.push(body);
    }
    return new TextEncoder().encode(`[${inner.join(",")}]`);
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

  keep: number | null = null;
  readonly keepVersionCalls: Array<{ secretId: string; version: number }> = [];

  async keepVersion(secretId: string, version: number): Promise<number> {
    this.keepVersionCalls.push({ secretId, version });
    return this.keep ?? version - 1;
  }

  async latestVersion(secretId: string): Promise<number | null> {
    return this.ownerVersions.get(secretId) ?? null;
  }

  setOwnerVersion(secretId: string, version: number): void {
    this.ownerVersions.set(secretId, version);
  }

  /** Refuse with `too_frequent`, the way an app's rate limit would. */
  refuseSaves = false;
  refuseVerifications = false;
  /** Fail every save with a plain error, the way an unavailable backend would. */
  failSaves = false;

  async recordVerification(): Promise<void> {
    if (this.refuseVerifications) throw shareStoreRefusal("too_frequent");
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
    return JSON.parse(new TextDecoder().decode(bytes));
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

  async loadAll(secretId: string, kind: 0 | 1 | 2 | 3): Promise<Uint8Array[]> {
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
  private readonly failingUris = new Set<string>();

  /** Every later send to `uri` rejects, as a broken link would. */
  failUri(uri: string): void {
    this.failingUris.add(uri);
  }

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
    if (this.failingUris.has(endpoint.uri)) {
      throw new Error("simulated transport failure");
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
    autoAccept?: import("@derec-alliance/web").AutoAcceptPolicy;
    replicaId?: bigint;
    secretId?: bigint;
    threshold?: number;
    /** Leave `withThreshold` uncalled so the library default applies. */
    omitThreshold?: boolean;
    unsafeConnection?: boolean;
    maxSubshares?: bigint;
    parameterRange?: Partial<ParameterRange>;
    channelStore?: InMemoryChannelStore;
    autoRespondOnFailure?: boolean;
    timeouts?: import("@derec-alliance/web").Timeouts;
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
    .withCommunicationInfo({ name });
  if (!options.omitThreshold) {
    builder = builder.withThreshold(options.threshold ?? THRESHOLD);
  }
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
  if (options.timeouts !== undefined) {
    builder = builder.withTimeouts(options.timeouts);
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
      assertBytes(ev.action, "ActionRequired.action");
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
  // Both peers rotate to the same long-term id at handshake completion —
  // return it so downstream assertions can key on it instead of the
  // transient pairing_channel_id, which is removed once the rekey lands.
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

  await doPair(helper, owner, 1n, "Pairing");

  console.log("\n✓ Pairing flow passed.\n");
}


/**
 * `verifyFingerprint(wrong)` on a still-`Pending` channel is the
 * man-in-the-middle case: it must reject with `fingerprint_mismatch` and
 * revoke the pairing, so neither the member record nor the channel key
 * survives.
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
    new TextEncoder().encode(JSON.stringify(channelJson)),
  );
  await node.secretStore.save(nodeSid, String(channelId), 0, sharedKey);

  let caught: { code?: string; category?: string; channel_id?: string } | null = null;
  try {
    await node.protocol.verifyFingerprint(channelId, "0000-0000-0000-0000");
  } catch (e) {
    caught = e as { code?: string; category?: string; channel_id?: string };
  }
  if (caught?.code !== "fingerprint_mismatch" || caught.category !== "pairing") {
    throw new Error(
      `verifyFingerprint(wrong) must fail with pairing/fingerprint_mismatch, got ${JSON.stringify(caught)}`,
    );
  }
  if (caught.channel_id !== String(channelId)) {
    throw new Error(`verifyFingerprint(wrong) must name channel ${channelId}, got ${String(caught.channel_id)}`);
  }

  const storedBytes = await node.channelStore.load(
    nodeSid,
    String(channelId),
    String(replicaId),
  );
  if (storedBytes) throw new Error("verifyFingerprint(wrong) must remove the member record");
  const storedKey = await node.secretStore.load(nodeSid, String(channelId), 0);
  if (storedKey) throw new Error("verifyFingerprint(wrong) must remove the channel key");
  console.log("  verifyFingerprint(wrong) fails with fingerprint_mismatch  ✓");
  console.log("  member record and channel key removed  ✓");
  console.log("\n✓ Fingerprint mismatch passed.\n");
}


/**
 * A `NoKeys` pairing holds the long-term channel `Pending` until the
 * fingerprints are compared out of band. A wrong fingerprint on that side
 * revokes the pairing there — channel record and SharedKey both go — while
 * the peer, which has not compared anything yet, keeps its own `Pending`
 * channel intact.
 */
async function runNoKeysFingerprintMismatchFlow(): Promise<void> {
  console.log("=== [Protocol] NoKeys fingerprint mismatch ===\n");

  const owner = makeNode("Owner", "https://owner.example.com");
  const helper = makeNode("Helper", "https://helper.example.com");
  const { longTermChannelId } = await doPairViaPrePair(
    helper,
    owner,
    4n,
    "NoKeysMismatch",
    ContactMode.NoKeys,
  );

  const ownerSid = String(owner.protocol.secretId());
  const helperSid = String(helper.protocol.secretId());

  let caught: { code?: string; category?: string; channel_id?: string } | null = null;
  try {
    await owner.protocol.verifyFingerprint(BigInt(longTermChannelId), "0000-0000-0000-0000");
  } catch (e) {
    caught = e as { code?: string; category?: string; channel_id?: string };
  }
  if (caught?.code !== "fingerprint_mismatch" || caught.category !== "pairing") {
    throw new Error(
      `NoKeys verifyFingerprint(wrong) must fail with pairing/fingerprint_mismatch, got ${JSON.stringify(caught)}`,
    );
  }
  if (caught.channel_id !== String(longTermChannelId)) {
    throw new Error(`NoKeys verifyFingerprint(wrong) must name channel ${longTermChannelId}, got ${String(caught.channel_id)}`);
  }
  console.log("  verifyFingerprint(wrong) fails with fingerprint_mismatch  ✓");

  const ownerRecord = await owner.channelStore.load(ownerSid, longTermChannelId, "0");
  if (ownerRecord) {
    throw new Error("NoKeys verifyFingerprint(wrong) must remove the owner's channel record");
  }
  const ownerKey = await owner.secretStore.load(ownerSid, longTermChannelId, 0);
  if (ownerKey) {
    throw new Error("NoKeys verifyFingerprint(wrong) must remove the owner's SharedKey");
  }
  console.log("  owner channel record and SharedKey removed  ✓");

  const helperRecord = await helper.channelStore.load(helperSid, longTermChannelId, "0");
  if (!helperRecord) {
    throw new Error("NoKeys verifyFingerprint(wrong) must not touch the helper's channel record");
  }
  const helperStatus = JSON.parse(new TextDecoder().decode(helperRecord)).Helper.status;
  if (helperStatus !== "Pending") {
    throw new Error(
      `NoKeys verifyFingerprint(wrong): helper channel must stay Pending; got ${helperStatus}`,
    );
  }
  const helperKey = await helper.secretStore.load(helperSid, longTermChannelId, 0);
  if (!helperKey) {
    throw new Error("NoKeys verifyFingerprint(wrong) must not touch the helper's SharedKey");
  }
  console.log("  helper channel still Pending with its SharedKey  ✓");

  console.log("\n✓ NoKeys fingerprint mismatch passed.\n");
}


/**
 * Sweeping an expired `Pending` channel deletes its SharedKey along with the
 * record, for a helper channel and for a replica channel once no member
 * remains on it. A `Paired` channel is never swept, however old.
 */
async function runExpiredPendingPairingLosesItsKeyFlow(): Promise<void> {
  console.log("=== [Protocol] Expired Pending pairing loses its key ===\n");

  const channelStore = new InMemoryChannelStore();
  const secretStore = new InMemorySecretStore();
  const protocol = new DeRecProtocolBuilder(DEFAULT_TEST_SECRET_ID)
    .withChannelStore(channelStore)
    .withShareStore(new InMemoryShareStore())
    .withSecretStore(secretStore)
    .withUserSecretStore(new InMemoryUserSecretStore())
    .withStateStore(new InMemoryStateStore())
    .withTransport(new RecordingTransport())
    .withOwnTransports([{ uri: "https://sweep.example.com", protocol: "https" }])
    .withThreshold(THRESHOLD)
    .withTimeouts({ expired_channels: { enabled: false, timeout_in_secs: 900 } })
    .build();
  const sid = String(protocol.secretId());

  const sharedKey = new Uint8Array(32);
  for (let i = 0; i < 32; i++) sharedKey[i] = (i * 7 + 3) & 0xff;
  const transports = [{ uri: "https://peer.example.com", protocol: 0 }];
  const helperRecord = (channelId: number, status: string) => ({
    Helper: {
      channel_id: channelId,
      transports,
      communication_info: {},
      peer_role: "Helper",
      status,
      created_at: 1700000000,
    },
  });

  const pendingHelper = "6161";
  const pendingReplica = "6162";
  const pairedHelper = "6163";
  const replicaId = String(0xbeef);

  await channelStore.save(
    sid,
    pendingHelper,
    "0",
    new TextEncoder().encode(JSON.stringify(helperRecord(6161, "Pending"))),
  );
  await secretStore.save(sid, pendingHelper, 0, sharedKey);

  await channelStore.save(
    sid,
    pendingReplica,
    replicaId,
    new TextEncoder().encode(
      JSON.stringify({
        Replica: {
          channel_id: 6162,
          replica_id: 0xbeef,
          transports,
          communication_info: {},
          role: "Destination",
          status: "Pending",
          created_at: 1700000000,
        },
      }),
    ),
  );
  await secretStore.save(sid, pendingReplica, 0, sharedKey);

  await channelStore.save(
    sid,
    pairedHelper,
    "0",
    new TextEncoder().encode(JSON.stringify(helperRecord(6163, "Paired"))),
  );
  await secretStore.save(sid, pairedHelper, 0, sharedKey);

  const removed = await protocol.removeExpiredChannels(60);
  if (!removed.includes(pendingHelper) || !removed.includes(pendingReplica)) {
    throw new Error(
      `removeExpiredChannels must report both expired Pending channels, got ${JSON.stringify(removed)}`,
    );
  }
  if (removed.includes(pairedHelper)) {
    throw new Error(
      `removeExpiredChannels must never sweep a Paired channel, got ${JSON.stringify(removed)}`,
    );
  }
  console.log("  removeExpiredChannels reports the Pending channels, not the Paired one  ✓");

  if (await channelStore.load(sid, pendingHelper, "0")) {
    throw new Error("expired Pending helper channel record must be removed");
  }
  if (await secretStore.load(sid, pendingHelper, 0)) {
    throw new Error("expired Pending helper channel must lose its SharedKey");
  }
  console.log("  expired helper channel: record and SharedKey removed  ✓");

  if (await channelStore.load(sid, pendingReplica, replicaId)) {
    throw new Error("expired Pending replica member record must be removed");
  }
  if (await secretStore.load(sid, pendingReplica, 0)) {
    throw new Error("expired Pending replica channel must lose its SharedKey");
  }
  console.log("  expired replica channel: member record and SharedKey removed  ✓");

  if (!(await channelStore.load(sid, pairedHelper, "0"))) {
    throw new Error("Paired helper channel record must survive the sweep");
  }
  if (!(await secretStore.load(sid, pairedHelper, 0))) {
    throw new Error("Paired helper channel must keep its SharedKey");
  }
  console.log("  Paired channel: record and SharedKey kept  ✓");

  console.log("\n✓ Expired Pending pairing loses its key passed.\n");
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
  // transient pairing_channel_id, which is removed once the rekey lands.
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
 * The third contact mode, which this SDK exposed but never exercised.
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
    return JSON.parse(new TextDecoder().decode(bytes)).Helper.status;
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
  await owner.protocol.verifyFingerprint(BigInt(longTermChannelId), helperFingerprint);
  await helper.protocol.verifyFingerprint(BigInt(longTermChannelId), ownerFingerprint);

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

  // The nonce is what authenticates a NoKeys PrePairRequest: a scanner that
  // presents another one is refused when the creator accepts.
  const nonceCreator = makeNode("Owner", "https://owner.example.com");
  const nonceScanner = makeNode("Helper", "https://helper.example.com");
  const contact = await nonceCreator.protocol.createContact(9999n, ContactMode.NoKeys, 8888n);
  await nonceScanner.protocol.start(FlowKind.Pairing, {
    kind: SenderKind.Helper,
    contact: { ...contact, nonce: 7777n },
  });
  const prePair = drainOne(nonceScanner, "Helper");
  const prePairAction = requireEvent(await nonceCreator.protocol.process(prePair), "ActionRequired", "Owner");
  let mismatch: string | undefined;
  try {
    await nonceCreator.protocol.accept(prePairAction.action);
  } catch (e) {
    mismatch = (e as { message?: string }).message;
  }
  if (!mismatch?.includes("NoKeys PrePair nonce mismatch")) {
    throw new Error(`accept must fail with the NoKeys nonce mismatch, got ${mismatch ?? "no error"}`);
  }
  console.log("  a PrePairRequest with the wrong nonce → accept fails with \"NoKeys PrePair nonce mismatch\"  ✓\n");

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
  // surface `prepair_hash_mismatch` once the real keys arrive. This is
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
  if (caught.category !== "pairing" || caught.code !== "prepair_hash_mismatch") {
    throw new Error(
      `tampered binding hash must surface pairing/PREPAIR_HASH_MISMATCH, got ${caught.category}/${caught.code}: ${caught.message}`,
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

  const secretData = new TextEncoder().encode("super-secret-value");
  await owner.protocol.start(FlowKind.ProtectSecret, {
    secrets: [{ id: new Uint8Array([1]), name: "smoke", data: secretData }],
    description: "smoke-test secret",
  });

  const outbound = owner.transport.drain();
  if (outbound.length !== 2) {
    throw new Error(`expected 2 StoreShareRequests, got ${outbound.length}`);
  }
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
    secrets: [{ id: new Uint8Array([5]), name: "sticky weights", data: new TextEncoder().encode("sticky-weights-secret") }],
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
    return bytes ? JSON.parse(new TextDecoder().decode(bytes)).Helper.weight : undefined;
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

  // Recover that version and restore it on a fresh device whose builder
  // says 2: its first publish splits at the restored t=3.
  const v3 = v2 + 1;
  await owner.protocol.start(FlowKind.RecoverSecret, { secretId, version: v3 });
  const recovered = (await roundTrip()).find((e) => e.type === "SecretRecovered");
  if (recovered?.type !== "SecretRecovered") throw new Error(`v${v3} must be recovered`);
  if (recovered.secret.threshold !== 3) {
    throw new Error(`the recovered roster must carry t=3, got ${recovered.secret.threshold}`);
  }
  const restored = makeNode("RestoredOwner", "https://restored.example.com", { secretId, threshold: 2 });
  await restored.protocol.restore(recovered.secret, v3);
  if ((await restored.userSecretStore.loadLatest(secretId.toString()))?.threshold !== 3) {
    throw new Error("restore must keep t=3");
  }
  const after = await restored.protocol.start(FlowKind.ProtectSecret, {
    secrets: [{ id: new Uint8Array([7]), name: "sticky", data: new Uint8Array([7, 8, 9]) }],
  });
  const v4 = requireEvent(after, "ProtectSecretStarted", "RestoredOwner").version;
  for (const channelId of [...channels, channelD]) {
    const t = await stored(restored, channelId, v4);
    if (t !== 3) {
      throw new Error(`the first publish after restore must split at the restored t=3, got ${t}`);
    }
  }
  console.log(`  [Restored] the first publish after restore (v${v4}) splits at the restored t=3, not the builder's 2  ✓`);

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
  const secretData = new TextEncoder().encode("two helpers, three subshares");
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

/**
 * `ProtectSecretParams.weights` and `WeightedChannel` accept a channel id as
 * `bigint | string`. Every channel id an event carries (here, `channel_id`
 * on `PairingCompleted`, via `doPair`'s `longTermChannelId`) is already a
 * decimal string, so a caller building a weights map straight from events
 * should not have to convert it to `bigint` first.
 */
async function runWeightedHelpersStringIdFlow(): Promise<void> {
  console.log("=== [Protocol] Weighted Helpers Flow (string channel ids) ===\n");

  const owner = makeNode("Owner", "https://owner.example.com", {
    secretId: 46n,
    threshold: 3,
  });
  const helper0 = makeNode("Helper0", "https://helper-0.example.com");
  const helper1 = makeNode("Helper1", "https://helper-1.example.com");

  const { longTermChannelId: channel0 } = await doPair(helper0, owner, 1n, "Owner↔Helper0");
  const { longTermChannelId: channel1 } = await doPair(helper1, owner, 2n, "Owner↔Helper1");
  console.log();

  // `channel0` is the decimal-string `channel_id` a `PairingCompleted` event
  // carried — passed straight through, with no `BigInt()` conversion.
  const protectEvents = await owner.protocol.start(FlowKind.ProtectSecret, {
    secrets: [{ id: new Uint8Array([4]), name: "string-id weighted secret", data: new Uint8Array([7]) }],
    description: "weighted round keyed by decimal-string channel ids",
    weights: new Map<bigint | string, number>([[channel0, 2]]),
  });

  const weightByChannel = new Map<string, number>();
  for (const ev of protectEvents) {
    if (ev.type === "ProtectSecretStarted") {
      weightByChannel.set(ev.channel_id, ev.weight);
    }
  }
  const expectedWeight: Record<string, number> = { [channel0]: 2, [channel1]: 1 };
  for (const [channelId, weight] of Object.entries(expectedWeight)) {
    if (weightByChannel.get(channelId) !== weight) {
      throw new Error(
        `ProtectSecretStarted: expected weight ${weight} for channel ${channelId}, got ${weightByChannel.get(channelId)}`,
      );
    }
  }
  console.log(
    `  [Owner]  start(ProtectSecret, weights={channel0 (string): 2}) → weight(channel0)=2, weight(channel1)=1  ✓`,
  );
  owner.transport.drain();

  // The resolved weights are stored on each helper record. The record is
  // opaque bytes, but `weight` is a small integer, so parsing it to read the
  // weight is safe; the channel id comes from the store key, not the record.
  for (const [channelId, weight] of Object.entries(expectedWeight)) {
    const bytes = await owner.channelStore.load("46", channelId, "0");
    const stored = bytes ? JSON.parse(new TextDecoder().decode(bytes)).Helper.weight : undefined;
    if (stored !== weight) {
      throw new Error(`stored helper record for ${channelId}: expected weight ${weight}, got ${stored}`);
    }
  }
  console.log("  [Owner]  each helper record stores its resolved weight (channel0=2, channel1=1)  ✓");

  console.log("\n✓ Weighted helpers flow (string channel ids) passed.\n");
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
  const secretBytes = new TextEncoder().encode("correct horse battery staple");


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

  // Simulate state loss explicitly so the pair-completion auto-publish hook
  // has nothing to replay against the new channels.
  await owner.userSecretStore.remove(ownerSecretId.toString());

  console.log("  -- Recovery: re-pair on fresh channels --\n");

  // transient contact id → the long-term id both sides rotate to.
  const rekeyedRecovery = new Map<bigint, bigint>();
  const rekRecovery = (transient: bigint): bigint => {
    const r = rekeyedRecovery.get(transient);
    if (r === undefined) throw new Error(`no rekeyed id for recovery cid=${transient}`);
    return r;
  };

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
    const rekeyed = ownerPairing.channel_id;
    rekeyedRecovery.set(fresh, BigInt(rekeyed));

    // Link the original (rekeyed) channel to the rotated recovery id so
    // helper-side linked_channels() reaches the original share rows when
    // Discovery/Recovery arrives on the recovery channel. Both ends must be
    // ids the stores actually hold — the transient contact ids are gone by
    // now, and linking them would leave the graph pointing at nothing.
    const origRekeyed = label === "HelperA" ? originalRekeyedA : originalRekeyedB;
    await helper.channelStore.linkChannel(
      String(helper.protocol.secretId()),
      origRekeyed,
      rekeyed,
    );
    console.log(`  [${label}] re-paired: contact=${fresh} → rekeyed=${rekeyed}`);
  }

  // Simulate Owner-side state loss: drop the original channels so recovery
  // only fans out to the recovery channels.
  const ownerSidRecovery = String(owner.protocol.secretId());
  await owner.channelStore.remove(ownerSidRecovery, originalRekeyedA, "0");
  await owner.channelStore.remove(ownerSidRecovery, originalRekeyedB, "0");
  console.log(`\n  [Owner]  removed original channels ${originalRekeyedA}, ${originalRekeyedB} to simulate state loss\n`);


  console.log("  -- Discovery: Owner asks each helper what it holds --\n");

  await owner.protocol.start(FlowKind.Discovery, {
    target: [rekRecovery(recoveryChannelA), rekRecovery(recoveryChannelB)],
  });

  const discRequests = owner.transport.drain();
  if (discRequests.length !== 2) {
    throw new Error(`expected 2 DiscoveryRequests, got ${discRequests.length}`);
  }
  const discovered: Array<Extract<DeRecEvent, { type: "SecretsDiscovered" }>> = [];
  for (const env of discRequests) {
    const isA = env.endpoint.uri.includes("helper-a");
    const helper = isA ? helperA : helperB;
    const label = isA ? "HelperA" : "HelperB";
    await processAll(helper, env.message);
    const resp = drainOne(helper, label);
    for (const ev of await owner.protocol.process(resp)) {
      if (ev.type === "SecretsDiscovered") discovered.push(ev);
    }
  }
  const discoveredEntry = discovered
    .flatMap((d) => d.secrets)
    .find((s) => s.secret_id === ownerSecretId.toString());
  if (!discoveredEntry) {
    throw new Error(`SecretsDiscovered must list secret ${ownerSecretId}, got ${JSON.stringify(discovered)}`);
  }
  if (!discoveredEntry.versions.some((v) => v.description === description)) {
    throw new Error(`the version description must survive discovery, got ${JSON.stringify(discoveredEntry.versions)}`);
  }
  console.log(
    `  [Owner]  SecretsDiscovered on ${discovered.length} channel(s): secret_id=${discoveredEntry.secret_id} "${description}"  ✓\n`,
  );


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
  for (const s of recovered.secrets) {
    assertBytes(s.id, "SecretRecovered.secret.secrets[].id");
    assertBytes(s.data, "SecretRecovered.secret.secrets[].data");
  }
  for (const h of recovered.helpers) {
    assertBytes(h.shared_key, "SecretRecovered.secret.helpers[].shared_key");
  }
  console.log("  [Owner]  SecretRecovered byte fields arrive as Uint8Array  ✓");

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

  // Restore errors carry the same `category` as every other library error,
  // and a conflict names the channels that block it.
  const restoreError = async (label: string): Promise<DeRecError> => {
    try {
      await restored.protocol.restore(recovered, 1);
    } catch (e) {
      return e as DeRecError;
    }
    throw new Error(`${label}: restore must be refused`);
  };
  const already = await restoreError("second restore");
  if (already.code !== "already_restored" || already.category !== "input") {
    throw new Error(
      `second restore: expected input/already_restored, got ${already.category}/${already.code}`,
    );
  }
  await restored.userSecretStore.remove(ownerSecretId.toString());
  const conflict = await restoreError("restore over existing channels");
  const expectedIds = recovered.helpers.map((h) => h.channel_id).sort();
  if (
    conflict.code !== "restore_conflict" ||
    conflict.category !== "input" ||
    JSON.stringify([...(conflict.channel_ids ?? [])].sort()) !== JSON.stringify(expectedIds)
  ) {
    throw new Error(
      `restore over existing channels: expected input/restore_conflict naming ${expectedIds.join(",")}, got ${JSON.stringify(conflict)}`,
    );
  }
  console.log("  [Restored] already_restored and restore_conflict carry category \"input\"; restore_conflict names the channels ✓");

  console.log("\n✓ Discovery & Recovery flow passed.\n");
}

/**
 * A recovery decides only once every helper it asked has answered, so a
 * helper that never answers holds the decision until
 * `timeouts.get_share_response_secs` elapses. `tick()` then reports that
 * helper as timed out and recovers from the shares in hand.
 */
async function runSilentHelperRecoveryFlow(): Promise<void> {
  console.log("=== [Protocol] Silent Helper Recovery Flow ===\n");

  const owner = makeNode("Owner", "https://owner.example.com", {
    timeouts: { get_share_response_secs: 1 },
  });
  const helperA = makeNode("HelperA", "https://helper-a.example.com");
  const helperB = makeNode("HelperB", "https://helper-b.example.com");
  const helperC = makeNode("HelperC", "https://helper-c.example.com");

  await doPair(helperA, owner, 1n, "Owner↔HelperA");
  await doPair(helperB, owner, 2n, "Owner↔HelperB");
  const { longTermChannelId: channelC } = await doPair(helperC, owner, 3n, "Owner↔HelperC");
  console.log();

  const helpersByUri: Record<string, [Node, string]> = {
    "https://helper-a.example.com": [helperA, "HelperA"],
    "https://helper-b.example.com": [helperB, "HelperB"],
    "https://helper-c.example.com": [helperC, "HelperC"],
  };

  const secretData = new TextEncoder().encode("three helpers, one silent");
  const protectEvents = await owner.protocol.start(FlowKind.ProtectSecret, {
    secrets: [{ id: new Uint8Array([9]), name: "silent-helper secret", data: secretData }],
  });
  const version = requireEvent(protectEvents, "ProtectSecretStarted", "Owner").version;
  for (const outbound of owner.transport.drain()) {
    const [helper, label] = helpersByUri[outbound.endpoint.uri]!;
    const helperEvents = await processAll(helper, outbound.message);
    requireEvent(helperEvents, "ShareStored", label);
    await owner.protocol.process(drainOne(helper, label));
  }
  console.log(`  [Owner]  start(ProtectSecret) → version ${version} stored on all three helpers`);

  await owner.protocol.start(FlowKind.RecoverSecret, {
    secretId: owner.protocol.secretId(),
    version,
  });

  // HelperC never sees its request.
  const recoveryEvents: DeRecEvent[] = [];
  for (const outbound of owner.transport.drain()) {
    if (outbound.endpoint.uri === "https://helper-c.example.com") continue;
    const [helper, label] = helpersByUri[outbound.endpoint.uri]!;
    await processAll(helper, outbound.message);
    recoveryEvents.push(...(await owner.protocol.process(drainOne(helper, label))));
  }

  const received = recoveryEvents.filter((e) => e.type === "RecoveryShareReceived").length;
  if (received !== 2) {
    throw new Error(`HelperA and HelperB answer: expected 2 RecoveryShareReceived, got ${received}`);
  }
  if (recoveryEvents.some((e) => e.type === "SecretRecovered")) {
    throw new Error(
      `nothing is decided while HelperC's answer is due: [${recoveryEvents.map((e) => e.type).join(", ")}]`,
    );
  }
  const waiting = await owner.protocol.tick();
  if (waiting.length !== 0) {
    throw new Error(
      `the recovery waits out its window: tick() → [${waiting.map((e) => e.type).join(", ")}]`,
    );
  }
  console.log("  [Owner]  2 shares in, HelperC silent → no SecretRecovered, tick() empty  ✓");

  await new Promise<void>((resolve) => setTimeout(resolve, 2100));
  const settled = await owner.protocol.tick();
  const [failed, recovered, ...rest] = settled;
  if (
    failed?.type !== "RecoverSecretFailed" ||
    recovered?.type !== "SecretRecovered" ||
    rest.length !== 0
  ) {
    throw new Error(
      `expected a timeout then SecretRecovered, got [${settled.map((e) => e.type).join(", ")}]`,
    );
  }
  if (failed.channel_id !== channelC) {
    throw new Error(`HelperC (${channelC}) is the one that timed out, got ${failed.channel_id}`);
  }
  if (failed.version !== version) {
    throw new Error(`RecoverSecretFailed.version: expected ${version}, got ${failed.version}`);
  }
  if (failed.error !== "timeout") {
    throw new Error(`RecoverSecretFailed.error: expected "timeout", got "${failed.error}"`);
  }
  const recoveredSecret = recovered.secret.secrets.find((s) => s.id.length === 1 && s.id[0] === 9);
  if (!recoveredSecret || !byteArraysEqual(recoveredSecret.data, secretData)) {
    throw new Error("recovered secret must carry the protected bytes");
  }
  console.log(
    `  [Owner]  after the window, tick() → RecoverSecretFailed(${channelC}, "timeout"), SecretRecovered("${recoveredSecret.name}")  ✓`,
  );

  const closed = await owner.protocol.tick();
  if (closed.length !== 0) {
    throw new Error(
      `the recovery is closed once decided: tick() → [${closed.map((e) => e.type).join(", ")}]`,
    );
  }
  console.log("  [Owner]  tick() after the decision is empty  ✓");

  console.log("\n✓ Silent helper recovery flow passed.\n");
}

/**
 * Protect a one-entry secret named `name` from `owner` across every helper in
 * `helpers`, deliver the round, and return the version it published.
 */
async function protectAcross(
  owner: AddressedNode,
  helpers: AddressedNode[],
  name: string,
): Promise<number> {
  const events = await owner.node.protocol.start(FlowKind.ProtectSecret, {
    secrets: [{ id: new Uint8Array([10]), name, data: new TextEncoder().encode(name) }],
  });
  const version = requireEvent(events, "ProtectSecretStarted", name).version;
  await pumpAll([owner, ...helpers]);
  return version;
}

/**
 * Replace the share `to` holds on `toChannel` with the one `from` holds on
 * `fromChannel`, both at `version`, through the helpers' own share stores.
 * Both splits are of the same `(secret_id, version)`, so the moved share
 * still passes every check it is put to on its own.
 */
async function transplantShare(
  from: Node,
  fromChannel: string,
  to: Node,
  toChannel: string,
  version: number,
): Promise<void> {
  const [foreign] = await from.shareStore.load(String(from.protocol.secretId()), fromChannel, [version]);
  if (!foreign) throw new Error("the foreign helper holds a share for the version");
  const toSid = String(to.protocol.secretId());
  const [held] = await to.shareStore.load(toSid, toChannel, [version]);
  if (!held) throw new Error("the helper holds a share for the version");
  await to.shareStore.save(toSid, toChannel, { ...held, bytes: foreign.bytes });
}

/**
 * Owner A splits its secret at threshold 3 across five helpers. A second
 * owner, B, with the same secret id, splits a different secret at version 1
 * across its own helpers at `bThreshold`; two of A's helpers end up holding
 * B's shares instead of A's. Returns A's decision events and the channels of
 * the five helpers, in order.
 */
async function recoverWithTwoOfFiveFromAnotherSplit(
  bThreshold: number,
): Promise<{ events: DeRecEvent[]; channels: string[] }> {
  const secretId = 44n;
  const owner: AddressedNode = {
    node: makeNode("owner-a", "https://owner-a.example.com", { secretId, threshold: 3 }),
    uri: "https://owner-a.example.com",
  };
  // Each helper advertises its own name; that is what the owner records.
  const helpers: AddressedNode[] = [1, 2, 3, 4, 5].map((i) => ({
    node: makeNode(`helper-${i}`, `https://helper-${i}.example.com`),
    uri: `https://helper-${i}.example.com`,
  }));
  const channels: string[] = [];
  for (const [i, helper] of helpers.entries()) {
    const { longTermChannelId } = await doPair(helper.node, owner.node, BigInt(10 + i), `OwnerA↔helper-${i + 1}`);
    channels.push(longTermChannelId);
  }
  const version = await protectAcross(owner, helpers, "owner-a secret");

  const other: AddressedNode = {
    node: makeNode("owner-b", "https://owner-b.example.com", { secretId, threshold: bThreshold }),
    uri: "https://owner-b.example.com",
  };
  const xs: AddressedNode[] = [1, 2, 3].map((i) => ({
    node: makeNode(`x${i}`, `https://x${i}.example.com`),
    uri: `https://x${i}.example.com`,
  }));
  const xChannels: string[] = [];
  for (const [i, x] of xs.entries()) {
    const { longTermChannelId } = await doPair(x.node, other.node, BigInt(21 + i), `OwnerB↔x${i + 1}`);
    xChannels.push(longTermChannelId);
  }
  const otherVersion = await protectAcross(other, xs, "owner-b secret");
  if (otherVersion !== version) {
    throw new Error(`both splits are of the same version: ${otherVersion} ≠ ${version}`);
  }

  await transplantShare(xs[0]!.node, xChannels[0]!, helpers[3]!.node, channels[3]!, version);
  await transplantShare(xs[1]!.node, xChannels[1]!, helpers[4]!.node, channels[4]!, version);

  await owner.node.protocol.start(FlowKind.RecoverSecret, { secretId, version });
  const events = await pumpAll([owner, ...helpers]);
  if (events.some((e) => e.type === "RecoveryShareCorrupted")) {
    throw new Error(
      `a share of another split is not evidence against its helper: [${events.map((e) => e.type).join(", ")}]`,
    );
  }
  return { events, channels };
}

function helperChannels(helpers: RecoveryHelper[]): string[] {
  return helpers.map((h) => h.channel_id);
}

function helperNames(helpers: RecoveryHelper[]): string[] {
  return helpers.map((h) => h.communication_info?.["name"] ?? "");
}

function expectSame(label: string, got: unknown, want: unknown): void {
  if (JSON.stringify(got) !== JSON.stringify(want)) {
    throw new Error(`${label}: expected ${JSON.stringify(want)}, got ${JSON.stringify(got)}`);
  }
}

/**
 * Three helpers back the owner's split; two hold valid shares of another
 * split that cannot reconstruct. The library cannot tell which side is the
 * owner's, so it reports a dispute naming both, not a recovery.
 */
async function runDisputedRecoveryFlow(): Promise<void> {
  console.log("=== [Protocol] Disputed Recovery Flow ===\n");

  const { events, channels } = await recoverWithTwoOfFiveFromAnotherSplit(3);
  const disputed = requireEvent(events, "RecoveryDisputed", "OwnerA");
  if (events.some((e) => e.type === "SecretRecovered")) {
    throw new Error("a disputed secret is never reported as recovered");
  }
  expectSame("RecoveryDisputed.secret name", disputed.secret.secrets[0]?.name, "owner-a secret");
  expectSame("RecoveryDisputed.supported_by channels", helperChannels(disputed.supported_by), channels.slice(0, 3));
  expectSame("RecoveryDisputed.disputed_by channels", helperChannels(disputed.disputed_by), channels.slice(3));
  expectSame("RecoveryDisputed.supported_by names", helperNames(disputed.supported_by), ["helper-1", "helper-2", "helper-3"]);
  expectSame("RecoveryDisputed.disputed_by names", helperNames(disputed.disputed_by), ["helper-4", "helper-5"]);
  console.log(
    "  [OwnerA]  RecoveryDisputed(\"owner-a secret\") supported_by [helper-1..3], disputed_by [helper-4, helper-5], no SecretRecovered  ✓",
  );

  console.log("\n✓ Disputed recovery flow passed.\n");
}

/**
 * When the other split's two shares reconstruct too, the owner faces two
 * complete secrets and has to choose between them.
 */
async function runConflictingRecoveryFlow(): Promise<void> {
  console.log("=== [Protocol] Conflicting Recovery Flow ===\n");

  const { events, channels } = await recoverWithTwoOfFiveFromAnotherSplit(2);
  const conflict = requireEvent(events, "RecoveryConflict", "OwnerA");
  expectSame(
    "RecoveryConflict.candidates",
    conflict.candidates.map((c) => [c.secret.secrets[0]?.name, helperChannels(c.supported_by)]),
    [
      ["owner-a secret", channels.slice(0, 3)],
      ["owner-b secret", channels.slice(3)],
    ],
  );
  expectSame("RecoveryConflict.disputed_by (every share is on one side or the other)", conflict.disputed_by, []);
  console.log(
    "  [OwnerA]  RecoveryConflict candidates [(\"owner-a secret\", helper-1..3), (\"owner-b secret\", helper-4..5)], disputed_by []  ✓",
  );

  console.log("\n✓ Conflicting recovery flow passed.\n");
}

/**
 * A recovering device can already be a helper for another owner. `restore`
 * wipes only the recovery channels whose peer is a helper; the channel on
 * which this device helps that owner, and the share it holds there, survive.
 */
async function runRestoreKeepsHelperDutiesFlow(): Promise<void> {
  console.log("=== [Protocol] Restore Keeps Helper Duties Flow ===\n");

  const ownSecretId = 4545n;
  const lost: AddressedNode = {
    node: makeNode("lost-device", "https://lost.example.com", { secretId: ownSecretId }),
    uri: "https://lost.example.com",
  };
  const helperA: AddressedNode = {
    node: makeNode("helper-a", "https://helper-a.example.com"),
    uri: "https://helper-a.example.com",
  };
  const helperB: AddressedNode = {
    node: makeNode("helper-b", "https://helper-b.example.com"),
    uri: "https://helper-b.example.com",
  };
  const { longTermChannelId: channelA } = await doPair(helperA.node, lost.node, 1n, "Lost↔HelperA");
  const { longTermChannelId: channelB } = await doPair(helperB.node, lost.node, 2n, "Lost↔HelperB");
  const version = await protectAcross(lost, [helperA, helperB], "own secret");

  const device: AddressedNode = {
    node: makeNode("new-device", "https://device.example.com", { secretId: ownSecretId }),
    uri: "https://device.example.com",
  };
  const deviceSid = String(device.node.protocol.secretId());

  // The new device helps another owner first.
  const otherOwner: AddressedNode = {
    node: makeNode("other-owner", "https://other.example.com", { secretId: 9090n }),
    uri: "https://other.example.com",
  };
  const otherHelper: AddressedNode = {
    node: makeNode("other-helper", "https://other-helper.example.com"),
    uri: "https://other-helper.example.com",
  };
  const { longTermChannelId: dutyChannel } = await doPair(device.node, otherOwner.node, 3n, "Other↔Device");
  await doPair(otherHelper.node, otherOwner.node, 4n, "Other↔OtherHelper");
  const otherVersion = await protectAcross(otherOwner, [device, otherHelper], "other owner's secret");
  const heldBefore = await device.node.shareStore.load(deviceSid, dutyChannel, [otherVersion]);
  if (heldBefore.length !== 1) {
    throw new Error(`the device holds the other owner's share: got ${heldBefore.length} share(s)`);
  }
  console.log(`  [Device]  helps the other owner on duty channel ${dutyChannel}, holding its v${otherVersion} share  ✓`);

  // Then it recovers its own secret over fresh recovery channels.
  const recoveryChannels: string[] = [];
  for (const [helper, original, transient] of [
    [helperA, channelA, 100n],
    [helperB, channelB, 101n],
  ] as const) {
    const contact: ContactMessage = await device.node.protocol.createContact(transient, ContactMode.InlineKeys);
    await helper.node.protocol.start(FlowKind.Pairing, { kind: SenderKind.Helper, contact });
    const events = await pumpAll([device, helper]);
    const paired = events.find(
      (e) => e.type === "PairingCompleted" && e.pairing_channel_id === String(transient),
    ) as Extract<DeRecEvent, { type: "PairingCompleted" }> | undefined;
    if (!paired) {
      throw new Error(`the recovery pairing on ${transient} completes: [${events.map((e) => e.type).join(", ")}]`);
    }
    await helper.node.channelStore.linkChannel(
      String(helper.node.protocol.secretId()),
      original,
      paired.channel_id,
    );
    recoveryChannels.push(paired.channel_id);
  }

  await device.node.protocol.start(FlowKind.RecoverSecret, { secretId: ownSecretId, version });
  const recoveryEvents = await pumpAll([device, helperA, helperB]);
  const recovered = requireEvent(recoveryEvents, "SecretRecovered", "Device").secret;
  console.log("  [Device]  recovers its own secret over fresh recovery channels  ✓");

  const restoreEvents = await device.node.protocol.restore(recovered, version);
  const touched = restoreEvents.flatMap((e) =>
    e.type === "UnpairStarted" || e.type === "Unpaired" || e.type === "UnpairFailed" ? [e.channel_id] : [],
  );
  if (touched.includes(dutyChannel)) {
    throw new Error(
      `restore must not unpair the channel to the other owner: [${restoreEvents.map((e) => e.type).join(", ")}]`,
    );
  }
  for (const recoveryChannel of recoveryChannels) {
    if (!touched.includes(recoveryChannel)) {
      throw new Error(`restore still wipes recovery channel ${recoveryChannel}`);
    }
  }
  console.log("  [Device]  restore unpairs both recovery channels, never the duty channel  ✓");
  await pumpAll([device, helperA, helperB]);

  const dutyBytes = await device.node.channelStore.load(deviceSid, dutyChannel, "0");
  if (!dutyBytes) throw new Error("the channel to the other owner survives restore");
  const dutyStatus = JSON.parse(new TextDecoder().decode(dutyBytes)).Helper.status;
  if (dutyStatus !== "Paired") {
    throw new Error(`the channel to the other owner stays Paired, got ${dutyStatus}`);
  }
  const heldAfter = await device.node.shareStore.load(deviceSid, dutyChannel, [otherVersion]);
  if (heldAfter.length !== 1) {
    throw new Error(`the share held for the other owner survives restore: got ${heldAfter.length} share(s)`);
  }
  console.log("  [Device]  duty channel still Paired and the other owner's share still held  ✓");

  await otherOwner.node.protocol.start(FlowKind.VerifyShares, {
    secretId: otherOwner.node.protocol.secretId(),
    version: otherVersion,
  });
  const verified = (await pumpAll([otherOwner, device, otherHelper])).flatMap((e) =>
    e.type === "ShareVerified" ? [e.channel_id] : [],
  );
  if (!verified.includes(dutyChannel)) {
    throw new Error(`the other owner can still verify the restored device's share: [${verified.join(", ")}]`);
  }
  console.log("  [Other]   VerifyShares → ShareVerified on the duty channel  ✓");

  console.log("\n✓ Restore keeps helper duties flow passed.\n");
}

/**
 * Start a replica pairing from `scanner`, as `kind`, against a fresh contact
 * from `creator` at `transient`.
 */
async function startReplicaScan(
  scanner: Node,
  creator: Node,
  transient: bigint,
  kind: SenderKind,
): Promise<void> {
  const contact = await creator.protocol.createContact(transient, ContactMode.InlineKeys);
  await scanner.protocol.start(FlowKind.Pairing, { kind, contact });
}

/**
 * `ProtectSecret` on `owner` must be accepted: a replica pairing that never
 * completed is no group, and must never stop the device from protecting.
 */
async function assertProtects(owner: Node, name: string, label = "ReplicaA"): Promise<void> {
  try {
    await owner.protocol.start(FlowKind.ProtectSecret, {
      secrets: [{ id: new Uint8Array([11]), name, data: new TextEncoder().encode(name) }],
    });
  } catch (e) {
    throw new Error(`ProtectSecret (${name}) must succeed: ${JSON.stringify(e)}`);
  }
  console.log(`  [${label}] ProtectSecret ${name}  ✓`);
}

/**
 * A replica pairing that never completes must not leave this device unable
 * to protect: neither while it is pending, nor after a later pairing
 * completes, nor once the expiry sweep has cleared it. The device's own row
 * lands on the channel of the pairing that was confirmed.
 */
async function runAbandonedReplicaPairingFlow(): Promise<void> {
  console.log("=== [Protocol] Abandoned Replica Pairing Flow ===\n");

  const aId = 0xA1A1n;
  const a: AddressedNode = {
    node: makeNode("replica-a", "https://replica-a.example.com", {
      replicaId: aId,
      timeouts: { expired_channels: { enabled: true, timeout_in_secs: 1 } },
    }),
    uri: "https://replica-a.example.com",
  };
  const b: AddressedNode = {
    node: makeNode("replica-b", "https://replica-b.example.com", { replicaId: 0xB2B2n }),
    uri: "https://replica-b.example.com",
  };
  const c: AddressedNode = {
    node: makeNode("replica-c", "https://replica-c.example.com", { replicaId: 0xC3C3n }),
    uri: "https://replica-c.example.com",
  };

  // B never hears of the request.
  await startReplicaScan(a.node, b.node, 100n, SenderKind.ReplicaSource);
  a.node.transport.drain();
  await assertProtects(a.node, "while a replica pairing is pending");

  await startReplicaScan(a.node, c.node, 200n, SenderKind.ReplicaSource);
  const pairingEvents = await pumpAll([a, c]);
  const completed = pairingEvents.find(
    (e) => e.type === "PairingCompleted" && e.pairing_channel_id === "200",
  ) as Extract<DeRecEvent, { type: "PairingCompleted" }> | undefined;
  if (!completed) {
    throw new Error(`the pairing with C completes: [${pairingEvents.map((e) => e.type).join(", ")}]`);
  }
  const groupChannel = completed.channel_id;
  await crossConfirmFingerprint(a.node, c.node, BigInt(groupChannel));
  await pumpAll([a, c]);
  await assertProtects(a.node, "after a later pairing is confirmed");
  await pumpAll([a, c]);

  await new Promise<void>((resolve) => setTimeout(resolve, 2100));
  await a.node.protocol.tick();
  await assertProtects(a.node, "after the expiry sweep");
  await pumpAll([a, c]);

  const aSid = String(a.node.protocol.secretId());
  // The stored record carries ids as bare JSON numbers, beyond what a JS
  // number holds exactly, so they are read from the text.
  const roster = new TextDecoder().decode(
    await a.node.channelStore.listReplicas(aSid, {
      ids: [String(aId)],
      status: [],
      role: null,
      exclude: [],
    }),
  );
  const own = {
    replica_id: /"replica_id":(\d+)/.exec(roster)?.[1],
    channel_id: /"channel_id":(\d+)/.exec(roster)?.[1],
    status: /"status":"(\w+)"/.exec(roster)?.[1],
  };
  if ((roster.match(/"replica_id":/g) ?? []).length !== 1 || own.replica_id !== String(aId)) {
    const all = new TextDecoder().decode(await a.node.channelStore.listReplicas(aSid, ANY_REPLICAS));
    throw new Error(`A keeps its own row: roster ${all}`);
  }
  if (own.channel_id !== groupChannel) {
    throw new Error(`A's own row is on the confirmed group channel ${groupChannel}, got ${own.channel_id}`);
  }
  if (own.status !== "Paired") {
    throw new Error(`A's own row is Paired, got ${own.status}`);
  }
  console.log(`  [ReplicaA] own row on the confirmed group channel ${groupChannel}, Paired  ✓`);

  console.log("\n✓ Abandoned replica pairing flow passed.\n");
}

/**
 * A contact's channel identifier is chosen by whoever created it, and a
 * replica group's identifier travels in the clear on every envelope of the
 * group. A contact on the group channel must be refused, and a pending
 * pairing on that channel must never take the group key when it expires.
 */
async function runContactOnTheGroupChannelFlow(): Promise<void> {
  console.log("=== [Protocol] Contact On The Group Channel Flow ===\n");

  const a: AddressedNode = {
    node: makeNode("replica-a", "https://replica-a.example.com", {
      replicaId: 0xA1A1n,
      timeouts: { expired_channels: { enabled: true, timeout_in_secs: 1 } },
    }),
    uri: "https://replica-a.example.com",
  };
  const c: AddressedNode = {
    node: makeNode("replica-c", "https://replica-c.example.com", { replicaId: 0xC3C3n }),
    uri: "https://replica-c.example.com",
  };
  const adversary = makeNode("adversary", "https://adversary.example.com");

  await startReplicaScan(a.node, c.node, 200n, SenderKind.ReplicaSource);
  const pairingEvents = await pumpAll([a, c]);
  const completed = pairingEvents.find(
    (e) => e.type === "PairingCompleted" && e.pairing_channel_id === "200",
  ) as Extract<DeRecEvent, { type: "PairingCompleted" }> | undefined;
  if (!completed) {
    throw new Error(`the pairing with C completes: [${pairingEvents.map((e) => e.type).join(", ")}]`);
  }
  const groupChannel = completed.channel_id;
  await crossConfirmFingerprint(a.node, c.node, BigInt(groupChannel));
  await pumpAll([a, c]);

  const contact = await adversary.protocol.createContact(BigInt(groupChannel), ContactMode.InlineKeys);
  await expectChannelCode("a contact on the group channel must be refused", "channel_already_paired", String(groupChannel), () =>
    a.node.protocol.start(FlowKind.Pairing, { kind: SenderKind.Owner, contact }),
  );
  if (a.node.transport.drain().length !== 0) {
    throw new Error("nothing is sent for a refused contact");
  }
  console.log("  [ReplicaA] contact on the group channel refused with channel_already_paired, nothing sent  ✓");

  await assertProtects(c.node, "group traffic after the refused contact", "ReplicaC");
  const events: DeRecEvent[] = [];
  for (const m of c.node.transport.drain()) {
    events.push(...(await processAll(a.node, m.message)));
  }
  if (events.some((e) => e.type === "MessageIgnored")) {
    throw new Error(`A still processes the group's traffic: ${JSON.stringify(events)}`);
  }
  await pumpAll([a, c]);
  console.log("  [ReplicaA] group traffic still processed  ✓");

  const aSid = String(a.node.protocol.secretId());
  // The channel id is a u64 beyond what a JS number holds exactly, so the
  // record is written as text.
  const pending =
    `{"Helper":{"channel_id":${groupChannel},"transports":[],"communication_info":{},` +
    `"status":"Pending","created_at":0,"peer_role":"Helper","weight":1}}`;
  await a.node.channelStore.save(aSid, groupChannel, "0", new TextEncoder().encode(pending));
  await a.node.protocol.tick();
  if (!(await a.node.secretStore.load(aSid, groupChannel, 0))) {
    throw new Error("an expired pairing on the group channel must not take the group key");
  }
  await assertProtects(a.node, "after the expiry sweep");
  console.log("  [ReplicaA] expired pairing on the group channel leaves the group key  ✓");

  console.log("\n✓ Contact on the group channel flow passed.\n");
}

/**
 * A joiner whose fingerprint is not yet confirmed is not a member: the source
 * neither lists it in the roster it publishes nor asks it in a version check,
 * and a check whose only member stays silent concludes once its budget
 * elapses. Mirrors `run_unconfirmed_joiner_flow` in
 * `smoke-tests/rust/src/protocol.rs`.
 */
async function runUnconfirmedJoinerFlow(): Promise<void> {
  console.log("=== [Protocol] Replica Unconfirmed Joiner Flow ===\n");

  const source: AddressedNode = {
    node: makeNode("source", "https://source-unconfirmed.example.com", {
      replicaId: 0x5050n,
      timeouts: { get_share_response_secs: 1 },
    }),
    uri: "https://source-unconfirmed.example.com",
  };
  const dest: AddressedNode = {
    node: makeNode("dest", "https://dest-unconfirmed.example.com", { replicaId: 0xd1d1n }),
    uri: "https://dest-unconfirmed.example.com",
  };
  const joiner: AddressedNode = {
    node: makeNode("joiner", "https://joiner-unconfirmed.example.com", { replicaId: 0xd3d3n }),
    uri: "https://joiner-unconfirmed.example.com",
  };
  const completedOn = (events: DeRecEvent[], transient: string): string => {
    const completed = events.find(
      (e) => e.type === "PairingCompleted" && e.pairing_channel_id === transient,
    ) as Extract<DeRecEvent, { type: "PairingCompleted" }> | undefined;
    if (!completed) {
      throw new Error(`the pairing on ${transient} completes: [${events.map((e) => e.type).join(", ")}]`);
    }
    return completed.channel_id;
  };

  await startReplicaScan(dest.node, source.node, 191n, SenderKind.ReplicaDestination);
  const group = completedOn(await pumpAll([source, dest]), "191");
  await crossConfirmFingerprint(source.node, dest.node, BigInt(group));
  await pumpAll([source, dest]);
  await assertProtects(source.node, "unconfirmed joiner", "Source");
  await pumpAll([source, dest]);

  await startReplicaScan(joiner.node, source.node, 192n, SenderKind.ReplicaDestination);
  completedOn(await pumpAll([source, dest, joiner]), "192");

  await assertProtects(source.node, "unconfirmed joiner", "Source");
  const published = await pumpAll([source, dest, joiner]);
  const received = published.find(
    (e) => e.type === "ReplicaSecretReceived" || e.type === "ReplicaSecretInstalled",
  ) as { secret?: { replicas?: { members: Array<{ replica_id: string }> } | null } } | undefined;
  const members = received?.secret?.replicas?.members;
  if (!members) {
    throw new Error(`the destination must receive the new version: ${JSON.stringify(published)}`);
  }
  const listed = members.map((m) => m.replica_id);
  if (listed.length !== 2 || listed.includes(String(0xd3d3))) {
    throw new Error(`an unconfirmed joiner must not be published: ${JSON.stringify(listed)}`);
  }
  console.log("  the published roster leaves out the unconfirmed joiner  ✓");

  await source.node.protocol.start(FlowKind.ReplicaDiscovery);
  const checked = await pumpAll([source, dest, joiner]);
  if (checked.some((e) => e.type === "MessageIgnored")) {
    throw new Error(`the joiner must not be asked: ${JSON.stringify(checked)}`);
  }
  if (!checked.some((e) => e.type === "ReplicaDiscoveryComplete")) {
    throw new Error(`the check concludes on the destination's answer: ${JSON.stringify(checked)}`);
  }
  console.log("  the version check skips the joiner and concludes at once  ✓");

  await source.node.protocol.start(FlowKind.ReplicaDiscovery);
  source.node.transport.drain();
  if ((await source.node.protocol.tick()).length !== 0) {
    throw new Error("the check waits out its window");
  }
  await new Promise<void>((resolve) => setTimeout(resolve, 2100));
  const concluded = await source.node.protocol.tick();
  const done = concluded[0];
  if (
    concluded.length !== 1 ||
    done?.type !== "ReplicaDiscoveryComplete" ||
    (done.fetched_from ?? null) !== null
  ) {
    throw new Error(`expected ReplicaDiscoveryComplete: ${JSON.stringify(concluded)}`);
  }
  if ((await source.node.protocol.tick()).length !== 0) {
    throw new Error("the check is closed once concluded");
  }
  console.log("  a silent member's check concludes on the timeout  ✓");

  console.log("\n✓ Replica unconfirmed joiner flow passed.\n");
}

/**
 * A pairing has a lifetime, `timeouts.pairing_secs`, and both sides enforce
 * it without sending anything: the scanner refuses an expired contact, and
 * the creator ignores a request on one and refuses a late accept. Pairing
 * involves both parties, so the remedy is a fresh contact. Mirrors
 * `run_pairing_expiry_flow` in `smoke-tests/rust/src/protocol.rs`.
 */
async function runPairingExpiryFlow(): Promise<void> {
  console.log("=== [Protocol] Pairing Expiry Flow ===\n");

  const shortWindow = { timeouts: { pairing_secs: 1 } };
  const creatorA = makeNode("helper-expiry-a", "https://helper-expiry-a.example.com");
  const scannerA = makeNode("owner-expiry-a", "https://owner-expiry-a.example.com", shortWindow);
  const creatorB = makeNode("helper-expiry-b", "https://helper-expiry-b.example.com", shortWindow);
  const scannerB = makeNode("owner-expiry-b", "https://owner-expiry-b.example.com");
  const creatorC = makeNode("helper-expiry-c", "https://helper-expiry-c.example.com", shortWindow);
  const scannerC = makeNode("owner-expiry-c", "https://owner-expiry-c.example.com");

  const createContact = (creator: Node, channelId: bigint) =>
    creator.protocol.createContact(channelId, ContactMode.InlineKeys);
  const scanAsOwner = (scanner: Node, contact: Awaited<ReturnType<typeof createContact>>) =>
    scanner.protocol.start(FlowKind.Pairing, { kind: SenderKind.Owner, contact });
  const codeOf = async (call: () => Promise<unknown>): Promise<string | undefined> => {
    try {
      await call();
    } catch (e) {
      return (e as { code?: string }).code;
    }
    return undefined;
  };

  const staleContact = await createContact(creatorA, 181n);
  const expiringContact = await createContact(creatorB, 182n);
  await scanAsOwner(scannerC, await createContact(creatorC, 183n));
  const [request] = scannerC.transport.drain();
  if (!request) throw new Error("scanner-c sends a pair request");
  const late = (await creatorC.protocol.process(request.message)).find(
    (e) => e.type === "ActionRequired",
  ) as Extract<DeRecEvent, { type: "ActionRequired" }> | undefined;
  if (!late) throw new Error("creator-c is asked to accept the pairing");

  await new Promise<void>((resolve) => setTimeout(resolve, 2100));

  const scanCode = await codeOf(() => scanAsOwner(scannerA, staleContact));
  if (scanCode !== "pairing_expired") {
    throw new Error(`the scanner must refuse an expired contact with pairing_expired, got ${scanCode ?? "no error"}`);
  }
  if (scannerA.transport.drain().length !== 0) throw new Error("nothing is sent for an expired contact");
  console.log("  [Owner] scanning a contact older than the window → pairing_expired, nothing sent  ✓");

  await scanAsOwner(scannerB, expiringContact);
  const [requestB] = scannerB.transport.drain();
  if (!requestB) throw new Error("scanner-b sends a pair request");
  const events = await creatorB.protocol.process(requestB.message);
  const [ignored] = events;
  if (
    events.length !== 1 ||
    ignored?.type !== "MessageIgnored" ||
    ignored.reason !== "Expired" ||
    ignored.channel_id !== "182"
  ) {
    throw new Error(`a request on an expired contact must be MessageIgnored(Expired); got ${JSON.stringify(events)}`);
  }
  if (creatorB.transport.drain().length !== 0) throw new Error("the creator does not answer it");
  console.log("  [Helper] request on its expired contact → MessageIgnored(Expired), nothing sent  ✓");

  const acceptCode = await codeOf(() => creatorC.protocol.accept(late.action));
  if (acceptCode !== "pairing_expired") {
    throw new Error(`a late accept must be refused with pairing_expired, got ${acceptCode ?? "no error"}`);
  }
  if (creatorC.transport.drain().length !== 0) throw new Error("a refused accept sends nothing");
  const sid = String(creatorC.protocol.secretId());
  const channels = JSON.parse(new TextDecoder().decode(await creatorC.channelStore.listHelpers(sid, ANY_HELPERS)));
  if (channels.length !== 0) throw new Error(`a refused accept records no channel, got ${JSON.stringify(channels)}`);
  console.log("  [Helper] accepting after the window → pairing_expired, no channel, nothing sent  ✓");

  await scanAsOwner(scannerC, await createContact(creatorC, 184n));
  const paired = await pumpAll([
    { node: scannerC, uri: "https://owner-expiry-c.example.com" },
    { node: creatorC, uri: "https://helper-expiry-c.example.com" },
  ]);
  if (!paired.some((e) => e.type === "PairingCompleted")) throw new Error("a fresh contact pairs");
  console.log("  [Helper] a fresh contact pairs  ✓");

  console.log("Pairing expiry flow passed.\n");
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

  // Initiate unpair on the Owner side.
  await owner.protocol.start(FlowKind.Unpair, {
    channel_id: longTermChannelId,
    memo: "decommissioning",
  });
  const unpairRequest = drainOne(owner, "Owner");
  console.log(
    `  [Owner]  start(Unpair) → UnpairRequest ${unpairRequest.length}B`,
  );

  // Helper auto-accepts (processAll satisfies ActionRequired events).
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

  // Owner processes the Ok response → Unpaired event + state dropped.
  const ownerEvents = await processAll(owner, unpairResponse);
  const ownerUnpaired = requireEvent(ownerEvents, "Unpaired", "Owner");
  if (ownerUnpaired.channel_id !== longTermChannelId) {
    throw new Error(
      `Owner Unpaired channel_id mismatch: ${ownerUnpaired.channel_id} ≠ ${longTermChannelId}`,
    );
  }
  console.log(`  [Owner]  processAll(UnpairResponse) → Unpaired`);

  for (const [label, node] of [["Owner", owner], ["Helper", helper]] as const) {
    if ((await node.channelStore.load(String(node.protocol.secretId()), longTermChannelId, "0")) !== null) {
      throw new Error(`${label}: the channel record must be removed after unpair`);
    }
  }
  console.log("  [Owner/Helper] channel records removed  ✓");

  // Unpairing is the owner's to start: a helper's attempt is refused.
  const helper2 = makeNode("Helper2", "https://helper.example.com");
  const { longTermChannelId: helperChannel } = await doPair(
    helper2,
    makeNode("Owner2", "https://owner.example.com"),
    8n,
    "Unpair/HelperInitiated",
  );
  await expectChannelCode("helper-initiated unpair", "role_mismatch", String(helperChannel), () =>
    helper2.protocol.start(FlowKind.Unpair, { channel_id: helperChannel, memo: "helper trying to unpair" }),
  );
  console.log("  [Helper] start(Unpair) → role_mismatch  ✓");

  console.log("\n✓ Unpairing flow passed.\n");
}


/**
 * Asserts both halves of the `replyTo` contract: (1) with `autoReplyTo`
 * `true`, every outbound channel-mode request carries this node's own
 * transports in `request.reply_to` on the inner request body; (2) a request
 * whose `replyTo` differs from the channel's stored peer endpoint is answered
 * at `replyTo`. Mirrors `run_reply_to_flow` in
 * `smoke-tests/rust/src/protocol.rs`.
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
  // `request.reply_to[0].uri === ownerUri`. The shared key is sitting in the
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
  const { longTermChannelId: defaultLongTermChannelId } = await doPair(
    helper2,
    ownerDefault,
    channelId,
    "ReplyTo/Default",
  );
  await ownerDefault.protocol.start(FlowKind.Discovery, {
    target: BigInt(defaultLongTermChannelId),
  });
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

  // Half (2): a request naming a replyTo the helper has never seen is
  // answered there, not at the owner's stored endpoint.
  const phantomUri = "https://phantom-replica.example.com";
  const crafted = primitives.discovery.request.produce(
    BigInt(longTermChannelId),
    sharedKey,
    [{ uri: phantomUri, protocol: 0 }],
  );
  helper.transport.drain();
  await processAll(helper, crafted.envelope);
  const answered = helper.transport.drain();
  if (answered.length !== 1 || answered[0]!.endpoint.uri !== phantomUri) {
    throw new Error(
      `the responder must route to request.replyTo (${phantomUri}), sent to [${answered.map((m) => m.endpoint.uri).join(", ")}]`,
    );
  }

  console.log("  ✓ auto_reply_to stamps replyTo on outbound requests");
  console.log("  ✓ default (no auto_reply_to) leaves replyTo unset");
  console.log("  ✓ the responder answers at an inbound replyTo, not the stored endpoint");
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
  await doPair(helperA, owner, helperAChannel, "Owner↔HelperA");
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
  requireEvent(ownerPairEvents, "PairingCompleted", "Owner/replica");
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
  const destPairing = requireEvent(destPairEvents, "PairingCompleted", "Destination/replica");
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
  // The replica handshake rekeys like any other, so everything downstream
  // keys on the rotated id the stores actually hold.
  const replicaChannel = BigInt(destPairing.channel_id);
  console.log(
    `  replica pair handshake: owner sees peer=${ownerReplicaPaired.peer_replica_id}, dest sees peer=${destReplicaPaired.peer_replica_id}, channel=${replicaChannel}  ✓`,
  );

  // 3. Cross-confirm fingerprints — channel is `Pending` until both
  //    sides verify, and ProtectSecret refuses to target a Pending
  //    replica channel.
  const ownerFp = await owner.protocol.getFingerprint(replicaChannel);
  const destFp = await destination.protocol.getFingerprint(replicaChannel);
  if (ownerFp !== destFp) {
    throw new Error(
      `replica fingerprint mismatch: owner=${ownerFp} dest=${destFp}`,
    );
  }
  await owner.protocol.verifyFingerprint(replicaChannel, destFp);
  await destination.protocol.verifyFingerprint(replicaChannel, ownerFp);
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
  const secretData = new TextEncoder().encode("secret-payload-for-replica-and-helper");
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
  for (const h of received.secret.helpers) {
    assertBytes(h.shared_key, "ReplicaSecretInstalled.secret.helpers[].shared_key");
  }
  for (const u of received.secret.secrets) {
    assertBytes(u.id, "ReplicaSecretInstalled.secret.secrets[].id");
    assertBytes(u.data, "ReplicaSecretInstalled.secret.secrets[].data");
  }
  assertBytes(received.secret.replicas?.shared_key, "ReplicaSecretInstalled.secret.replicas.shared_key");
  for (const sh of received.shares) {
    assertBytes(sh.committed_share, "ReplicaSecretInstalled.shares[].committed_share");
  }
  console.log(
    `  ReplicaSecretInstalled: secret=${received.secret.secrets.length}secret/${received.secret.helpers.length}helpers/${(received.secret.replicas?.members.length ?? 0)}members, shares=${received.shares.length}  ✓`,
  );

  // The destination acknowledges the copy, and the owner reports the ack.
  const ack = drainOne(destination, "Destination");
  const acked = (await owner.protocol.process(ack)).find(
    (e) => e.type === "ReplicaSecretAcked" && BigInt(e.channel_id) === replicaChannel,
  );
  if (acked?.type !== "ReplicaSecretAcked") {
    throw new Error("the owner must emit ReplicaSecretAcked for the destination's acknowledgement");
  }
  if (BigInt(acked.from_replica_id) !== destReplicaId || acked.status !== StatusEnum.Ok) {
    throw new Error(
      `ReplicaSecretAcked must come from ${destReplicaId} with status Ok, got from=${acked.from_replica_id} status=${acked.status}`,
    );
  }
  console.log(`  [Owner] ReplicaSecretAcked from=${acked.from_replica_id} status=${acked.status} memo=${JSON.stringify(acked.memo)}  ✓`);

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
  const helperStored = JSON.parse(new TextDecoder().decode(helperStoredBytes)).Helper;
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
  if (errorCode(caught) !== "replica_id_not_configured") {
    throw new Error(
      `scanner without replica_id must refuse to start a replica pair with replica_id_not_configured, got ${JSON.stringify(caught)}`,
    );
  }
  if (unconfiguredScanner.transport.drain().length !== 0) {
    throw new Error("no outbound traffic should have been queued");
  }
  console.log("  scanner without replica_id refuses to start replica pair: replica_id_not_configured  ✓");

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
  if (errorCode(caught2) !== "replica_id_not_configured") {
    throw new Error(
      `unconfigured responder must refuse a replica-mode PairRequest with replica_id_not_configured, got ${JSON.stringify(caught2)}`,
    );
  }
  console.log("  responder without replica_id refuses inbound replica PairRequest: replica_id_not_configured  ✓");

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
      secrets: [{ id: new Uint8Array([9]), name: "rate-limited", data: new TextEncoder().encode(data) }],
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
    secrets: [{ id: new Uint8Array([10]), name: "failing", data: new TextEncoder().encode("payload") }],
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
  assertBytes(rf.action, "RequestFailed.action");
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
 * Pairs an owner with HelperA and HelperB under `secretId` and returns the
 * helpers keyed by the endpoint the owner addresses them on.
 */
async function pairKeepVersionHelpers(
  secretId: bigint,
  channelA: bigint,
  channelB: bigint,
): Promise<{ owner: Node; helpersByUri: Map<string, [Node, string, string]> }> {
  const owner = makeNode("Owner", "https://owner.example.com", { secretId });
  const helperA = makeNode("HelperA", "https://helper-a.example.com", { secretId });
  const helperB = makeNode("HelperB", "https://helper-b.example.com", { secretId });
  const pairedA = await doPair(helperA, owner, channelA, "Owner↔HelperA");
  const pairedB = await doPair(helperB, owner, channelB, "Owner↔HelperB");
  owner.transport.drain();
  const helpersByUri = new Map<string, [Node, string, string]>([
    ["https://helper-a.example.com", [helperA, "HelperA", pairedA.longTermChannelId]],
    ["https://helper-b.example.com", [helperB, "HelperB", pairedB.longTermChannelId]],
  ]);
  return { owner, helpersByUri };
}

/**
 * Runs one ProtectSecret round. Every envelope addressed to a helper in
 * `deliverTo` is stored and answered; the rest are dropped.
 */
async function runKeepVersionRound(
  owner: Node,
  helpersByUri: Map<string, [Node, string, string]>,
  round: number,
  deliverTo: string[],
): Promise<void> {
  await owner.protocol.start(FlowKind.ProtectSecret, {
    secrets: [{ id: new Uint8Array([3]), name: "kept", data: new TextEncoder().encode(`round-${round}`) }],
    description: `round ${round}`,
  });
  for (const { endpoint, message } of owner.transport.drain()) {
    const [helper, label] = helpersByUri.get(endpoint.uri)!;
    if (!deliverTo.includes(label)) continue;
    requireEvent(await processAll(helper, message), "ShareStored", label);
    await owner.protocol.process(drainOne(helper, label));
  }
}

/** Throws unless the helper holds exactly `expected` on its channel. */
async function assertHeldVersions(
  helper: Node,
  label: string,
  secretId: bigint,
  channelId: string,
  expected: number[],
): Promise<void> {
  const versions = (await helper.shareStore.load(secretId.toString(), channelId, []))
    .map((share) => share.version)
    .sort((a, b) => a - b);
  if (versions.join(",") !== expected.join(",")) {
    throw new Error(`[${label}] must hold exactly versions [${expected.join(", ")}]; got [${versions.join(", ")}]`);
  }
}

/**
 * A helper that stores version V keeps V and the request's `keepVersion`, and
 * applies the rest through `ShareStore.removeVersions`. Rounds 1 to 3 keep
 * the previous version; round 4 keeps v2, so v3 must leave every helper's
 * store and v2 and v4 must stay.
 */
async function runHelperKeepVersionFlow(): Promise<void> {
  console.log("=== [Protocol] Helper keepVersion Flow ===\n");

  const secretId = 43n;
  const { owner, helpersByUri } = await pairKeepVersionHelpers(secretId, 21n, 22n);
  for (let round = 1; round <= 4; round++) {
    owner.shareStore.keep = round === 4 ? 2 : null;
    await runKeepVersionRound(owner, helpersByUri, round, ["HelperA", "HelperB"]);
  }

  for (const [helper, label, channelId] of helpersByUri.values()) {
    await assertHeldVersions(helper, label, secretId, channelId, [2, 4]);
    const reached = helper.shareStore.removeVersionsCalls.some(
      (c) => c.secretId === secretId.toString() && c.channelId === channelId && c.versions.join(",") === "3",
    );
    if (!reached) {
      throw new Error(`[${label}] removeVersions must reach the app store with [3]`);
    }
    console.log(`  [${label}] v4 with keepVersion 2 holds [2, 4] and removed v3 via removeVersions  ✓`);
  }

  console.log("\n✓ Helper keepVersion flow passed.\n");
}

/**
 * The owner asks `ShareStore.keepVersion` once per round and sends the same
 * answer to every helper. HelperB misses the v2 round, so after v3 (keeping
 * v1) both helpers hold exactly v1 and v3: HelperA drops the v2 it stored.
 */
async function runOwnerKeepVersionMissedRoundFlow(): Promise<void> {
  console.log("=== [Protocol] Owner keepVersion Across a Missed Round ===\n");

  const secretId = 44n;
  const { owner, helpersByUri } = await pairKeepVersionHelpers(secretId, 31n, 32n);
  owner.shareStore.keep = 0;
  await runKeepVersionRound(owner, helpersByUri, 1, ["HelperA", "HelperB"]);
  owner.shareStore.keep = 1;
  await runKeepVersionRound(owner, helpersByUri, 2, ["HelperA"]);
  console.log("  [Owner]  v2 reached HelperA only  ✓");
  await runKeepVersionRound(owner, helpersByUri, 3, ["HelperA", "HelperB"]);

  const asked = owner.shareStore.keepVersionCalls
    .filter((c) => c.secretId === secretId.toString())
    .map((c) => c.version);
  if (asked.join(",") !== "1,2,3") {
    throw new Error(`keepVersion must be asked once per round; got versions [${asked.join(", ")}]`);
  }
  console.log("  keepVersion asked once per round with the version being sent  ✓");

  for (const [helper, label, channelId] of helpersByUri.values()) {
    await assertHeldVersions(helper, label, secretId, channelId, [1, 3]);
    console.log(`  [${label}] holds exactly [1, 3] after the v3 round  ✓`);
  }

  console.log("\n✓ Owner keepVersion across a missed round passed.\n");
}

/**
 * A `keepVersion` equal to or greater than the version being shared fails
 * `start(ProtectSecret)` with `invalid_keep_version` before anything is sent.
 */
async function runInvalidKeepVersionFlow(): Promise<void> {
  console.log("=== [Protocol] Invalid keepVersion Fails the Round ===\n");

  const secretId = 47n;
  const { owner, helpersByUri } = await pairKeepVersionHelpers(secretId, 41n, 42n);
  await runKeepVersionRound(owner, helpersByUri, 1, ["HelperA", "HelperB"]);

  owner.shareStore.keep = 2;
  let error: DeRecError | undefined;
  try {
    await owner.protocol.start(FlowKind.ProtectSecret, {
      secrets: [{ id: new Uint8Array([3]), name: "kept", data: new TextEncoder().encode("round-2") }],
      description: "round 2",
    });
  } catch (e) {
    error = e as DeRecError;
  }
  if (error?.code !== "invalid_keep_version" || error.category !== "sharing") {
    throw new Error(`keepVersion 2 for v2 must fail with invalid_keep_version, got ${JSON.stringify(error)}`);
  }
  const sent = owner.transport.drain();
  if (sent.length !== 0) {
    throw new Error(`a round with an invalid keepVersion must send nothing; sent ${sent.length}`);
  }
  console.log("  [Owner]  keepVersion 2 for v2 → invalid_keep_version, nothing sent  ✓");

  console.log("\n✓ Invalid keepVersion flow passed.\n");
}

/**
 * The application's replay record: the identity of every envelope a device
 * sent or accepted, keyed on `envelope.message_id`.
 */
class SeenEnvelopes {
  private readonly ids = new Set<string>();

  private static idOf(bytes: Uint8Array): string {
    return Array.from(envelope.message_id(bytes).id, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  record(bytes: Uint8Array): void {
    this.ids.add(SeenEnvelopes.idOf(bytes));
  }

  contains(bytes: Uint8Array): boolean {
    return this.ids.has(SeenEnvelopes.idOf(bytes));
  }
}

function raisedUpdateChannelInfo(events: DeRecEvent[]): boolean {
  return events.some((e) => e.type === "ActionRequired" && e.action_kind === "UpdateChannelInfo");
}

/**
 * The library processes every copy of a message delivered within the inbound
 * window, including one delivered back to its own sender. An application that
 * records the message id of what it sends and accepts drops a replay, a copy
 * whose unauthenticated trace id was changed, and a reflection.
 */
async function runReplayDetectionFlow(): Promise<void> {
  console.log("=== [Protocol] Replay detection ===\n");

  const helper = makeNode("Helper", "https://helper.example.com");
  const owner = makeNode("Owner", "https://owner.example.com");
  const { longTermChannelId } = await doPair(helper, owner, 61n, "ReplayDetection");
  owner.transport.drain();
  const ownerSeen = new SeenEnvelopes();
  const helperSeen = new SeenEnvelopes();

  await owner.protocol.start(FlowKind.UpdateChannelInfo, {
    target: BigInt(longTermChannelId),
    communication_info: { name: "owner-renamed" },
  });
  const update = drainOne(owner, "Owner");
  ownerSeen.record(update);

  if (helperSeen.contains(update)) throw new Error("a first delivery is not in the record");
  let events = await helper.protocol.process(update);
  if (!raisedUpdateChannelInfo(events)) {
    throw new Error(`the update must raise ActionRequired; got ${JSON.stringify(events.map((e) => e.type))}`);
  }
  helperSeen.record(update);

  const restamped = envelope.apply_trace_id(update, 0x7e57n);
  if (byteArraysEqual(restamped, update)) throw new Error("the copy travels as different bytes");
  if (!helperSeen.contains(update) || !helperSeen.contains(restamped)) {
    throw new Error("the replay and the re-stamped copy must be recognised");
  }
  events = await helper.protocol.process(restamped);
  if (!raisedUpdateChannelInfo(events)) throw new Error("unchecked, the library processes the copy again");
  console.log("  [Helper] replay and re-stamped copy share the original's message id  ✓");

  if (!ownerSeen.contains(update)) throw new Error("the reflection must be recognised");
  events = await owner.protocol.process(update);
  if (!raisedUpdateChannelInfo(events)) throw new Error("unchecked, the library reads its own update as the peer's");
  console.log("  [Owner]  reflected update matches an outbound message id  ✓");

  console.log("Replay detection flow passed.\n");
}

/**
 * A helper that dropped v2 under v3's `keepVersion` does not store v2 again
 * when v2's request is delivered once more: it is ignored as `Superseded`,
 * unanswered.
 */
async function runSupersededShareRequestFlow(): Promise<void> {
  console.log("=== [Protocol] Superseded share request ===\n");

  const secretId = 0x6565n;
  const { owner, helpersByUri } = await pairKeepVersionHelpers(secretId, 63n, 64n);
  owner.shareStore.keep = 0;
  await runKeepVersionRound(owner, helpersByUri, 1, ["HelperA", "HelperB"]);

  await owner.protocol.start(FlowKind.ProtectSecret, {
    secrets: [{ id: new Uint8Array([3]), name: "kept", data: new TextEncoder().encode("round-2") }],
    description: "round 2",
  });
  let v2ForA: Uint8Array | undefined;
  for (const { endpoint, message } of owner.transport.drain()) {
    const [helper, label] = helpersByUri.get(endpoint.uri)!;
    if (label === "HelperA") v2ForA = message;
    requireEvent(await processAll(helper, message), "ShareStored", label);
    await owner.protocol.process(drainOne(helper, label));
  }
  if (!v2ForA) throw new Error("v2 was sent to HelperA");

  await runKeepVersionRound(owner, helpersByUri, 3, ["HelperA", "HelperB"]);
  const [helperA, , channelA] = helpersByUri.get("https://helper-a.example.com")!;
  await assertHeldVersions(helperA, "HelperA", secretId, channelA, [3]);

  const events = await helperA.protocol.process(v2ForA);
  const [ignored] = events;
  if (
    events.length !== 1 ||
    ignored?.type !== "MessageIgnored" ||
    ignored.reason !== "Superseded" ||
    ignored.channel_id !== channelA
  ) {
    throw new Error(`v2 delivered again must be MessageIgnored(Superseded); got ${JSON.stringify(events)}`);
  }
  await assertHeldVersions(helperA, "HelperA", secretId, channelA, [3]);
  if (helperA.transport.drain().length !== 0) throw new Error("a superseded request is not answered");
  console.log("  [HelperA] v2 delivered after v3 → MessageIgnored(Superseded), still holds [3]  ✓");

  console.log("Superseded share request flow passed.\n");
}

/** Asserts a byte field crossed the bridge as a `Uint8Array`. */
function assertBytes(value: unknown, label: string): void {
  if (!(value instanceof Uint8Array)) {
    throw new Error(`${label} must be a Uint8Array, got ${Object.prototype.toString.call(value)}`);
  }
}

/**
 * Byte span of the value of the first top-level field `field` in a protobuf
 * message: the payload of a length-delimited field, the encoding of any
 * other.
 */
function protoField(bytes: Uint8Array, field: number): { start: number; end: number } {
  let i = 0;
  const varint = (): number => {
    let value = 0;
    for (let shift = 0; ; shift += 7) {
      const b = bytes[i++];
      if (b === undefined) throw new Error("protoField: truncated varint");
      value += (b & 0x7f) * 2 ** shift;
      if (b < 0x80) return value;
    }
  };
  while (i < bytes.length) {
    const key = varint();
    const wireType = key & 7;
    let start = i;
    if (wireType === 0) {
      varint();
    } else if (wireType === 2) {
      const length = varint();
      start = i;
      i += length;
    } else if (wireType === 1) {
      i += 8;
    } else if (wireType === 5) {
      i += 4;
    } else {
      throw new Error(`protoField: unsupported wire type ${wireType}`);
    }
    if (Math.floor(key / 8) === field) return { start, end: i };
  }
  throw new Error(`protoField: field ${field} not found`);
}

/**
 * `envelope` with its encrypted body replaced by `plaintext`, sealed under
 * `sharedKey` the way the channel seals it: AES-256-GCM, the 12-byte nonce
 * prepended. `plaintext` keeps the original length, so the envelope's field
 * lengths are unchanged.
 */
async function resealBody(
  envelope: Uint8Array,
  sharedKey: Uint8Array,
  plaintext: (length: number) => Uint8Array,
): Promise<Uint8Array> {
  const body = protoField(envelope, 6);
  const nonce = envelope.slice(body.start, body.start + 12);
  const key = await crypto.subtle.importKey("raw", sharedKey.slice(), "AES-GCM", false, ["encrypt"]);
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce },
      key,
      plaintext(body.end - body.start - 12 - 16).slice(),
    ),
  );
  const out = envelope.slice();
  out.set(sealed, body.start + 12);
  return out;
}

/**
 * The helper's own size bound refuses a share before the application is
 * asked: the helper reports `ShareRefused` and the owner, answered with the
 * same status and memo, `ShareRejected(SIZE_LIMIT_EXCEEDED)`.
 */
async function runShareSizeRefusalFlow(): Promise<void> {
  console.log("=== [Protocol] Share size refusal Flow ===\n");

  const secretId = 47n;
  const owner = makeNode("Owner", "https://owner.example.com", { secretId });
  const helperA = makeNode("HelperA", "https://helper-a.example.com", {
    secretId,
    parameterRange: { max_share_size: 16n },
  });
  const helperB = makeNode("HelperB", "https://helper-b.example.com", { secretId });
  const pairedA = await doPair(helperA, owner, 71n, "Owner↔HelperA");
  await doPair(helperB, owner, 72n, "Owner↔HelperB");

  const started = await owner.protocol.start(FlowKind.ProtectSecret, {
    secrets: [{ id: new Uint8Array([11]), name: "oversized", data: new TextEncoder().encode("oversized") }],
  });
  const version = requireEvent(started, "ProtectSecretStarted", "Owner").version;

  const memo = "share size is outside the helper's accepted range";
  const ownerEvents: DeRecEvent[] = [];
  for (const { endpoint, message } of owner.transport.drain()) {
    const isA = endpoint.uri === "https://helper-a.example.com";
    const helper = isA ? helperA : helperB;
    const helperEvents = await processAll(helper, message);
    if (isA) {
      const refused = requireEvent(helperEvents, "ShareRefused", "HelperA");
      if (
        helperEvents.some((e) => e.type === "ActionRequired") ||
        refused.channel_id !== pairedA.longTermChannelId ||
        refused.version !== version ||
        refused.status !== StatusEnum.SizeLimitExceeded ||
        refused.memo !== memo
      ) {
        throw new Error(`HelperA must refuse the share itself, got ${JSON.stringify(helperEvents)}`);
      }
      console.log("  [HelperA] share over max_share_size → ShareRefused(SIZE_LIMIT_EXCEEDED), no ActionRequired  ✓");
    }
    ownerEvents.push(...(await owner.protocol.process(drainOne(helper, isA ? "HelperA" : "HelperB"))));
  }

  const rejected = ownerEvents.filter(
    (e): e is Extract<DeRecEvent, { type: "ShareRejected" }> => e.type === "ShareRejected",
  );
  if (
    rejected.length !== 1 ||
    rejected[0]!.channel_id !== pairedA.longTermChannelId ||
    rejected[0]!.version !== version ||
    rejected[0]!.status !== StatusEnum.SizeLimitExceeded ||
    rejected[0]!.memo !== memo
  ) {
    throw new Error(`expected one ShareRejected(SIZE_LIMIT_EXCEEDED) from HelperA, got ${JSON.stringify(rejected)}`);
  }
  console.log("  [Owner]   ShareRejected(SIZE_LIMIT_EXCEEDED) with the helper's memo  ✓");

  console.log("\n✓ Share size refusal flow passed.\n");
}

/**
 * With `auto_respond_on_failure` on, the library answers a failed request
 * itself: `RequestFailed` reports `responded: true` and carries no token, and
 * the owner observes `ShareRejected(FAIL)` with the generic memo.
 */
async function runAutoRespondOnFailureFlow(): Promise<void> {
  console.log("=== [Protocol] Failed request answered by the library ===\n");

  const secretId = 48n;
  const owner = makeNode("Owner", "https://owner.example.com", { secretId });
  const helperA = makeNode("HelperA", "https://helper-a.example.com", {
    secretId,
    autoRespondOnFailure: true,
  });
  const helperB = makeNode("HelperB", "https://helper-b.example.com", { secretId });
  const pairedA = await doPair(helperA, owner, 73n, "Owner↔HelperA");
  await doPair(helperB, owner, 74n, "Owner↔HelperB");

  helperA.shareStore.failSaves = true;
  const started = await owner.protocol.start(FlowKind.ProtectSecret, {
    secrets: [{ id: new Uint8Array([12]), name: "failing", data: new TextEncoder().encode("payload") }],
  });
  const version = requireEvent(started, "ProtectSecretStarted", "Owner").version;

  const ownerEvents: DeRecEvent[] = [];
  for (const { endpoint, message } of owner.transport.drain()) {
    const isA = endpoint.uri === "https://helper-a.example.com";
    const helper = isA ? helperA : helperB;
    const helperEvents = await processAll(helper, message);
    if (isA) {
      const rf = requireEvent(helperEvents, "RequestFailed", "HelperA");
      if (
        rf.channel_id !== pairedA.longTermChannelId ||
        rf.action_kind !== "StoreShare" ||
        !rf.responded ||
        "action" in rf ||
        rf.status !== StatusEnum.Fail ||
        rf.memo !== "request could not be processed"
      ) {
        throw new Error(`HelperA must answer the failure itself, got ${JSON.stringify(rf)}`);
      }
      console.log("  [HelperA] save fails → RequestFailed(responded=true), no action token  ✓");
    }
    const replies = helper.transport.drain();
    if (replies.length !== 1) {
      throw new Error(`${isA ? "HelperA" : "HelperB"} must send exactly one response, sent ${replies.length}`);
    }
    ownerEvents.push(...(await owner.protocol.process(replies[0]!.message)));
  }

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
    throw new Error(`expected one ShareRejected(FAIL) from HelperA, got ${JSON.stringify(rejected)}`);
  }
  console.log("  [Owner]   ShareRejected(status=FAIL, memo=\"request could not be processed\")  ✓");

  console.log("\n✓ Auto-respond-on-failure flow passed.\n");
}

/**
 * A request whose body decrypts under the channel key but does not decode is
 * still owed an answer. With `auto_respond_on_failure` off it is reported as
 * `RequestFailed(action_kind: "Failed", FORMAT_ERROR)` with a token that
 * `accept` refuses and `reject` answers with an `ErrorResponseMessage`, which
 * the sender reports as `ErrorResponseReceived`.
 */
async function runUndecodableRequestFlow(): Promise<void> {
  console.log("=== [Protocol] Undecodable request Flow ===\n");

  const secretId = 49n;
  const owner = makeNode("Owner", "https://owner.example.com", { secretId });
  const helper = makeNode("Helper", "https://helper.example.com", { secretId });
  const { longTermChannelId } = await doPair(helper, owner, 75n, "Owner↔Helper");

  await owner.protocol.start(FlowKind.Discovery, { target: BigInt(longTermChannelId) });
  const request = drainOne(owner, "Owner");
  const sharedKey = await owner.secretStore.load(secretId.toString(), longTermChannelId, 0);
  if (!sharedKey) throw new Error("owner shared_key missing");
  const undecodable = await resealBody(request, sharedKey, (n) => new Uint8Array(n).fill(0xff));

  const helperEvents = await helper.protocol.process(undecodable);
  const rf = requireEvent(helperEvents, "RequestFailed", "Helper");
  if (
    rf.channel_id !== longTermChannelId ||
    rf.action_kind !== "Failed" ||
    rf.responded ||
    rf.status !== StatusEnum.FormatError ||
    !rf.action
  ) {
    throw new Error(`Helper must report an unanswered RequestFailed(Failed, FORMAT_ERROR) with a token, got ${JSON.stringify(rf)}`);
  }
  assertBytes(rf.action, "RequestFailed.action");
  if (helper.transport.drain().length !== 0) {
    throw new Error("with auto_respond_on_failure off, the helper must not answer by itself");
  }
  console.log(`  [Helper] undecodable body → RequestFailed(action_kind=Failed, status=FORMAT_ERROR, memo="${rf.memo}") with a token  ✓`);

  const token = rf.action;
  await expectCode("accept(Failed token)", "invalid_input", () => helper.protocol.accept(token));
  if (helper.transport.drain().length !== 0) {
    throw new Error("a refused accept must send nothing");
  }
  console.log("  [Helper] accept(Failed token) refused (invalid_input), nothing sent  ✓");

  await helper.protocol.reject(rf.action, rf.status, rf.memo);
  const ownerEvents = await owner.protocol.process(drainOne(helper, "Helper"));
  const received = requireEvent(ownerEvents, "ErrorResponseReceived", "Owner");
  if (
    received.channel_id !== longTermChannelId ||
    received.status !== StatusEnum.FormatError ||
    received.memo !== rf.memo
  ) {
    throw new Error(`Owner must report the helper's ErrorResponse, got ${JSON.stringify(received)}`);
  }
  if (owner.transport.drain().length !== 0) {
    throw new Error("an ErrorResponseReceived is never answered");
  }
  console.log("  [Helper] reject(token) → ErrorResponseMessage; [Owner] ErrorResponseReceived(FORMAT_ERROR, same memo), not answered  ✓");

  console.log("\n✓ Undecodable request flow passed.\n");
}

/**
 * A channel whose share for the version was never confirmed has no proof on
 * the owner: `start(VerifyShares)` fails it locally with `NoProof` and sends
 * it no challenge, while a confirmed channel is challenged as usual.
 */
async function runVerifyNoProofFlow(): Promise<void> {
  console.log("=== [Protocol] VerifyShares without a proof ===\n");

  const secretId = 50n;
  const owner = makeNode("Owner", "https://owner.example.com", { secretId });
  const helperA = makeNode("HelperA", "https://helper-a.example.com", { secretId });
  const helperB = makeNode("HelperB", "https://helper-b.example.com", { secretId });
  const pairedA = await doPair(helperA, owner, 76n, "Owner↔HelperA");
  const pairedB = await doPair(helperB, owner, 77n, "Owner↔HelperB");

  helperA.shareStore.refuseSaves = true;
  const started = await owner.protocol.start(FlowKind.ProtectSecret, {
    secrets: [{ id: new Uint8Array([13]), name: "unconfirmed", data: new TextEncoder().encode("no-proof") }],
  });
  const version = requireEvent(started, "ProtectSecretStarted", "Owner").version;
  for (const { endpoint, message } of owner.transport.drain()) {
    const isA = endpoint.uri === "https://helper-a.example.com";
    const helper = isA ? helperA : helperB;
    await processAll(helper, message);
    await owner.protocol.process(drainOne(helper, isA ? "HelperA" : "HelperB"));
  }

  const events = await owner.protocol.start(FlowKind.VerifyShares, { secretId, version });
  const failed = events.filter(
    (e): e is Extract<DeRecEvent, { type: "VerifySharesFailed" }> => e.type === "VerifySharesFailed",
  );
  if (
    failed.length !== 1 ||
    failed[0]!.channel_id !== pairedA.longTermChannelId ||
    failed[0]!.version !== version ||
    failed[0]!.reason !== "NoProof"
  ) {
    throw new Error(`expected one VerifySharesFailed(NoProof) for HelperA, got ${JSON.stringify(events)}`);
  }
  if (!events.some((e) => e.type === "VerifySharesStarted" && e.channel_id === pairedB.longTermChannelId)) {
    throw new Error("HelperB, which confirmed, must still be challenged");
  }
  const sent = owner.transport.drain();
  if (sent.length !== 1 || sent[0]!.endpoint.uri !== "https://helper-b.example.com") {
    throw new Error(`only HelperB may be challenged, sent to [${sent.map((m) => m.endpoint.uri).join(", ")}]`);
  }
  console.log(`  [Owner] v${version}: HelperA VerifySharesFailed(reason=NoProof), no challenge; HelperB challenged  ✓`);

  console.log("\n✓ VerifyShares NoProof flow passed.\n");
}

/**
 * Verdicts on verification answers that do not prove the share: the answer
 * to a challenge a newer one replaced is ignored as `StaleResponse`, a proof
 * over bytes that differ from the owner's is `ShareVerifyInvalid`, and a
 * message whose plaintext envelope timestamp differs from the encrypted one
 * is ignored as `TimestampMismatch`.
 */
async function runVerificationVerdictsFlow(): Promise<void> {
  console.log("=== [Protocol] Verification verdicts ===\n");

  const secretId = 51n;
  const owner = makeNode("Owner", "https://owner.example.com", { secretId });
  const helperA = makeNode("HelperA", "https://helper-a.example.com", { secretId });
  const helperB = makeNode("HelperB", "https://helper-b.example.com", { secretId });
  const { longTermChannelId: channelA } = await doPair(helperA, owner, 78n, "Owner↔HelperA");
  await doPair(helperB, owner, 79n, "Owner↔HelperB");

  const started = await owner.protocol.start(FlowKind.ProtectSecret, {
    secrets: [{ id: new Uint8Array([14]), name: "verdicts", data: new TextEncoder().encode("verdicts") }],
  });
  const version = requireEvent(started, "ProtectSecretStarted", "Owner").version;
  for (const { endpoint, message } of owner.transport.drain()) {
    const isA = endpoint.uri === "https://helper-a.example.com";
    const helper = isA ? helperA : helperB;
    await processAll(helper, message);
    await owner.protocol.process(drainOne(helper, isA ? "HelperA" : "HelperB"));
  }

  const challenge = async (): Promise<{ traceId: string; message: Uint8Array }> => {
    const events = await owner.protocol.start(FlowKind.VerifyShares, {
      secretId,
      version,
      target: BigInt(channelA),
    });
    const { trace_id } = requireEvent(events, "VerifySharesStarted", "Owner");
    return { traceId: trace_id, message: drainOne(owner, "Owner") };
  };
  const answer = async (message: Uint8Array): Promise<Uint8Array> => {
    await processAll(helperA, message);
    return drainOne(helperA, "HelperA");
  };

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
    throw new Error(`the replaced challenge's answer must be MessageIgnored(StaleResponse), got ${JSON.stringify(stale)}`);
  }
  const current = await owner.protocol.process(secondAnswer);
  if (!current.some((e) => e.type === "ShareVerified" && e.channel_id === channelA && e.version === version)) {
    throw new Error(`the current challenge's answer must still verify, got ${JSON.stringify(current)}`);
  }
  console.log("  [Owner]   answer to a replaced challenge → MessageIgnored(StaleResponse); current answer → ShareVerified  ✓");

  // HelperA's stored share no longer matches the bytes the owner holds a
  // proof of, as after storage corruption.
  const sid = secretId.toString();
  const [stored] = await helperA.shareStore.load(sid, channelA, [version]);
  if (!stored) throw new Error(`HelperA must hold v${version}`);
  const share = protoField(stored.bytes, 1);
  const corrupted = stored.bytes.slice();
  corrupted[share.start + Math.floor((share.end - share.start) / 2)]! ^= 0xff;
  await helperA.shareStore.save(sid, channelA, { ...stored, bytes: corrupted });
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
  console.log("  [Owner]   proof over HelperA's corrupted share → ShareVerifyInvalid  ✓");

  // The plaintext envelope timestamp is moved one second off the encrypted
  // inner one.
  const { message } = await challenge();
  const timestamp = protoField(message, 5);
  const seconds = protoField(message.subarray(timestamp.start, timestamp.end), 1);
  const shifted = message.slice();
  shifted[timestamp.start + seconds.start]! ^= 0x01;
  const mismatched = await helperA.protocol.process(shifted);
  const dropped = mismatched[0];
  if (
    mismatched.length !== 1 ||
    dropped?.type !== "MessageIgnored" ||
    dropped.reason !== "TimestampMismatch" ||
    dropped.channel_id !== channelA
  ) {
    throw new Error(`a mismatched envelope timestamp must be MessageIgnored(TimestampMismatch), got ${JSON.stringify(mismatched)}`);
  }
  if (helperA.transport.drain().length !== 0) {
    throw new Error("a message ignored for its timestamp must not be answered");
  }
  console.log("  [HelperA] envelope timestamp ≠ inner timestamp → MessageIgnored(TimestampMismatch), nothing sent  ✓");

  console.log("\n✓ Verification verdicts flow passed.\n");
}

/**
 * `start` refuses a weight assignment the round cannot honour — a weight
 * that alone meets the threshold, or a weight for a channel that is not a
 * paired helper — with `invalid_weight`, before anything is sent.
 */
async function runInvalidWeightFlow(): Promise<void> {
  console.log("=== [Protocol] invalid_weight from start ===\n");

  const secretId = 52n;
  const owner = makeNode("Owner", "https://owner.example.com", { secretId });
  const helperA = makeNode("HelperA", "https://helper-a.example.com", { secretId });
  const helperB = makeNode("HelperB", "https://helper-b.example.com", { secretId });
  const { longTermChannelId: channelA } = await doPair(helperA, owner, 80n, "Owner↔HelperA");
  await doPair(helperB, owner, 81n, "Owner↔HelperB");

  for (const [what, weights] of [
    ["a weight equal to the threshold", new Map([[BigInt(channelA), THRESHOLD]])],
    ["a weight for an unpaired channel", new Map([[0xbadn, 1]])],
  ] as const) {
    await expectCode(what, "invalid_weight", () =>
      owner.protocol.start(FlowKind.ProtectSecret, {
        secrets: [{ id: new Uint8Array([15]), name: "weighted", data: new Uint8Array([1]) }],
        weights,
      }),
    );
    if (owner.transport.drain().length !== 0) {
      throw new Error(`${what}: nothing may be sent`);
    }
    console.log(`  ${what} → invalid_weight, nothing sent  ✓`);
  }

  console.log("\n✓ invalid_weight flow passed.\n");
}

/**
 * A replica destination's library refuses a copy whose share map does not
 * verify: it reports `ReplicaSecretRefused` and writes nothing. The copy here
 * is a catch-up served from the source's stores, one of whose tracked shares
 * was corrupted, so it is not answered.
 */
async function runReplicaSecretRefusedFlow(): Promise<void> {
  console.log("=== [Protocol] Replica copy refused ===\n");

  const secretId = 0x5ec7n;
  const source = {
    node: makeNode("Source", "https://refusing-source.example.com", { secretId, replicaId: 0x7171n }),
    uri: "https://refusing-source.example.com",
  };
  const helperA = {
    node: makeNode("HelperA", "https://refusing-helper-a.example.com", { secretId }),
    uri: "https://refusing-helper-a.example.com",
  };
  const helperB = {
    node: makeNode("HelperB", "https://refusing-helper-b.example.com", { secretId }),
    uri: "https://refusing-helper-b.example.com",
  };
  const destination = {
    node: makeNode("Destination", "https://refusing-destination.example.com", { secretId, replicaId: 0x7272n }),
    uri: "https://refusing-destination.example.com",
  };
  const { longTermChannelId: channelA } = await doPair(helperA.node, source.node, 82n, "Source↔HelperA");
  await doPair(helperB.node, source.node, 83n, "Source↔HelperB");

  const { rekeyed } = await pairReplicaHandshake(source, destination, 84n);
  // The source confirms first, so its publish reaches the destination while
  // the destination still shows the code and is ignored there.
  const destinationFp = await destination.node.protocol.getFingerprint(rekeyed);
  await source.node.protocol.verifyFingerprint(rekeyed, destinationFp);
  await pumpAll([source, helperA, helperB, destination]);

  const sid = secretId.toString();
  const version = (await source.node.userSecretStore.loadLatest(sid))?.version;
  if (version === undefined) throw new Error("the source must hold a snapshot");
  const [tracked] = await source.node.shareStore.load(sid, channelA, [version]);
  if (!tracked) throw new Error(`the source must track HelperA's v${version} share`);
  // One byte of the committed share's Merkle commitment: the share still
  // decodes, and its proof no longer opens to the commitment.
  const commitment = protoField(tracked.bytes, 2);
  const corrupted = tracked.bytes.slice();
  corrupted[commitment.start]! ^= 0xff;
  await source.node.shareStore.save(sid, channelA, { ...tracked, bytes: corrupted });

  const sourceFp = await source.node.protocol.getFingerprint(rekeyed);
  await destination.node.protocol.verifyFingerprint(rekeyed, sourceFp);
  await destination.node.protocol.start(FlowKind.ReplicaDiscovery);
  const events = await pumpAll([destination, source]);
  const refused = requireEvent(events, "ReplicaSecretRefused", "Destination");
  if (
    BigInt(refused.from_replica_id) !== 0x7171n ||
    refused.secret_id !== sid ||
    refused.version !== version ||
    refused.status !== StatusEnum.VerificationFailed ||
    refused.memo !== "CommittedDeRecShare Merkle proof verification failed"
  ) {
    throw new Error(`unexpected ReplicaSecretRefused ${JSON.stringify(refused)}`);
  }
  if (events.some((e) => e.type === "ReplicaSecretInstalled" || e.type === "ReplicaSecretReceived")) {
    throw new Error("a refused copy must not be installed");
  }
  if ((await destination.node.userSecretStore.loadLatest(sid)) !== null) {
    throw new Error("a refused copy must write nothing");
  }
  console.log(`  [Destination] catch-up with a corrupted share → ReplicaSecretRefused(status=${refused.status}), nothing written  ✓`);

  console.log("\n✓ Replica copy refused flow passed.\n");
}

/** `true` for either replica arrival event: an install or an update. */
function isReplicaArrival(
  e: DeRecEvent,
): e is Extract<DeRecEvent, { type: "ReplicaSecretReceived" | "ReplicaSecretInstalled" }> {
  return e.type === "ReplicaSecretReceived" || e.type === "ReplicaSecretInstalled";
}

/** The channels of every `ShareVerified` in `events`. */
function verifiedChannels(events: DeRecEvent[]): Set<string> {
  return new Set(
    events.flatMap((e) => (e.type === "ShareVerified" ? [e.channel_id] : [])),
  );
}

/**
 * A stored roster read back as JSON. The stored record carries ids as bare
 * JSON numbers, beyond what a JS number holds exactly, so they are quoted
 * before parsing.
 */
async function storedRoster(
  node: Node,
): Promise<Array<{
  replica_id: string;
  channel_id: string;
  transports: Array<{ uri: string }>;
  communication_info?: Record<string, string>;
}>> {
  const text = new TextDecoder().decode(
    await node.channelStore.listReplicas(String(node.protocol.secretId()), ANY_REPLICAS),
  );
  return JSON.parse(text.replace(/"(replica_id|channel_id)":(\d+)/g, '"$1":"$2"'));
}

/**
 * A replica destination that received a mirrored vault can verify the helpers
 * holding that vault's shares. It never spoke to those helpers and never split
 * the secret: the roster gives it each helper's channel and key, and the share
 * map the committed bytes to check a proof against. A version it pulled with
 * `ReplicaDiscovery` is as verifiable as one pushed to it. Mirrors
 * `run_replica_mirror_then_verify_flow` in `smoke-tests/rust/src/protocol.rs`.
 */
async function runReplicaMirrorThenVerifyFlow(): Promise<void> {
  console.log("=== [Protocol] Replica mirror-then-verify Flow ===\n");

  const source: AddressedNode = {
    node: makeNode("Source", "https://mirror-source.example.com", {
      secretId: 0xC0FFEEn,
      replicaId: 0xAAAA_AAAA_AAAA_AAAAn,
    }),
    uri: "https://mirror-source.example.com",
  };
  const helperA: AddressedNode = {
    node: makeNode("HelperA", "https://mirror-helper-a.example.com"),
    uri: "https://mirror-helper-a.example.com",
  };
  const helperB: AddressedNode = {
    node: makeNode("HelperB", "https://mirror-helper-b.example.com"),
    uri: "https://mirror-helper-b.example.com",
  };
  const destination: AddressedNode = {
    node: makeNode("Destination", "https://mirror-destination.example.com", {
      replicaId: 0xBBBB_BBBB_BBBB_BBBBn,
    }),
    uri: "https://mirror-destination.example.com",
  };
  const all = [source, helperA, helperB, destination];

  const { longTermChannelId: channelA } = await doPair(helperA.node, source.node, 1n, "Source↔HelperA");
  const { longTermChannelId: channelB } = await doPair(helperB.node, source.node, 2n, "Source↔HelperB");
  const { rekeyed } = await pairReplicaHandshake(source, destination, 3n);
  await crossConfirmFingerprint(source.node, destination.node, rekeyed);
  // The pair-completion auto-publish is not the round under test.
  await pumpAll(all);

  const protect = (data: string, description: string) =>
    source.node.protocol.start(FlowKind.ProtectSecret, {
      secrets: [{ id: new Uint8Array([1]), name: "mirrored secret", data: new TextEncoder().encode(data) }],
      description,
    });

  await protect("vault-contents", "mirror round");
  const mirrored = (await pumpAll(all)).find(isReplicaArrival);
  if (!mirrored) throw new Error("the destination must report the mirrored vault");
  if (mirrored.shares.length !== 2) {
    throw new Error(`the mirrored payload must carry one share per helper, got ${mirrored.shares.length}`);
  }

  // The destination acts as the owner of the vault it received, over its own
  // partition: it was never configured with the source's secret id.
  const destinationSid = destination.node.protocol.secretId();
  for (const channelId of [channelA, channelB]) {
    const tracked = await destination.node.shareStore.load(String(destinationSid), channelId, [mirrored.version]);
    if (tracked.length !== 1 || tracked[0]!.bytes.length === 0) {
      throw new Error(
        `the destination must hold the committed bytes for helper channel ${channelId} at v${mirrored.version}, got ${tracked.length} share(s)`,
      );
    }
  }
  console.log(`  [Destination] holds a tracking share per helper at the mirrored v${mirrored.version}  ✓`);

  const verifyOnDestination = async (version: number): Promise<Set<string>> => {
    await destination.node.protocol.start(FlowKind.VerifyShares, { secretId: destinationSid, version });
    return verifiedChannels(await pumpAll(all));
  };
  const pushed = await verifyOnDestination(mirrored.version);
  if (!pushed.has(channelA) || !pushed.has(channelB)) {
    throw new Error(`the destination must verify both helpers on a pushed version, verified ${JSON.stringify([...pushed])}`);
  }
  console.log(`  [Destination] VerifyShares v${mirrored.version} (pushed) → ShareVerified from both helpers  ✓`);

  const missed = await protect("vault-contents-v2", "round the destination misses");
  const missedVersion = requireEvent(missed, "ProtectSecretStarted", "Source").version;
  if (missedVersion <= mirrored.version) {
    throw new Error(`the missed round must be newer: v${missedVersion} after v${mirrored.version}`);
  }
  // Delivered to the helpers only: the destination's copy is dropped.
  for (const { endpoint, message } of source.node.transport.drain()) {
    const helper = [helperA, helperB].find((h) => h.uri === endpoint.uri);
    if (helper) await processAll(helper.node, message);
  }
  await pumpAll([source, helperA, helperB]);

  await destination.node.protocol.start(FlowKind.ReplicaDiscovery);
  const caughtUp = await pumpAll(all);
  if (!caughtUp.some((e) => e.type === "ReplicaSecretReceived" && e.version === missedVersion)) {
    throw new Error(`the catch-up must hydrate the missed v${missedVersion}, got [${caughtUp.map((e) => e.type).join(", ")}]`);
  }
  const pulled = await verifyOnDestination(missedVersion);
  if (!pulled.has(channelA) || !pulled.has(channelB)) {
    throw new Error(`a version obtained by catch-up must be as verifiable as a pushed one, verified ${JSON.stringify([...pulled])}`);
  }
  console.log(`  [Destination] VerifyShares v${missedVersion} (pulled by catch-up) → ShareVerified from both helpers  ✓`);

  console.log("\n✓ Replica mirror-then-verify flow passed.\n");
}

/**
 * A published roster describes every member the same way, the publisher
 * included: every endpoint it advertised, in preference order, and its
 * `communication_info`. Anything rebuilding the group from a `Secret` can
 * otherwise neither name nor reach the member that wrote it. Mirrors
 * `run_replica_roster_describes_every_member_flow` in
 * `smoke-tests/rust/src/protocol.rs`.
 */
async function runReplicaRosterDescribesEveryMemberFlow(): Promise<void> {
  console.log("=== [Protocol] Replica roster describes every member Flow ===\n");

  const sourceId = 0xCCCC_CCCC_CCCC_CCCCn;
  const destinationId = 0xDDDD_DDDD_DDDD_DDDDn;
  const identity = (label: string, name: string, replicaId: bigint) => {
    const uri = `https://${label}.example.com`;
    const endpoints = [uri, `grpcs://${label}.example.com:443`];
    const channelStore = new InMemoryChannelStore();
    const shareStore = new InMemoryShareStore();
    const secretStore = new InMemorySecretStore();
    const userSecretStore = new InMemoryUserSecretStore();
    const stateStore = new InMemoryStateStore();
    const transport = new RecordingTransport();
    const protocol = new DeRecProtocolBuilder(DEFAULT_TEST_SECRET_ID)
      .withStores({ channelStore, shareStore, secretStore, userSecretStore, stateStore })
      .withTransport(transport)
      .withOwnTransports([
        { uri: endpoints[0]!, protocol: "https" },
        { uri: endpoints[1]!, protocol: "grpc" },
      ])
      .withThreshold(THRESHOLD)
      .withReplicaId(replicaId)
      .withCommunicationInfo({ name })
      .build();
    const node: Node = { protocol, transport, channelStore, shareStore, secretStore, userSecretStore, stateStore };
    return { entry: { node, uri } as AddressedNode, endpoints };
  };
  const source = identity("roster-source", "Alice-1", sourceId);
  const destination = identity("roster-destination", "Alice-2", destinationId);
  const scope = [source.entry, destination.entry];

  const { rekeyed: groupChannel } = await pairReplicaHandshake(source.entry, destination.entry, 0x0570n);
  await crossConfirmFingerprint(source.entry.node, destination.entry.node, groupChannel);
  await pumpAll(scope);

  await source.entry.node.protocol.start(FlowKind.ProtectSecret, {
    secrets: [{ id: new Uint8Array([1]), name: "roster secret", data: new TextEncoder().encode("roster-contents") }],
  });
  const secret = (await pumpAll(scope)).filter(isReplicaArrival).pop()?.secret;
  if (!secret) throw new Error("the destination must receive the published secret");

  const describe = (transports: Array<{ uri: string }>, info?: Record<string, string> | null) =>
    JSON.stringify([transports.map((t) => t.uri), info?.name ?? null]);
  const expected = [
    [String(sourceId), source.endpoints, "Alice-1"],
    [String(destinationId), destination.endpoints, "Alice-2"],
  ] as const;

  const members = secret.replicas?.members ?? [];
  if (members.length !== 2) {
    throw new Error(`both members are published, got ${JSON.stringify(members)}`);
  }
  for (const [replicaId, endpoints, name] of expected) {
    const member = members.find((m) => m.replica_id === replicaId);
    if (!member) throw new Error(`member ${replicaId} missing from ${JSON.stringify(members)}`);
    const got = describe(member.transports, member.communication_info);
    if (got !== describe(endpoints.map((uri) => ({ uri })), { name })) {
      throw new Error(`published row for ${name}: got ${got}`);
    }
  }
  console.log("  published roster names and reaches the writer as well as its peer  ✓");

  // The destination's record of the source must be as complete as its
  // record of itself.
  const stored = await storedRoster(destination.entry.node);
  for (const [replicaId, endpoints, name] of expected) {
    const member = stored.find((m) => m.replica_id === replicaId);
    if (!member) throw new Error(`the destination holds no row for ${replicaId}`);
    const got = describe(member.transports, member.communication_info);
    if (got !== describe(endpoints.map((uri) => ({ uri })), { name })) {
      throw new Error(`the destination's stored row for ${name}: got ${got}`);
    }
  }
  console.log("  destination stores every member, itself included, the same way  ✓");

  console.log("\n✓ Replica roster describes every member flow passed.\n");
}

/**
 * A destination can verify the versions it was synced, and only those. Alice
 * protects across three helpers (v1), then pairs Bob, whose joining publishes
 * v2. Both verify v2; only Alice verifies v1. Bob asking about v1 fails each
 * channel locally with `NoProof` and sends no challenge, because he holds no
 * reference bytes, not because a helper is at fault. A synced destination is
 * already provisioned, so `restore` refuses it. Mirrors
 * `run_replica_verifies_only_synced_versions_flow` in
 * `smoke-tests/rust/src/protocol.rs`.
 */
async function runReplicaVerifiesOnlySyncedVersionsFlow(): Promise<void> {
  console.log("=== [Protocol] Replica verifies only synced versions Flow ===\n");

  const alice: AddressedNode = {
    node: makeNode("Alice", "https://synced-alice.example.com", { secretId: 0xC0FFEEn, replicaId: 0xA11CEn }),
    uri: "https://synced-alice.example.com",
  };
  const helpers: AddressedNode[] = [1, 2, 3].map((i) => ({
    node: makeNode(`Helper${i}`, `https://synced-helper-${i}.example.com`),
    uri: `https://synced-helper-${i}.example.com`,
  }));
  const bob: AddressedNode = {
    node: makeNode("Bob", "https://synced-bob.example.com", { replicaId: 0xB0Bn }),
    uri: "https://synced-bob.example.com",
  };
  const all = [alice, ...helpers, bob];

  const channels: string[] = [];
  for (const [i, helper] of helpers.entries()) {
    channels.push((await doPair(helper.node, alice.node, BigInt(i + 1), `Alice↔Helper${i + 1}`)).longTermChannelId);
  }

  const started = await alice.node.protocol.start(FlowKind.ProtectSecret, {
    secrets: [{ id: new Uint8Array([1]), name: "wallet", data: new TextEncoder().encode("alice-secret-v1") }],
  });
  const v1 = requireEvent(started, "ProtectSecretStarted", "Alice").version;
  await pumpAll([alice, ...helpers]);

  // Confirming the fingerprint puts Bob on the roster, and the publish that
  // follows carries v2 to him.
  const { rekeyed } = await pairReplicaHandshake(alice, bob, 4n);
  await crossConfirmFingerprint(alice.node, bob.node, rekeyed);
  const synced = (await pumpAll(all)).find(isReplicaArrival);
  if (!synced) throw new Error("Bob must be synced when he joins the roster");
  const v2 = synced.version;
  if (v2 <= v1) throw new Error(`joining must publish a newer version (v1=${v1}, v2=${v2})`);

  await expectCode("restore on a synced destination", "already_restored", () =>
    bob.node.protocol.restore(synced.secret, v2),
  );
  console.log("  [Bob] restore on a synced destination → already_restored  ✓");

  const aliceSid = alice.node.protocol.secretId();
  const bobSid = bob.node.protocol.secretId();
  for (const channelId of channels) {
    for (const [label, node, sid, version, want] of [
      ["Alice", alice.node, aliceSid, v1, 1],
      ["Alice", alice.node, aliceSid, v2, 1],
      ["Bob", bob.node, bobSid, v1, 0],
      ["Bob", bob.node, bobSid, v2, 1],
    ] as const) {
      const rows = (await node.shareStore.load(String(sid), channelId, [version])).length;
      if (rows !== want) {
        throw new Error(`${label} must hold ${want} tracking share(s) for helper ${channelId} at v${version}, got ${rows}`);
      }
    }
  }
  console.log(`  tracking shares: Alice v${v1}+v${v2}, Bob v${v2} only  ✓`);

  for (const [who, node, sid, version] of [
    ["Alice", alice.node, aliceSid, v2],
    ["Bob", bob.node, bobSid, v2],
    ["Alice", alice.node, aliceSid, v1],
  ] as const) {
    await node.protocol.start(FlowKind.VerifyShares, { secretId: sid, version });
    const verified = verifiedChannels(await pumpAll(all));
    if (!channels.every((c) => verified.has(c))) {
      throw new Error(`${who} must verify v${version} against all three helpers, verified ${JSON.stringify([...verified])}`);
    }
  }

  const events = await bob.node.protocol.start(FlowKind.VerifyShares, { secretId: bobSid, version: v1 });
  const noProof = new Set(
    events.flatMap((e) => (e.type === "VerifySharesFailed" && e.reason === "NoProof" ? [e.channel_id] : [])),
  );
  if (!channels.every((c) => noProof.has(c))) {
    throw new Error(`Bob holds no v${v1} bytes, so every helper channel fails with NoProof, got ${JSON.stringify(events)}`);
  }
  if (bob.node.transport.drain().length !== 0) {
    throw new Error(`no v${v1} challenge is sent without a proof to check the answer against`);
  }
  console.log(`  alice: v${v1} ✓ v${v2} ✓   bob: v${v1} NoProof (never synced) v${v2} ✓  ✓`);

  console.log("\n✓ Replica verifies only synced versions flow passed.\n");
}

/**
 * Pair `owner` with three helpers, publish one secret across them, deliver the
 * round, and return the helpers, their channels and the published version.
 */
async function protectAcrossThree(
  owner: Node,
  data: Uint8Array,
  secretByte: number,
  name: string,
): Promise<{ helpers: AddressedNode[]; channels: string[]; version: number }> {
  const helpers: AddressedNode[] = ["a", "b", "c"].map((h) => ({
    node: makeNode(`Helper${h.toUpperCase()}`, `https://${name}-helper-${h}.example.com`),
    uri: `https://${name}-helper-${h}.example.com`,
  }));
  const channels: string[] = [];
  for (const [i, helper] of helpers.entries()) {
    channels.push((await doPair(helper.node, owner, BigInt(i + 1), `Owner↔Helper${i}`)).longTermChannelId);
  }
  const started = await owner.protocol.start(FlowKind.ProtectSecret, {
    secrets: [{ id: new Uint8Array([secretByte]), name, data }],
  });
  const version = requireEvent(started, "ProtectSecretStarted", "Owner").version;
  return { helpers, channels, version };
}

/**
 * One of three helpers no longer holds the version asked for. It answers both
 * the verification challenge and the recovery request with
 * `UNKNOWN_SHARE_VERSION`; the owner reports `ShareVerifyRejected` and
 * `RecoveryShareRefused` and recovers from the other two. The refusing helper
 * answers first, so a refusal collected as a share would poison every
 * reconstruction after it. Mirrors `run_helper_without_the_version_flow` in
 * `smoke-tests/rust/src/protocol.rs`.
 */
async function runHelperWithoutTheVersionFlow(): Promise<void> {
  console.log("=== [Protocol] Helper without the version Flow ===\n");

  const ownerUri = "https://forgetful-owner.example.com";
  const owner = makeNode("Owner", ownerUri, { secretId: 42n });
  const secretData = new TextEncoder().encode("three helpers, one forgetful");
  const { helpers, channels, version } = await protectAcrossThree(owner, secretData, 7, "forgetful");
  const all = [{ node: owner, uri: ownerUri }, ...helpers];
  await pumpAll(all);
  const [helperA] = helpers;
  const [channelA] = channels;
  if (!helperA || !channelA) throw new Error("three helpers are paired");

  await helperA.node.shareStore.removeVersions(String(helperA.node.protocol.secretId()), channelA, [version]);

  const ownerSid = owner.protocol.secretId();
  await owner.protocol.start(FlowKind.VerifyShares, { secretId: ownerSid, version });
  const verifyEvents = await pumpAll(all);
  const rejected = verifyEvents.flatMap((e) =>
    e.type === "ShareVerifyRejected" ? [[e.channel_id, e.status]] : [],
  );
  if (JSON.stringify(rejected) !== JSON.stringify([[channelA, StatusEnum.UnknownShareVersion]])) {
    throw new Error(`HelperA must refuse the challenge with UNKNOWN_SHARE_VERSION, got ${JSON.stringify(rejected)}`);
  }
  const verified = verifyEvents.filter((e) => e.type === "ShareVerified").length;
  if (verified !== 2) throw new Error(`HelperB and HelperC still prove possession, got ${verified}`);
  console.log("  [Owner] VerifyShares → ShareVerifyRejected(UNKNOWN_SHARE_VERSION) from HelperA, 2 ShareVerified  ✓");

  const asked = (await owner.protocol.start(FlowKind.RecoverSecret, { secretId: ownerSid, version })).filter(
    (e) => e.type === "RecoverSecretStarted",
  ).length;
  if (asked !== 3) throw new Error(`every helper is asked for its share, got ${asked}`);
  const recoveryEvents = await pumpAll(all);
  const refused = recoveryEvents.flatMap((e) =>
    e.type === "RecoveryShareRefused" ? [[e.channel_id, e.version, e.status]] : [],
  );
  if (JSON.stringify(refused) !== JSON.stringify([[channelA, version, StatusEnum.UnknownShareVersion]])) {
    throw new Error(`the app sees exactly one refusal, from HelperA, got ${JSON.stringify(refused)}`);
  }
  if (recoveryEvents.some((e) => e.type === "RecoveryIncomplete" || e.type === "RecoveryConflict")) {
    throw new Error(`a refusal must not leave the recovery undecided: ${JSON.stringify(recoveryEvents)}`);
  }
  const recovered = recoveryEvents.find((e) => e.type === "SecretRecovered");
  if (
    recovered?.type !== "SecretRecovered" ||
    !recovered.secret.secrets.some((s) => s.id.length === 1 && s.id[0] === 7 && byteArraysEqual(s.data, secretData))
  ) {
    throw new Error(`the two remaining helpers must complete the recovery, got [${recoveryEvents.map((e) => e.type).join(", ")}]`);
  }
  console.log("  [Owner] RecoverSecret → RecoveryShareRefused(UNKNOWN_SHARE_VERSION) from HelperA, SecretRecovered from the rest  ✓");

  const missing = version + 100;
  await owner.protocol.start(FlowKind.RecoverSecret, { secretId: ownerSid, version: missing });
  const missingEvents = await pumpAll(all);
  const incomplete = missingEvents.flatMap((e) =>
    e.type === "RecoveryIncomplete" ? [[e.secret_id, e.version, e.shares_received]] : [],
  );
  if (JSON.stringify(incomplete) !== JSON.stringify([[String(ownerSid), missing, 0]])) {
    throw new Error(`a version no helper holds closes as RecoveryIncomplete naming its secret, got ${JSON.stringify(missingEvents)}`);
  }
  console.log("  [Owner] RecoverSecret for a version no helper holds → RecoveryIncomplete naming the secret, 0 shares  ✓");

  console.log("\n✓ Helper without the version flow passed.\n");
}

/**
 * One of three helpers holds a tampered share: one byte of its first
 * subshare's `y` flipped in storage, so it still answers OK. The owner reports
 * it as `RecoveryShareCorrupted(InvalidProof)` and recovers from the other
 * two. The tampered helper answers first, so a corrupted share that were
 * collected would fail every reconstruction after it. Mirrors
 * `run_corrupted_share_flow` in `smoke-tests/rust/src/protocol.rs`.
 */
async function runCorruptedShareFlow(): Promise<void> {
  console.log("=== [Protocol] Corrupted share Flow ===\n");

  const ownerUri = "https://tampered-owner.example.com";
  const owner = makeNode("Owner", ownerUri, { secretId: 43n });
  const secretData = new TextEncoder().encode("three helpers, one tampered");
  const { helpers, channels, version } = await protectAcrossThree(owner, secretData, 8, "tampered");
  const all = [{ node: owner, uri: ownerUri }, ...helpers];
  await pumpAll(all);
  const [helperA] = helpers;
  const [channelA] = channels;
  if (!helperA || !channelA) throw new Error("three helpers are paired");

  // StoreShareRequest.share → CommittedDeRecShare.deRecShare →
  // DeRecShare.subshares[0] → Subshare.y. Lengths are unchanged, so the
  // byte is flipped in place.
  const helperSid = String(helperA.node.protocol.secretId());
  const [stored] = await helperA.node.shareStore.load(helperSid, channelA, [version]);
  if (!stored) throw new Error(`HelperA must hold v${version}`);
  const bytes = stored.bytes.slice();
  let offset = 0;
  let view = bytes;
  for (const field of [1, 1, 2, 2]) {
    const span = protoField(view, field);
    offset += span.start;
    view = view.subarray(span.start, span.end);
  }
  bytes[offset]! ^= 0x01;
  await helperA.node.shareStore.save(helperSid, channelA, { ...stored, bytes });

  await owner.protocol.start(FlowKind.RecoverSecret, { secretId: owner.protocol.secretId(), version });
  const recoveryEvents = await pumpAll(all);
  const corrupted = recoveryEvents.flatMap((e) =>
    e.type === "RecoveryShareCorrupted" ? [[e.channel_id, e.version, e.reason]] : [],
  );
  if (JSON.stringify(corrupted) !== JSON.stringify([[channelA, version, "InvalidProof"]])) {
    throw new Error(`the app sees exactly one corrupted share, from HelperA, got ${JSON.stringify(corrupted)}`);
  }
  if (recoveryEvents.some((e) => e.type === "RecoveryIncomplete" || e.type === "RecoveryConflict")) {
    throw new Error(`a corrupted share must not leave the recovery undecided: ${JSON.stringify(recoveryEvents)}`);
  }
  const recovered = recoveryEvents.find((e) => e.type === "SecretRecovered");
  if (
    recovered?.type !== "SecretRecovered" ||
    !recovered.secret.secrets.some((s) => s.id.length === 1 && s.id[0] === 8 && byteArraysEqual(s.data, secretData))
  ) {
    throw new Error(`the two untouched helpers must complete the recovery, got [${recoveryEvents.map((e) => e.type).join(", ")}]`);
  }
  console.log("  [Owner] RecoverSecret → RecoveryShareCorrupted(InvalidProof) from HelperA, SecretRecovered from the rest  ✓");

  console.log("\n✓ Corrupted share flow passed.\n");
}

/**
 * A `ProtectSecret` fan-out whose send to one helper fails reports
 * `ProtectSecretFailed` for that helper and `ProtectSecretStarted` for the
 * other: one failure neither stops the fan-out nor fails the call. Mirrors
 * `run_protect_secret_per_target_failure_flow` in
 * `smoke-tests/rust/src/protocol.rs`.
 */
async function runProtectSecretPerTargetFailureFlow(): Promise<void> {
  console.log("=== [Protocol] ProtectSecret per-target failure Flow ===\n");

  const owner = makeNode("Owner", "https://owner.example.com", { secretId: 42n });
  const helperA = makeNode("HelperA", "https://helper-a.example.com");
  const helperB = makeNode("HelperB", "https://helper-b.example.com");
  const { longTermChannelId: channelA } = await doPair(helperA, owner, 1n, "Owner↔HelperA");
  const { longTermChannelId: channelB } = await doPair(helperB, owner, 2n, "Owner↔HelperB");

  owner.transport.failUri("https://helper-b.example.com");
  const events = await owner.protocol.start(FlowKind.ProtectSecret, {
    secrets: [{ id: new Uint8Array([1, 2, 3]), name: "per-target-failure", data: new TextEncoder().encode("payload") }],
  });
  const started = events.filter((e) => e.type === "ProtectSecretStarted");
  const failed = events.filter(
    (e): e is Extract<DeRecEvent, { type: "ProtectSecretFailed" }> => e.type === "ProtectSecretFailed",
  );
  if (started.length !== 1 || failed.length !== 1) {
    throw new Error(`expected one started and one failed, got ${started.length} + ${failed.length}`);
  }
  if (started[0]!.channel_id !== channelA) {
    throw new Error(`the started event must be for HelperA, got ${started[0]!.channel_id}`);
  }
  if (failed[0]!.channel_id !== channelB || failed[0]!.error !== "transport send failed: the message reached none of the peer's endpoints") {
    throw new Error(`the failed event must be for HelperB with the transport failure, got ${JSON.stringify(failed[0])}`);
  }
  console.log(`  HelperA: ProtectSecretStarted ✓   HelperB: ProtectSecretFailed("${failed[0]!.error}")  ✓`);

  console.log("\n✓ ProtectSecret per-target failure flow passed.\n");
}

/** A channel's stored `SharedKey`, or `null` when the channel has none. */
function channelKey(node: Node, secretId: bigint, channelId: bigint): Promise<Uint8Array | null> {
  return node.secretStore.load(String(secretId), String(channelId), 0);
}

/**
 * The replica group is one channel and one key. The first destination's
 * pairing fixes the group key; a second destination pairs on an ephemeral key,
 * then the handover moves it onto the group channel, after which every entry
 * holds the identical key, the ephemeral channel is gone on both sides, and a
 * follow-up round reaches the joiner on the group channel. Mirrors
 * `run_replica_group_key_handover_flow` in `smoke-tests/rust/src/protocol.rs`.
 */
async function runReplicaGroupKeyHandoverFlow(): Promise<void> {
  console.log("=== [Protocol] Replica group-key handover Flow ===\n");

  const sid = 0xBEEFn;
  const source: AddressedNode = {
    node: makeNode("Source", "https://handover-source.example.com", { secretId: sid, replicaId: 0xC0DE_C0DE_C0DE_C0DEn }),
    uri: "https://handover-source.example.com",
  };
  const dest1: AddressedNode = {
    node: makeNode("Dest1", "https://handover-dest1.example.com", { secretId: sid, replicaId: 0xD1D1_D1D1_D1D1_D1D1n }),
    uri: "https://handover-dest1.example.com",
  };
  const dest2: AddressedNode = {
    node: makeNode("Dest2", "https://handover-dest2.example.com", { secretId: sid, replicaId: 0xD2D2_D2D2_D2D2_D2D2n }),
    uri: "https://handover-dest2.example.com",
  };
  const all = [source, dest1, dest2];
  const requireKey = async (node: Node, channelId: bigint, label: string): Promise<Uint8Array> => {
    const key = await channelKey(node, sid, channelId);
    if (!key) throw new Error(`${label} must hold a key for channel ${channelId}`);
    return key;
  };

  const { rekeyed: groupChannel } = await pairReplicaHandshake(source, dest1, 1n);
  await crossConfirmFingerprint(source.node, dest1.node, groupChannel);
  await pumpAll(all);
  const groupKey = await requireKey(source.node, groupChannel, "Source");
  if (!byteArraysEqual(groupKey, await requireKey(dest1.node, groupChannel, "Dest1"))) {
    throw new Error("after the first pairing, Source and Dest1 must hold the same group key");
  }
  console.log("  step 1: pair Source↔Dest1 — the group key emerged, both sides agree  ✓");

  const { rekeyed: ephemeral } = await pairReplicaHandshake(source, dest2, 2n);
  const ephemeralKey = await requireKey(source.node, ephemeral, "Source");
  if (!byteArraysEqual(ephemeralKey, await requireKey(dest2.node, ephemeral, "Dest2"))) {
    throw new Error("before the handover, Source and Dest2 must share the ephemeral key");
  }
  if (byteArraysEqual(ephemeralKey, groupKey)) {
    throw new Error("before the handover, Dest2's ephemeral key must not be the group key");
  }
  await crossConfirmFingerprint(source.node, dest2.node, ephemeral);
  await pumpAll(all);

  for (const [label, node] of [["Source", source.node], ["Dest1", dest1.node], ["Dest2", dest2.node]] as const) {
    if (!byteArraysEqual(await requireKey(node, groupChannel, label), groupKey)) {
      throw new Error(`${label} must hold the group key, fixed at the first pairing, on the group channel`);
    }
  }
  for (const [label, node] of [["Source", source.node], ["Dest2", dest2.node]] as const) {
    if ((await channelKey(node, sid, ephemeral)) !== null) {
      throw new Error(`${label} must drop the ephemeral pairing channel's key after the handover`);
    }
  }
  for (const [label, node] of [["Source", source.node], ["Dest1", dest1.node], ["Dest2", dest2.node]] as const) {
    const roster = await storedRoster(node);
    if (roster.length !== 3 || roster.some((m) => m.channel_id !== String(groupChannel))) {
      throw new Error(`${label} must place all three members on the group channel, got ${JSON.stringify(roster)}`);
    }
  }
  console.log("  step 2: pair Source↔Dest2 — group converged on one channel and one key  ✓");

  const payload = new TextEncoder().encode("k_group payload");
  await source.node.protocol.start(FlowKind.ProtectSecret, {
    secrets: [{ id: new Uint8Array([0x42]), name: "post-handover", data: payload }],
    description: "post-handover round",
  });
  const postEvents = await pumpAll(all);
  if (!postEvents.some((e) => e.type === "ReplicaSecretReceived" && e.channel_id === String(groupChannel))) {
    throw new Error("the post-handover round must arrive on the group channel");
  }
  const snapshot = await dest2.node.userSecretStore.loadLatest(String(sid));
  if (!snapshot?.secrets.some((s) => byteArraysEqual(s.data, payload))) {
    throw new Error("Dest2 must decrypt the post-handover payload with the group key");
  }
  if (!byteArraysEqual(await requireKey(source.node, groupChannel, "Source"), groupKey)) {
    throw new Error("the group key must stay stable across follow-up rounds");
  }
  console.log("  step 3: follow-up ProtectSecret round under the group key; Dest2 decrypted it  ✓");

  console.log("\n✓ Replica group-key handover flow passed.\n");
}

/**
 * A publish sent before the joiner's handover acknowledgement reaches the
 * source still reaches the joiner, and so does every later one when that
 * acknowledgement never arrives: the joiner drops its ephemeral channel as
 * soon as it hydrates, so the source must already address it on the group
 * channel. Mirrors `run_replica_publish_before_handover_ack_flow` in
 * `smoke-tests/rust/src/protocol.rs`.
 */
async function runReplicaPublishBeforeHandoverAckFlow(): Promise<void> {
  console.log("=== [Protocol] Replica publish before handover ack Flow ===\n");

  const sid = 0xBEEFn;
  const source: AddressedNode = {
    node: makeNode("Source", "https://lost-ack-source.example.com", { secretId: sid, replicaId: 0xC0DE_C0DE_C0DE_C0DEn }),
    uri: "https://lost-ack-source.example.com",
  };
  const dest1: AddressedNode = {
    node: makeNode("Dest1", "https://lost-ack-dest1.example.com", { secretId: sid, replicaId: 0xD1D1_D1D1_D1D1_D1D1n }),
    uri: "https://lost-ack-dest1.example.com",
  };
  const dest2: AddressedNode = {
    node: makeNode("Dest2", "https://lost-ack-dest2.example.com", { secretId: sid, replicaId: 0xD2D2_D2D2_D2D2_D2D2n }),
    uri: "https://lost-ack-dest2.example.com",
  };
  const all = [source, dest1, dest2];

  const { rekeyed: groupChannel } = await pairReplicaHandshake(source, dest1, 1n);
  await crossConfirmFingerprint(source.node, dest1.node, groupChannel);
  await pumpAll(all);

  const { rekeyed: ephemeral } = await pairReplicaHandshake(source, dest2, 2n);
  await crossConfirmFingerprint(source.node, dest2.node, ephemeral);
  for (const { endpoint, message } of source.node.transport.drain()) {
    const dest = [dest1, dest2].find((d) => d.uri === endpoint.uri);
    if (dest) await processAll(dest.node, message);
  }
  if (dest2.node.transport.drain().length === 0) {
    throw new Error("Dest2 must have acknowledged the handover before the acknowledgement is dropped");
  }
  await pumpAll(all);
  console.log("  step 1: handover delivered, Dest2's acknowledgement lost  ✓");

  for (const text of ["before the ack", "after the ack"]) {
    const payload = new TextEncoder().encode(text);
    await source.node.protocol.start(FlowKind.ProtectSecret, {
      secrets: [{ id: new Uint8Array([0x42]), name: "handover", data: payload }],
    });
    await pumpAll(all);
    const snapshot = await dest2.node.userSecretStore.loadLatest(String(sid));
    if (!snapshot?.secrets.some((s) => byteArraysEqual(s.data, payload))) {
      throw new Error(`Dest2 must receive the publish carrying "${text}"`);
    }
  }
  console.log("  step 2: both publishes reached Dest2 on the group channel  ✓");

  console.log("\n✓ Replica publish before handover ack flow passed.\n");
}

/**
 * `start(Pairing)` with a fresh contact on a channel id that already finished
 * pairing is refused with `channel_already_paired` and changes nothing: the
 * channel stays Paired, its `SharedKey` stays, no `PairingSecret` or
 * `PairingContact` appears, and nothing is sent. Mirrors
 * `run_start_pairing_rejects_already_paired_channel` in
 * `smoke-tests/rust/src/protocol.rs`.
 */
async function runStartPairingRejectsAlreadyPairedChannelFlow(): Promise<void> {
  console.log("=== [Protocol] start(Pairing) rejects already-Paired channel ===\n");

  const policy = {
    pairing: true,
    prePair: true,
    storeShare: true,
    verifyShare: true,
    discovery: true,
    getShare: true,
    unpair: true,
    updateChannelInfo: true,
  };
  const owner: AddressedNode = {
    node: makeNode("Owner", "https://repaired-owner.example.com", { autoAccept: policy }),
    uri: "https://repaired-owner.example.com",
  };
  const helper: AddressedNode = {
    node: makeNode("Helper", "https://repaired-helper.example.com", { autoAccept: policy }),
    uri: "https://repaired-helper.example.com",
  };

  await helperStartPair(owner.node, helper.node, 1000n);
  const completed = (await pumpAll([owner, helper])).find(
    (e) => e.type === "PairingCompleted" && e.pairing_channel_id === "1000",
  );
  if (completed?.type !== "PairingCompleted") throw new Error("the first pairing completes");
  const channelId = completed.channel_id;
  const sid = String(helper.node.protocol.secretId());
  const status = async (): Promise<string> => {
    const bytes = await helper.node.channelStore.load(sid, channelId, "0");
    if (!bytes) throw new Error("the helper's channel record must exist");
    return JSON.parse(new TextDecoder().decode(bytes)).Helper.status;
  };
  if ((await status()) !== "Paired") throw new Error("the channel is Paired after the first pairing");

  const fresh = await owner.node.protocol.createContact(BigInt(channelId), ContactMode.InlineKeys);
  let refusal: DeRecError | undefined;
  try {
    await helper.node.protocol.start(FlowKind.Pairing, { kind: SenderKind.Helper, contact: fresh });
  } catch (e) {
    refusal = e as DeRecError;
  }
  if (refusal?.code !== "channel_already_paired") {
    throw new Error(`a re-scan of a Paired channel must be refused with channel_already_paired, got ${JSON.stringify(refusal)}`);
  }
  if (refusal.channel_id !== channelId) {
    throw new Error(`the refusal must name the offending channel ${channelId}, got ${String(refusal.channel_id)}`);
  }
  if ((await status()) !== "Paired") throw new Error("the channel must stay Paired after the refused start");
  if (!(await helper.node.secretStore.load(sid, channelId, 0))) {
    throw new Error("the SharedKey must remain after the refused start");
  }
  if ((await helper.node.secretStore.load(sid, channelId, 1)) || (await helper.node.secretStore.load(sid, channelId, 2))) {
    throw new Error("no PairingSecret or PairingContact may appear after the refused start");
  }
  if (helper.node.transport.drain().length !== 0) {
    throw new Error("a refused start must not send anything");
  }
  console.log("  [Helper] start(Pairing) on an already-Paired channel → channel_already_paired, no state change, nothing sent  ✓");

  console.log("\n✓ start(Pairing) rejects already-Paired channel flow passed.\n");
}

export async function runProtocolSmoke(): Promise<void> {
  console.log("━━━ [Protocol] Starting ━━━\n");

  await runPairingFlow();
  await runPairingRefusalFlow();
  await runFingerprintMismatchFlow();
  await runNoKeysFingerprintMismatchFlow();
  await runExpiredPendingPairingLosesItsKeyFlow();
  await runHashedKeysPairingFlow();
  await runNoKeysPairingFlow();
  runUnsafeConnectionConfigFlow();
  runGenerateReplicaIdFlow();
  await runConfigSurfaceFlow();
  await runWithConfigFlow();
  await runOverlappingCallsFlow();
  await runProtectSecretPerTargetFailureFlow();
  await runSharingFlow();
  await runWeightedHelpersFlow();
  await runWeightedHelpersStringIdFlow();
  await runStickyWeightsFlow();
  await runShareSubsharesFlow();
  await runStickyThresholdFlow();
  await runMaxSubsharesFlow();
  await runShareStoreRefusalFlow();
  await runShareSizeRefusalFlow();
  await runRequestFailedTokenFlow();
  await runAutoRespondOnFailureFlow();
  await runUndecodableRequestFlow();
  await runVerifyNoProofFlow();
  await runVerificationVerdictsFlow();
  await runInvalidWeightFlow();
  await runHelperKeepVersionFlow();
  await runOwnerKeepVersionMissedRoundFlow();
  await runInvalidKeepVersionFlow();
  await runSupersededShareRequestFlow();
  await runReplayDetectionFlow();
  await runDiscoveryAndRecoveryFlow();
  await runHelperWithoutTheVersionFlow();
  await runCorruptedShareFlow();
  await runSilentHelperRecoveryFlow();
  await runDisputedRecoveryFlow();
  await runConflictingRecoveryFlow();
  await runRestoreKeepsHelperDutiesFlow();
  await runAbandonedReplicaPairingFlow();
  await runContactOnTheGroupChannelFlow();
  await runPairingExpiryFlow();
  await runUnconfirmedJoinerFlow();
  await runUnpairingFlow();
  await runUpdateChannelInfoFlow();
  await runReplyToFlow();
  await runReplicaIdWiringSadPathsFlow();
  await runReplicaPairingAndSecretSyncFlow();
  await runReplicaMirrorThenVerifyFlow();
  await runReplicaRosterDescribesEveryMemberFlow();
  await runUnconfirmedDestinationIgnoresTheCopyFlow();
  await runReplicaVerifiesOnlySyncedVersionsFlow();
  await runReplicaSyncVersionProgressionFlow();
  await runReplicaGroupKeyHandoverFlow();
  await runReplicaPublishBeforeHandoverAckFlow();
  await runReplicaSecretRefusedFlow();
  await runAutoAcceptFlow();
  await runStartPairingRejectsAlreadyPairedChannelFlow();
  await runExpiredChannelCleanupFlow();
  await runBindingInputContractFlow();
  await runStoreAnswerContractFlow();
  await runDefiantChannelStoreFlow();

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
      { id: new Uint8Array([0xAA]), name: "auto-accept smoke", data: new TextEncoder().encode("web-auto-accept") },
    ],
    description: "web auto-accept smoke",
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
  console.log("  step 1: pair replica A → v=1, secret(h=0,s=0,r=2,shares=0)  ✓");

  // Step 2 — ProtectSecret([s1]) → v=2.
  const s1 = { id: new Uint8Array([0x01]), name: "secret-one", data: new TextEncoder().encode("first-user-secret") };
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
  console.log("  step 2: ProtectSecret([s1]) → v=2, secret(h=0,s=1,r=2,shares=0)  ✓");

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
  console.log("  step 3: pair replica B → v=3, secret(h=0,s=1,r=3,shares=0) on A+B  ✓");

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
  console.log("  step 4: pair helper #1 → v=4, secret(h=1,s=1,r=3,shares=0)  ✓");

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
  console.log("  step 5: pair helper #2 → v=5, secret(h=2,s=1,r=3,shares=0)  ✓");

  // Step 6 — ProtectSecret([s1, s2]) → v=6.
  const s2 = { id: new Uint8Array([0x02]), name: "secret-two", data: new TextEncoder().encode("second-user-secret") };
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
  console.log("  step 6: ProtectSecret([s1, s2]) → v=6, secret(h=2,s=2,r=3,shares=0)  ✓");

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
  console.log("  step 7: pair helper #3 → v=7, secret(h=3,s=2,r=3,shares=3); all 3 helpers ShareStored  ✓");

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
  console.log("  step 8: pair replica C → v=8, secret(h=3,s=2,r=4,shares=3) on A+B+C; all helpers refreshed  ✓");

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
  await source.node.protocol.verifyFingerprint(rekeyed, destinationFp);

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
  await destination.node.protocol.verifyFingerprint(rekeyed, sourceFp);
  // A snapshot that records no author, as one written before authors were
  // recorded, serves a catch-up whose author is unknown.
  const sourceSid = String(source.node.protocol.secretId());
  const held = await source.node.userSecretStore.loadLatest(sourceSid);
  if (held?.author_replica_id === undefined) {
    throw new Error("the source's snapshot must record its author");
  }
  const { author_replica_id: _author, ...unattributed } = held;
  await source.node.userSecretStore.saveLatest(sourceSid, unattributed);

  await destination.node.protocol.start(FlowKind.ReplicaDiscovery);
  const catchUp = await pumpAll([destination, source]);
  const installed = requireEvent(catchUp, "ReplicaSecretInstalled", "Destination");
  console.log("  destination pulled the copy with ReplicaDiscovery after confirming  ✓");
  if (installed.author_replica_id !== null) {
    throw new Error(`an unrecorded author must arrive as null, got ${String(installed.author_replica_id)}`);
  }
  console.log("  a copy whose author is unrecorded carries author_replica_id === null  ✓");

  console.log("\n✓ Unconfirmed replica destination flow passed.\n");
}

async function pairReplicaHandshake(
  owner: AddressedNode,
  replica: AddressedNode,
  channelId: bigint,
) {
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
  await owner.protocol.verifyFingerprint(channelId, replicaFp);
  await replica.protocol.verifyFingerprint(channelId, ownerFp);
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
    new TextDecoder().decode(await peer.channelStore.listHelpers(sid, ANY_HELPERS)),
  );
  if (storedHelpers.length !== helpers) {
    throw new Error(
      `replica ${label} must have materialised ${helpers} helper channel(s), got ${storedHelpers.length}`,
    );
  }

  const roster = JSON.parse(
    new TextDecoder().decode(await peer.channelStore.listReplicas(sid, ANY_REPLICAS)),
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
async function runOverlappingCallsFlow(): Promise<void> {
  console.log("=== [Protocol] overlapping calls on one instance ===\n");

  class SlowSecretStore extends InMemorySecretStore {
    override async save(
      secretId: string,
      channelId: string,
      kind: 0 | 1 | 2,
      value: Uint8Array,
    ): Promise<void> {
      await new Promise((resolve) => setTimeout(resolve, 10));
      return super.save(secretId, channelId, kind, value);
    }
  }

  const protocol = new DeRecProtocolBuilder(DEFAULT_TEST_SECRET_ID)
    .withChannelStore(new InMemoryChannelStore())
    .withShareStore(new InMemoryShareStore())
    .withSecretStore(new SlowSecretStore())
    .withUserSecretStore(new InMemoryUserSecretStore())
    .withStateStore(new InMemoryStateStore())
    .withTransport(new RecordingTransport())
    .withOwnTransports([{ uri: "https://overlap.example.com", protocol: "https" }])
    .withThreshold(THRESHOLD)
    .build();

  const settled: string[] = [];
  const track = <T>(label: string, call: Promise<T>): Promise<T> =>
    call.then((value) => {
      settled.push(label);
      return value;
    });
  const calls = Promise.all([
    track("createContact#1", protocol.createContact(1n, ContactMode.InlineKeys)),
    track("tick", protocol.tick()),
    track("setCommunicationInfo", protocol.setCommunicationInfo({ name: "Overlap" })),
    track("createContact#2", protocol.createContact(2n, ContactMode.InlineKeys)),
  ]);

  let timer: ReturnType<typeof setTimeout> | undefined;
  const hung = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () =>
        reject(
          new Error(
            `overlapping calls did not settle within 5s (settled: [${settled.join(", ")}]) — calls on one instance collide instead of queueing`,
          ),
        ),
      5000,
    );
  });
  try {
    await Promise.race([calls, hung]);
  } finally {
    clearTimeout(timer);
  }
  console.log("  four overlapping calls on one instance all settled  ✓");

  const expected = ["createContact#1", "tick", "setCommunicationInfo", "createContact#2"];
  if (settled.join() !== expected.join()) {
    throw new Error(
      `overlapping calls must run in call order: expected [${expected.join(", ")}], got [${settled.join(", ")}]`,
    );
  }
  console.log("  overlapping calls ran in the order they were made  ✓");

  console.log("\n✓ overlapping calls passed.\n");
}

/**
 * The expired-channel cleanup policy and the caller-driven sweep are
 * independent: with the policy disabled, `removeExpiredChannels` still runs,
 * spares a Pending pairing created within the current second, which stays
 * usable, and never touches a Paired channel. Mirrors
 * `run_expired_channel_cleanup_flow` in `smoke-tests/rust/src/protocol.rs`.
 */
async function runExpiredChannelCleanupFlow(): Promise<void> {
  console.log("\n=== [Protocol] Expired-channel cleanup ===\n");

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

  // A replica pairing is Pending on both ends until the fingerprints are
  // compared, and the caller-driven sweep spares a channel younger than its
  // threshold.
  const disabled = { expired_channels: { enabled: false, timeout_in_secs: 900 } };
  const owner: AddressedNode = {
    node: makeNode("Owner", "https://cleanup-owner.example.com", { replicaId: 11n, timeouts: disabled }),
    uri: "https://cleanup-owner.example.com",
  };
  const replica: AddressedNode = {
    node: makeNode("Replica", "https://cleanup-replica.example.com", { replicaId: 12n, timeouts: disabled }),
    uri: "https://cleanup-replica.example.com",
  };
  const { rekeyed } = await pairReplicaHandshake(owner, replica, 0xEC_0001n);
  const pending = await owner.node.protocol.removeExpiredChannels(3600);
  if (pending.length !== 0) {
    throw new Error(`a Pending channel younger than the threshold survives the sweep, removed ${JSON.stringify(pending)}`);
  }
  // Still usable: the fingerprint round-trip completes, which it could not
  // had the sweep dropped the channel or its keys.
  await crossConfirmFingerprint(owner.node, replica.node, rekeyed);
  console.log("  cleanup: a Pending replica pairing survives removeExpiredChannels(3600) and its fingerprint round-trip completes ✓");

  const paired = await owner.node.protocol.removeExpiredChannels(0);
  if (paired.length !== 0) {
    throw new Error(`Paired channels are out of scope for the sweep, removed ${JSON.stringify(paired)}`);
  }
  console.log("  cleanup: Paired channels are never swept ✓");
}


// A channel store that takes the filter and throws it away — the shape a store
// written before `ChannelFilter` existed still compiles into, because
// TypeScript accepts a function of fewer parameters where more are declared.
//
// This is the case the library's re-check was written for, so it is worth
// pinning through the real WASM bridge rather than only in Rust: the bridge is
// what hands the filter to JS and what reads the answer back.
class DefiantChannelStore extends InMemoryChannelStore {
  override async listHelpers(secretId: string): Promise<Uint8Array> {
    return super.listHelpers(secretId, { ids: [], status: [], role: null, exclude: [] });
  }

  override async listReplicas(secretId: string): Promise<Uint8Array> {
    return super.listReplicas(secretId, { ids: [], status: [], role: null, exclude: [] });
  }

  /// Move a channel's `created_at` back to the epoch so an age predicate can
  /// no longer be what spares it.
  ///
  /// Edited as text: re-encoding the record through `JSON.parse` would round
  /// its u64 `channel_id`, and this store exists to hold those bytes verbatim.
  async backdate(secretId: string, channelId: string): Promise<void> {
    const bytes = await this.load(secretId, channelId, "0");
    if (bytes === null) throw new Error(`backdate: no channel ${channelId}`);
    const text = new TextDecoder().decode(bytes);
    const edited = text.replace(/"created_at":\d+/, '"created_at":0');
    if (edited === text) throw new Error("backdate: no created_at field found");
    await this.save(secretId, channelId, "0", new TextEncoder().encode(edited));
  }
}

// A store that ignores the filter must not be able to make the library act on
// rows the filter excluded.
//
// `removeExpiredChannels` is the sharpest case: it narrows to
// `status: ["Pending"]` and deletes whatever comes back. Against a defiant
// store with no backstop it would delete *paired* channels and their pairing
// secrets — silently, and by default, since the same sweep runs inside
// `process()`.
async function runDefiantChannelStoreFlow(): Promise<void> {
  console.log("[Protocol] a store that ignores the filter cannot cause damage");

  const defiant = new DefiantChannelStore();
  const owner = makeNode("DefiantOwner", "https://defiant-owner.example.com", {
    channelStore: defiant,
  });
  const helper = makeNode("DefiantHelper", "https://defiant-helper.example.com");

  // A completed pairing leaves a Paired channel on both sides.
  const { longTermChannelId } = await doPair(helper, owner, 4242n, "Defiant↔Helper");

  const before = JSON.parse(
    new TextDecoder().decode(
      await defiant.listHelpers(DEFAULT_TEST_SECRET_ID.toString()),
    ),
  );
  if (before.length !== 1 || before[0].status !== "Paired") {
    throw new Error(
      `expected one paired channel before the sweep, got ${JSON.stringify(before)}`,
    );
  }

  // Age must not be what saves it. The sweep removes channels *older than*
  // the threshold, so a channel created this second survives `0` regardless of
  // its status — and the test would pass without the filter being applied at
  // all. Backdated, the status filter is the only thing left standing between
  // this paired channel and deletion.
  await defiant.backdate(DEFAULT_TEST_SECRET_ID.toString(), longTermChannelId);

  const removed = await owner.protocol.removeExpiredChannels(0);
  if (removed.length !== 0) {
    throw new Error(
      `a paired channel was swept: the status filter was not enforced (removed ${JSON.stringify(removed)})`,
    );
  }

  const after = JSON.parse(
    new TextDecoder().decode(
      await defiant.listHelpers(DEFAULT_TEST_SECRET_ID.toString()),
    ),
  );
  // Compared by count and status, not by id: `channel_id` rides the listing as
  // a JSON number, so a u64 above 2**53 does not survive `JSON.parse` intact —
  // see the note on `InMemoryChannelStore.list`.
  if (after.length !== 1 || after[0].status !== "Paired") {
    throw new Error(
      `the paired channel must survive a sweep for pending ones, got ${JSON.stringify(after)}`,
    );
  }
  console.log("  a defiant store cannot make the pending-sweep delete a paired channel  ✓");

  console.log("\n✓ Defiant-channel-store flow passed.\n");
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
// The core mints replica ids so every SDK obeys the same rule: random, and
// never 0, which no replica id may be.
export function runGenerateReplicaIdFlow(): void {
  console.log("=== [Protocol] generate_replica_id ===\n");
  for (let i = 0; i < 64; i++) {
    const id = generate_replica_id();
    if (typeof id !== "bigint" || id === 0n) {
      throw new Error(`generate_replica_id() must return a non-zero bigint, got ${String(id)}`);
    }
  }
  makeNode("Generated", "https://generated.example.com", {
    replicaId: generate_replica_id(),
  });
  console.log("  64 ids non-zero; a protocol builds with a generated id  ✓\n");
}

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
 * SDK. Each crosses into the native core, where a name mismatch would silently
 * drop the setting rather than fail — so each assertion here is checking the
 * value actually arrived.
 */
export async function runConfigSurfaceFlow(): Promise<void> {
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
  const protocol = base()
    .withOwnTransports([
      { uri: "https://a.example", protocol: "https" },
      { uri: "grpcs://a.example:443", protocol: "grpc" },
    ])
    .build();
  console.log("  distinct protocols accepted  ✓");

  // setOwnTransports replaces the set and is held to the same rule as the
  // builder.
  await protocol.setOwnTransports([{ uri: "https://only.example", protocol: "https" }]);
  console.log("  setOwnTransports replaces the whole set  ✓");

  refused = false;
  try {
    await protocol.setOwnTransports([
      { uri: "https://a.example", protocol: "https" },
      { uri: "https://b.example", protocol: "https" },
    ]);
  } catch {
    refused = true;
  }
  if (!refused) {
    throw new Error(
      "setOwnTransports must apply the same one-per-protocol rule as the builder",
    );
  }
  console.log("  setOwnTransports refuses a duplicate protocol  ✓");

  console.log("\n✓ config surface passed.\n");
}

/**
 * `withConfig` end to end: the shared fixture's full config builds a
 * protocol that runs an existing flow, a misspelled key is rejected rather
 * than ignored, an array is rejected, and a misspelled `withTimeouts` key is
 * rejected too.
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

  // The fixture's `full` config (every field set) builds a working protocol,
  // and an existing flow runs on it: proof the config reached the library,
  // not just the binding.
  const protocol = base().withConfig(protocolConfigFixtures.full as DeRecProtocolConfig).build();
  const events = await protocol.start(FlowKind.Discovery, {});
  if (!Array.isArray(events)) {
    throw new Error("start(Discovery) on a withConfig-built protocol must return an event array");
  }
  console.log("  the fixture's full config builds and runs Discovery  ✓");

  await expectCode("withConfig({ treshold: 3 })", "decode_error", () =>
    base().withConfig({ treshold: 3 } as never).build(),
  );
  console.log("  a misspelled withConfig key throws decode_error  ✓");

  await expectCode("withConfig([1, 2, 3])", "decode_error", () =>
    base().withConfig([1, 2, 3] as never).build(),
  );
  console.log("  an array passed to withConfig throws decode_error  ✓");

  await expectCode("withTimeouts({ sharing_round: 1 })", "invalid_timeouts", () =>
    base().withTimeouts({ sharing_round: 1 } as never).build(),
  );
  console.log("  a misspelled withTimeouts key throws invalid_timeouts  ✓");

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

/** The `code` of a structured binding error, or `undefined` for anything else. */
function errorCode(e: unknown): string | undefined {
  return typeof e === "object" && e !== null && "code" in e
    ? String((e as { code: unknown }).code)
    : undefined;
}

async function expectCode(
  label: string,
  expected: string,
  call: () => unknown,
): Promise<void> {
  let code: string | undefined;
  try {
    await call();
  } catch (e) {
    code = errorCode(e);
    if (code === undefined) throw e;
  }
  if (code !== expected) {
    throw new Error(`${label}: expected error code ${expected}, got ${code ?? "no error"}`);
  }
}

/** As `expectCode`, and the error must name `channelId` as the channel it is about. */
async function expectChannelCode(
  label: string,
  expected: string,
  channelId: string,
  call: () => unknown,
): Promise<void> {
  let error: DeRecError | undefined;
  try {
    await call();
  } catch (e) {
    if (errorCode(e) === undefined) throw e;
    error = e as DeRecError;
  }
  if (error?.code !== expected) {
    throw new Error(`${label}: expected error code ${expected}, got ${error?.code ?? "no error"}`);
  }
  if (error.channel_id !== channelId) {
    throw new Error(`${label}: the error must name channel ${channelId}, got ${String(error.channel_id)}`);
  }
}

/**
 * What crosses the binding is forwarded or rejected, never reinterpreted.
 *
 * Each case is one the bridge used to settle on its own: a restated default,
 * an accepted alias, a number silently truncated to an id, an empty id read
 * as `0`, a console write in place of the error path.
 */
async function runBindingInputContractFlow(): Promise<void> {
  console.log("=== [Protocol] binding input contract ===\n");

  // No `withThreshold`: the library's default (3) must be what applies. Two
  // helpers are below it, so the round splits nothing and sends them nothing,
  // where a 2-of-2 threshold would send each a share.
  const owner = makeNode("DefaultOwner", "https://default-owner.example.com", {
    omitThreshold: true,
  });
  const helperA = makeNode("DefaultHelperA", "https://default-helper-a.example.com");
  const helperB = makeNode("DefaultHelperB", "https://default-helper-b.example.com");
  await doPair(helperA, owner, 9101n, "DefaultOwner↔HelperA");
  await doPair(helperB, owner, 9102n, "DefaultOwner↔HelperB");
  owner.transport.drain();
  await owner.protocol.start(FlowKind.ProtectSecret, {
    secrets: [{ id: new Uint8Array([1]), name: "s", data: new Uint8Array([1]) }],
  });
  const sent = owner.transport.drain();
  if (sent.length !== 0) {
    throw new Error(
      `without withThreshold the library default (3) must apply: 2 helpers get no share, but ${sent.length} request(s) were sent`,
    );
  }
  console.log("  no withThreshold → the library default (3) applies: 2 helpers get no share  ✓");

  const base = () =>
    new DeRecProtocolBuilder(DEFAULT_TEST_SECRET_ID)
      .withChannelStore(new InMemoryChannelStore())
      .withShareStore(new InMemoryShareStore())
      .withSecretStore(new InMemorySecretStore())
      .withUserSecretStore(new InMemoryUserSecretStore())
      .withStateStore(new InMemoryStateStore())
      .withTransport(new RecordingTransport())
      .withOwnTransports([{ uri: "https://contract.example.com", protocol: "https" }]);

  // `withUnpairAck` takes the two names `UnpairAck` declares, exactly.
  base().withUnpairAck("required").withUnpairAck("not_required").build();
  for (const alias of ["fire_and_forget", "notrequired", "NOT_REQUIRED", "Required"]) {
    await expectCode(`withUnpairAck(${alias})`, "invalid_unpair_ack", () =>
      base().withUnpairAck(alias as never),
    );
  }
  console.log("  withUnpairAck accepts only \"required\" / \"not_required\"  ✓");

  // A node with no endpoint cannot be reached by any peer. An absent or empty
  // own-transport list reaches the library unchanged and is refused there.
  const unreachable = () =>
    new DeRecProtocolBuilder(DEFAULT_TEST_SECRET_ID)
      .withChannelStore(new InMemoryChannelStore())
      .withShareStore(new InMemoryShareStore())
      .withSecretStore(new InMemorySecretStore())
      .withUserSecretStore(new InMemoryUserSecretStore())
      .withStateStore(new InMemoryStateStore())
      .withTransport(new RecordingTransport());
  await expectCode("build() without withOwnTransports", "invalid_input", () =>
    unreachable().build(),
  );
  await expectCode("build() with withOwnTransports([])", "invalid_input", () =>
    unreachable().withOwnTransports([]).build(),
  );
  console.log("  absent or empty own transports refused by the library  ✓");

  // The library's memory is released explicitly. Releasing twice is a no-op,
  // as with .NET Dispose and Go Close; any call afterwards is refused.
  const released = base().build();
  released.free();
  released.free();
  let usedAfterFree = false;
  try {
    released.secretId();
    usedAfterFree = true;
  } catch {
    // expected
  }
  if (usedAfterFree) {
    throw new Error("a call after free() must throw");
  }
  const unbuilt = base();
  unbuilt.free();
  unbuilt[Symbol.dispose]();
  const built = base();
  const fromBuilt = built.build();
  built.free();
  fromBuilt[Symbol.dispose]();
  console.log("  free() / [Symbol.dispose]() release once and are safe to repeat  ✓");

  const protocol = base().build();

  // `removeExpiredChannels` takes a u64 in every encoding ids use.
  for (const secs of [0, 5n, "7", 2n ** 64n - 1n]) {
    const removed = await protocol.removeExpiredChannels(secs);
    if (!Array.isArray(removed)) {
      throw new Error(`removeExpiredChannels(${String(secs)}) must resolve to an array`);
    }
  }
  console.log("  removeExpiredChannels accepts number, bigint up to u64::MAX, decimal string  ✓");

  // A number that is not exactly a u64 is refused, not truncated.
  for (const bad of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53]) {
    await expectCode(`removeExpiredChannels(${bad})`, "decode_error", () =>
      protocol.removeExpiredChannels(bad),
    );
    await expectCode(`getFingerprint(${bad})`, "decode_error", () =>
      protocol.getFingerprint(bad),
    );
  }
  for (const bad of ["", "-1", "+1", "1.0", "18446744073709551616"]) {
    await expectCode(`removeExpiredChannels("${bad}")`, "decode_error", () =>
      protocol.removeExpiredChannels(bad),
    );
  }
  await expectCode("removeExpiredChannels(2^64)", "decode_error", () =>
    protocol.removeExpiredChannels(2n ** 64n),
  );
  console.log("  fractional, negative, unsafe and out-of-range ids are refused  ✓");

  // A recovered secret with an empty id is malformed, not channel 0.
  const helper = (channel_id: string) => ({
    helpers: [{ channel_id, transports: [], shared_key: new Uint8Array(32) }],
    secrets: [],
  });
  for (const bad of ["", "-1", "abc"]) {
    await expectCode(`restore(channel_id="${bad}")`, "invalid_recovered_secret", () =>
      protocol.restore(helper(bad) as never, 1),
    );
  }
  console.log("  restore refuses an empty or non-decimal channel_id  ✓");

  // A failed `process` surfaces through the rejected promise only.
  const original = console.error;
  const logged: unknown[] = [];
  console.error = (...args: unknown[]) => {
    logged.push(args);
  };
  let rejected = false;
  try {
    await protocol.process(new Uint8Array([0xff, 0x00, 0x01]));
  } catch {
    rejected = true;
  } finally {
    console.error = original;
  }
  if (!rejected) throw new Error("process(garbage) must reject");
  if (logged.length !== 0) {
    throw new Error(`process must not write to the console, got ${JSON.stringify(logged)}`);
  }
  console.log("  a failed process() rejects without writing to the console  ✓");

  // A number read as a u32 or a status is refused when it is not one, rather
  // than wrapped or truncated.
  for (const bad of [-1, 2.7, 2 ** 32, Number.NaN]) {
    await expectCode(`withThreshold(${bad})`, "decode_error", () => base().withThreshold(bad));
    await expectCode(`createContact(_, ${bad})`, "decode_error", () =>
      protocol.createContact(1n, bad as ContactMode),
    );
    await expectCode(`start(${bad})`, "decode_error", () =>
      protocol.start(bad as FlowKind.Discovery, {}),
    );
    await expectCode(`restore(_, ${bad})`, "decode_error", () =>
      protocol.restore({ helpers: [], secrets: [] } as never, bad),
    );
  }
  const pairing = makeNode("ContractHelper", "https://contract-helper.example.com");
  const requester = makeNode("ContractOwner", "https://contract-owner.example.com");
  await requester.protocol.start(FlowKind.Pairing, {
    kind: SenderKind.Owner,
    contact: await pairing.protocol.createContact(9103n, ContactMode.InlineKeys),
  });
  const pending = requireEvent(
    await pairing.protocol.process(drainOne(requester, "ContractOwner")),
    "ActionRequired",
    "ContractHelper",
  );
  for (const bad of [-1, 2.5, 2 ** 32]) {
    await expectCode(`reject(_, ${bad})`, "invalid_status", () =>
      pairing.protocol.reject(pending.action, bad as StatusEnum, "refused"),
    );
  }
  if (pairing.transport.drain().length !== 0) {
    throw new Error("a refused reject must send nothing");
  }
  console.log("  negative, fractional and out-of-range numbers refused by withThreshold, createContact, start, restore, reject  ✓");

  // Flow parameters decode strictly: a missing or mistyped field is an
  // error, not an empty value.
  const secret = { id: new Uint8Array([1]), name: "s", data: new Uint8Array([1]) };
  for (const [what, params] of [
    ["no secrets", {}],
    ["secrets that are not an array", { secrets: "s" }],
    ["a secret without data", { secrets: [{ id: secret.id, name: "s" }] }],
    ["a secret without an id", { secrets: [{ name: "s", data: secret.data }] }],
    ["a secret whose id is not bytes", { secrets: [{ ...secret, id: "s" }] }],
    ["a secret whose name is not a string", { secrets: [{ ...secret, name: 1 }] }],
    ["a description that is not a string", { secrets: [secret], description: 1 }],
  ] as const) {
    await expectCode(`start(ProtectSecret, ${what})`, "decode_error", () =>
      protocol.start(FlowKind.ProtectSecret, params as never),
    );
  }
  await expectCode("start(Unpair, memo: 1)", "decode_error", () =>
    protocol.start(FlowKind.Unpair, { channel_id: "1", memo: 1 } as never),
  );
  await expectCode("start(UnpairReplica, memo: 1)", "decode_error", () =>
    protocol.start(FlowKind.UnpairReplica, { replica_id: "1", memo: 1 } as never),
  );
  console.log("  ProtectSecret, Unpair and UnpairReplica params with a missing or mistyped field refused  ✓");

  console.log("\n✓ binding input contract passed.\n");
}

/**
 * A store's answer is read as strictly as an application's arguments: a value
 * of the wrong type is a store error, never a default.
 */
async function runStoreAnswerContractFlow(): Promise<void> {
  console.log("=== [Protocol] store answer contract ===\n");

  const secretId = 53n;
  const sid = secretId.toString();
  const secret = { id: new Uint8Array([16]), name: "s", data: new Uint8Array([1]) };

  for (const [what, snapshot] of [
    ["a fractional version", { version: 1.5, secrets: [] }],
    ["a negative version", { version: -1, secrets: [] }],
    ["a secret without a name", { version: 1, secrets: [{ id: secret.id, data: secret.data }] }],
  ] as const) {
    const node = makeNode("Owner", "https://owner.example.com", { secretId });
    await node.userSecretStore.saveLatest(sid, snapshot as never);
    await expectCode(`UserSecretStore.loadLatest → ${what}`, "store_error", () =>
      node.protocol.start(FlowKind.ProtectSecret, { secrets: [secret] }),
    );
    console.log(`  UserSecretStore.loadLatest returning ${what} → store_error  ✓`);
  }

  const owner = makeNode("Owner", "https://owner.example.com", { secretId });
  const helper = makeNode("Helper", "https://helper.example.com", { secretId });
  const { longTermChannelId } = await doPair(helper, owner, 85n, "Owner↔Helper");
  const discover = async (): Promise<DeRecEvent[]> => {
    await owner.protocol.start(FlowKind.Discovery, { target: BigInt(longTermChannelId) });
    return processAll(helper, drainOne(owner, "Owner"));
  };
  if ((await discover()).some((e) => e.type === "RequestFailed")) {
    throw new Error("discovery over a well-formed share store must not fail");
  }
  helper.transport.drain();
  await helper.shareStore.save(sid, longTermChannelId, {
    secretId: sid,
    version: 2.5,
    bytes: new Uint8Array([1]),
  });
  const failed = requireEvent(await discover(), "RequestFailed", "Helper");
  if (failed.action_kind !== "Discovery" || failed.error_code !== "store_error") {
    throw new Error(`a fractional share version must fail the request as a store error, got ${JSON.stringify(failed)}`);
  }
  console.log("  ShareStore.loadAll returning a fractional version → RequestFailed(store_error)  ✓");

  class NumericRemoveChannelStore extends InMemoryChannelStore {
    override async remove(secretId: string, channelId: string, replicaId: string): Promise<boolean> {
      await super.remove(secretId, channelId, replicaId);
      return 1 as unknown as boolean;
    }
  }
  const leaving = makeNode("Helper", "https://leaving-helper.example.com", {
    secretId,
    channelStore: new NumericRemoveChannelStore(),
  });
  const paired = await doPair(leaving, owner, 86n, "Owner↔LeavingHelper");
  await owner.protocol.start(FlowKind.Unpair, { channel_id: paired.longTermChannelId });
  const removal = requireEvent(
    await processAll(leaving, drainOne(owner, "Owner")),
    "RequestFailed",
    "LeavingHelper",
  );
  if (removal.action_kind !== "Unpair" || removal.error_code !== "store_error") {
    throw new Error(`a non-boolean ChannelStore.remove must be a store error, got ${JSON.stringify(removal)}`);
  }
  console.log("  ChannelStore.remove returning a number → RequestFailed(store_error)  ✓");

  console.log("\n✓ store answer contract passed.\n");
}
