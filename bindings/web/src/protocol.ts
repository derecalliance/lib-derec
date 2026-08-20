// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.
// Protocol smoke tests: exercises pairing, sharing, and discovery+recovery
// using the low-level `DeRecProtocol` runtime (`start` / `process` / `accept`)
// backed by in-memory stores.
// No UI: every `ActionRequired` event a peer receives is auto-accepted via
// `processAll`. The store implementations mirror the reference app's
// `stores.ts` algorithms exactly (channel-link graph + BFS closure, keyed
// share store, recording transport), but are Map-backed instead of
// localStorage-backed.

import { ContactMode, DeRecProtocol, DeRecProtocolBuilder, FlowKind, SenderKind, primitives } from "@derec-alliance/web";
import type {
  ChannelStore,
  ContactMessage,
  DeRecEvent,
  SecretStore,
  Share,
  ShareStore,
  StateStore,
  Transport,
  UserSecretStore,
  UserSecrets,
} from "@derec-alliance/web";


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
    _missingPolicy: "skip" | "fail",
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
  private list(secretId: string, variant: "Helper" | "Replica"): Uint8Array {
    const source = variant === "Helper" ? this.helpers : this.members;
    const prefix = `${secretId}:`;
    const tag = `{"${variant}":`;
    const inner: string[] = [];
    for (const [k, v] of source) {
      if (!k.startsWith(prefix)) continue;
      const text = new TextDecoder().decode(v);
      if (!text.startsWith(tag)) continue;
      inner.push(text.slice(tag.length, -1));
    }
    return new TextEncoder().encode(`[${inner.join(",")}]`);
  }

  async listHelpers(secretId: string): Promise<Uint8Array> {
    return this.list(secretId, "Helper");
  }

  async listReplicas(secretId: string): Promise<Uint8Array> {
    return this.list(secretId, "Replica");
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

  async send(
    endpoint: { protocol: string; uri: string },
    message: Uint8Array,
  ): Promise<void> {
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
const KEEP_VERSIONS_COUNT = 3;
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
  } = {},
): Node {
  const channelStore = new InMemoryChannelStore();
  const shareStore = new InMemoryShareStore();
  const secretStore = new InMemorySecretStore();
  const userSecretStore = new InMemoryUserSecretStore();
  const stateStore = new InMemoryStateStore();
  const transport = new RecordingTransport();
  let builder = new DeRecProtocolBuilder(options.secretId ?? DEFAULT_TEST_SECRET_ID)
    .withChannelStore(channelStore)
    .withShareStore(shareStore)
    .withSecretStore(secretStore)
    .withUserSecretStore(userSecretStore)
    .withStateStore(stateStore)
    .withTransport(transport)
    .withOwnTransport({ uri: endpointUri, protocol: "https" })
    .withThreshold(options.threshold ?? THRESHOLD)
    .withKeepVersionsCount(KEEP_VERSIONS_COUNT)
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
  // `process()`'s wasm wrapper flattens every underlying error to
  // `code: "DEREC_ERROR"` and surfaces the specific failure mode via the
  // message text — match on that. The message comes from the
  // `PairingError::PrePairHashMismatch` `#[error("...")]` annotation.
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


// VSS sharing requires threshold ≥ 2, so this scenario pairs the Owner with
// TWO helpers and reconstructs the secret from both shares. Mirrors the Rust
// `bindings/rust/src/protocol.rs::run_discovery_and_recovery_flow`.
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
  for (const env of discRequests) {
    const isA = env.endpoint.uri.includes("helper-a");
    const helper = isA ? helperA : helperB;
    const label = isA ? "HelperA" : "HelperB";
    await processAll(helper, env.message);
    const resp = drainOne(helper, label);
    await owner.protocol.process(resp);
  }


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

  const restored = makeNode("RestoredOwner", "https://restored.example.com", {
    secretId: ownerSecretId,
  });
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

  console.log("\n✓ Unpairing flow passed.\n");
}


/**
 * Asserts the `autoReplyTo` constructor flag: with it `true`, every outbound
 * channel-mode request must carry `request.replyTo = ownTransport` on the
 * inner request body. Covers half (1) of the replyTo contract; half (2)
 * (responder honours an inbound `replyTo`) is exercised by the Rust binding
 * smoke test against the orchestrator handler logic.
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
  if (!decoded.reply_to || decoded.reply_to.uri !== ownerUri) {
    throw new Error(
      `auto_reply_to must stamp replyTo = ownerUri (${ownerUri}) on the inner request body, got ${JSON.stringify(decoded.reply_to)}`,
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
  if (defaultDecoded.reply_to) {
    throw new Error(
      `without auto_reply_to, request.reply_to must be unset; got ${JSON.stringify(defaultDecoded.reply_to)}`,
    );
  }

  console.log("  ✓ auto_reply_to stamps replyTo on outbound requests");
  console.log("  ✓ default (no auto_reply_to) leaves replyTo unset");
  console.log("\n✓ replyTo flow passed.\n");
}


/**
 * Owner↔Destination replica pair, followed by a full ProtectSecret
 * fan-out that includes the Destination as one of the targets. Mirrors
 * `bindings/rust/src/protocol.rs::run_protect_secret_with_replica_targets_flow`
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
  const ownerConfirmed = await owner.protocol.verifyFingerprint(replicaChannel, destFp);
  const destConfirmed = await destination.protocol.verifyFingerprint(replicaChannel, ownerFp);
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

  owner.protocol.setCommunicationInfo(newInfo);
  owner.protocol.setOwnTransport(newUri, "https");

  await owner.protocol.start(FlowKind.UpdateChannelInfo, {
    target: BigInt(longTermChannelId),
    communication_info: newInfo,
    transport_protocol: { uri: newUri, protocol: 0 },
  });
  const updateRequest = drainOne(owner, "Owner");
  console.log(`  [Owner] start(UpdateChannelInfo) → request ${updateRequest.length}B`);

  const helperEvents = await processAll(helper, updateRequest);
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


export async function runProtocolSmoke(): Promise<void> {
  console.log("━━━ [Protocol] Starting ━━━\n");

  await runPairingFlow();
  await runHashedKeysPairingFlow();
  await runNoKeysPairingFlow();
  await runSharingFlow();
  await runDiscoveryAndRecoveryFlow();
  await runUnpairingFlow();
  await runUpdateChannelInfoFlow();
  await runReplyToFlow();
  await runReplicaIdWiringSadPathsFlow();
  await runReplicaPairingAndSecretSyncFlow();
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
  console.log("  step 1: pair replica A → v=1, secret(h=0,s=0,r=1,shares=0)  ✓");

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
    new TextDecoder().decode(await peer.channelStore.listHelpers(sid)),
  );
  if (storedHelpers.length !== helpers) {
    throw new Error(
      `replica ${label} must have materialised ${helpers} helper channel(s), got ${storedHelpers.length}`,
    );
  }

  const roster = JSON.parse(
    new TextDecoder().decode(await peer.channelStore.listReplicas(sid)),
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
  console.log("\n=== [Protocol] Expired-channel cleanup ===\n");

  const builder = new DeRecProtocolBuilder(DEFAULT_TEST_SECRET_ID)
    .withChannelStore(new InMemoryChannelStore())
    .withShareStore(new InMemoryShareStore())
    .withSecretStore(new InMemorySecretStore())
    .withUserSecretStore(new InMemoryUserSecretStore())
    .withStateStore(new InMemoryStateStore())
    .withTransport(new RecordingTransport())
    .withOwnTransport({ uri: "https://cleanup.example.com", protocol: "https" })
    .withThreshold(THRESHOLD)
    .withRemoveExpiredChannels(false, 900);
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
