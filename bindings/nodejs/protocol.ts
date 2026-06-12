// SPDX-License-Identifier: Apache-2.0
// Protocol smoke tests: exercises pairing, sharing, and discovery+recovery
// using the low-level `DeRecProtocol` runtime (`start` / `process` / `accept`)
// backed by in-memory stores.
// This is a Node.js (CommonJS-backed) port of the verified web smoke test
// (`bindings/web/src/protocol.ts`). The only difference is the module
// specifier: `@derec-alliance/nodejs` loads the wasm module synchronously on
// `require`, so there is no `init` to import or await.
// No UI: every `ActionRequired` event a peer receives is auto-accepted via
// `processAll`. The store implementations mirror the reference app's
// `stores.ts` algorithms exactly (channel-link graph + BFS closure, keyed
// share store, recording transport), but are Map-backed instead of
// localStorage-backed.

import { ContactMode, DeRecProtocol, DeRecProtocolBuilder, FlowKind, SenderKind, primitives } from "@derec-alliance/nodejs";
import type {
  ChannelStore,
  ContactMessage,
  DeRecEvent,
  SecretStore,
  Share,
  ShareStore,
  Transport,
  UserSecretStore,
  UserSecrets,
} from "@derec-alliance/nodejs";


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
  private readonly channels = new Map<string, Uint8Array>();
  private readonly links = new Map<string, Set<string>>();

  private key(secretId: string, channelId: string): string {
    return `${secretId}:${channelId}`;
  }

  async load(secretId: string, channelId: string): Promise<Uint8Array | null> {
    return this.channels.get(this.key(secretId, channelId)) ?? null;
  }

  async save(
    secretId: string,
    channelId: string,
    bytes: Uint8Array,
  ): Promise<void> {
    this.channels.set(this.key(secretId, channelId), bytes);
  }

  async listChannels(secretId: string): Promise<string[]> {
    const prefix = `${secretId}:`;
    return Array.from(this.channels.keys())
      .filter((k) => k.startsWith(prefix))
      .map((k) => k.slice(prefix.length));
  }

  async remove(secretId: string, channelId: string): Promise<boolean> {
    return this.channels.delete(this.key(secretId, channelId));
  }

  async linkChannel(secretId: string, a: string, b: string): Promise<void> {
    if (a === b) return;
    const ka = this.key(secretId, a);
    const kb = this.key(secretId, b);
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
      for (const linked of this.links.get(this.key(secretId, curr)) ?? []) {
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
}

const THRESHOLD = 2;
const KEEP_VERSIONS_COUNT = 3;
const DEFAULT_TEST_SECRET_ID = 0xDE_2ECn;

function makeNode(
  name: string,
  endpointUri: string,
  options: {
    autoReplyTo?: boolean;
    replicaId?: bigint;
    secretId?: bigint;
  } = {},
): Node {
  const channelStore = new InMemoryChannelStore();
  const shareStore = new InMemoryShareStore();
  const secretStore = new InMemorySecretStore();
  const userSecretStore = new InMemoryUserSecretStore();
  const transport = new RecordingTransport();
  let builder = new DeRecProtocolBuilder(options.secretId ?? DEFAULT_TEST_SECRET_ID)
    .withChannelStore(channelStore)
    .withShareStore(shareStore)
    .withSecretStore(secretStore)
    .withUserSecretStore(userSecretStore)
    .withTransport(transport)
    .withOwnTransport({ uri: endpointUri, protocol: "https" })
    .withThreshold(THRESHOLD)
    .withKeepVersionsCount(KEEP_VERSIONS_COUNT)
    .withCommunicationInfo({ name });
  if (options.autoReplyTo !== undefined) {
    builder = builder.withAutoReplyTo(options.autoReplyTo);
  }
  if (options.replicaId !== undefined) {
    builder = builder.withReplicaId(options.replicaId);
  }
  const protocol = builder.build();
  return { protocol, transport, channelStore, shareStore, secretStore, userSecretStore };
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

/** `true` if `haystack` contains `needle` as a contiguous subarray. */
function containsSubarray(haystack: Uint8Array, needle: Uint8Array): boolean {
  if (needle.length === 0 || haystack.length < needle.length) return false;
  outer: for (let i = 0; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
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
): Promise<void> {
  const contact: ContactMessage =
    await contactCreator.protocol.createContact(channelId, ContactMode.InlineKeys);
  console.log(
    `  [${label}/ContactCreator] createContact channel_id=${contact.channel_id}`,
  );

  await initiator.protocol.start(FlowKind.Pairing, {
    kind: SenderKind.Owner,
    contact,
  });
  const pairRequest = drainOne(initiator, `${label}/Initiator`);
  console.log(
    `  [${label}/Initiator]     start(Pairing, kind=Owner) → PairRequest ${pairRequest.length}B`,
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
}


async function runPairingFlow(): Promise<void> {
  console.log("=== [Protocol] Pairing Flow ===\n");

  const owner = makeNode("Owner", "https://owner.example.com");
  const helper = makeNode("Helper", "https://helper.example.com");

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
  const channelJson = {
    id: Number(channelId),
    transport: { uri: "https://peer.example.com", protocol: 0 },
    communication_info: {},
    status: "Pending",
    created_at: 1700000000,
    role: "ReplicaSource",
    replica_id: 0xcafe,
  };
  const nodeSid = String(node.protocol.secretId());
  await node.channelStore.save(
    nodeSid,
    String(channelId),
    new TextEncoder().encode(JSON.stringify(channelJson)),
  );
  await node.secretStore.save(nodeSid, String(channelId), 0, sharedKey);

  const unmatched = await node.protocol.verifyFingerprint(channelId, "0000-0000-0000-0000");
  if (unmatched) {
    throw new Error("verifyFingerprint must return false for a wrong fingerprint");
  }

  // Critical invariant for 5.1: the stored channel record must still
  // report Pending; the protocol must not have touched it.
  const storedBytes = await node.channelStore.load(nodeSid, String(channelId));
  if (!storedBytes) throw new Error("channel record missing after verify");
  const stored = JSON.parse(new TextDecoder().decode(storedBytes));
  if (stored.status !== "Pending") {
    throw new Error(
      `verifyFingerprint(wrong) must leave Channel.status as Pending; got ${stored.status}`,
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
async function doPairHashedKeys(
  contactCreator: Node,
  initiator: Node,
  channelId: bigint,
  label: string,
): Promise<void> {
  const contact: ContactMessage =
    await contactCreator.protocol.createContact(channelId, ContactMode.HashedKeys);
  if (contact.contact_mode !== ContactMode.HashedKeys) {
    throw new Error(`${label}: HashedKeys contact must advertise contact_mode = HashedKeys`);
  }
  if (contact.mlkem_encapsulation_key !== undefined) {
    throw new Error(`${label}: HashedKeys contact must NOT carry the ML-KEM key inline`);
  }
  if (contact.ecies_public_key !== undefined) {
    throw new Error(`${label}: HashedKeys contact must NOT carry the ECIES key inline`);
  }
  if (!contact.contact_binding_hash || contact.contact_binding_hash.length !== 48) {
    throw new Error(`${label}: HashedKeys contact must carry a 48-byte SHA-384 binding hash`);
  }
  console.log(
    `  [${label}/ContactCreator] createContact(HashedKeys) channel_id=${contact.channel_id} (binding-hash only, ${contact.contact_binding_hash.length}B)`,
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
}


async function runHashedKeysPairingFlow(): Promise<void> {
  console.log("=== [Protocol] HashedKeys Pairing Flow ===\n");

  // Happy path: full 4-leg chain ends with PairingCompleted on both sides.
  const owner = makeNode("Owner", "https://owner.example.com");
  const helper = makeNode("Helper", "https://helper.example.com");
  await doPairHashedKeys(helper, owner, 1n, "HashedKeys");

  // Both sides must have a paired channel record + a shared key in their
  // secret store (kind 0 = SharedKey). The latter is the strongest
  // end-to-end check that the PrePair → Pair chain converged on the
  // same key on both sides.
  const ownerSid = String(owner.protocol.secretId());
  const helperSid = String(helper.protocol.secretId());
  const ownerChannel = await owner.channelStore.load(ownerSid, "1");
  const helperChannel = await helper.channelStore.load(helperSid, "1");
  if (!ownerChannel || !helperChannel) {
    throw new Error("HashedKeys pairing: both sides must have a stored channel record");
  }
  const ownerSharedKey = await owner.secretStore.load(ownerSid, "1", 0);
  const helperSharedKey = await helper.secretStore.load(helperSid, "1", 0);
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
  // Helpers serving this owner are bound to the same vault id — every
  // store on the helper side partitions by that id, matching the
  // one-protocol-per-vault trait surface.
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

  await doPair(helperA, owner, channelA, "InitialA");
  await doPair(helperB, owner, channelB, "InitialB");
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

  for (const [helper, fresh, label] of [
    [helperA, recoveryChannelA, "HelperA"] as const,
    [helperB, recoveryChannelB, "HelperB"] as const,
  ]) {
    const contact: ContactMessage = await helper.protocol.createContact(fresh, ContactMode.InlineKeys);
    console.log(`  [${label}] createContact (recovery) channel_id=${contact.channel_id}`);

    const origChannel = label === "HelperA" ? channelA : channelB;
    await helper.channelStore.linkChannel(
      String(helper.protocol.secretId()),
      origChannel.toString(),
      fresh.toString(),
    );

    await owner.protocol.start(FlowKind.Pairing, {
      kind: SenderKind.Owner,
      contact,
    });
    const recReq = drainOne(owner, "Owner");
    const helperPairEvents = await processAll(helper, recReq);
    requireEvent(helperPairEvents, "PairingCompleted", label);
    const recResp = drainOne(helper, label);
    const ownerPairEvents = await processAll(owner, recResp);
    const ownerPairing = requireEvent(ownerPairEvents, "PairingCompleted", "Owner");
    if (ownerPairing.kind !== SenderKind.Owner) {
      throw new Error(`expected kind=Owner, got ${kindName(ownerPairing.kind)}`);
    }
    console.log(`  [${label}] re-paired on channel_id=${fresh}`);
  }

  // Simulate Owner-side state loss: drop the original channels so recovery
  // only fans out to the recovery channels. Without this, the Owner would
  // receive duplicate shares (one per original + one per linked recovery
  // channel) and Lagrange interpolation would collide on x-coordinates.
  const ownerSid = String(owner.protocol.secretId());
  await owner.channelStore.remove(ownerSid, channelA.toString());
  await owner.channelStore.remove(ownerSid, channelB.toString());
  console.log(`\n  [Owner]  removed original channels ${channelA}, ${channelB} to simulate state loss\n`);


  console.log("  -- Discovery: Owner asks each helper what it holds --\n");

  await owner.protocol.start(FlowKind.Discovery, {
    target: [recoveryChannelA, recoveryChannelB],
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

  let recovered: Uint8Array | null = null;
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

  if (!recovered || recovered.length === 0) {
    throw new Error("Recovery failed: no SecretRecovered event with non-empty bytes");
  }
  // The reconstructed payload is the encoded secret bag (DeRecSecret +
  // SecretContainer); assert the original secret bytes round-trip inside it.
  if (!containsSubarray(recovered, secretBytes)) {
    throw new Error(
      `SecretRecovered (${recovered.length}B) does not contain the original ${secretBytes.length}B secret`,
    );
  }
  console.log(`  [Owner]  SecretRecovered ${recovered.length}B — contains original secret ✓`);

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

  await doPair(helper, owner, channelId, "Unpair");
  console.log();

  await owner.protocol.start(FlowKind.Unpair, {
    target: channelId,
    memo: "decommissioning",
  });
  const unpairRequest = drainOne(owner, "Owner");
  console.log(
    `  [Owner]  start(Unpair) → UnpairRequest ${unpairRequest.length}B`,
  );

  const helperEvents = await processAll(helper, unpairRequest);
  const helperUnpaired = requireEvent(helperEvents, "Unpaired", "Helper");
  if (helperUnpaired.channel_id !== channelId.toString()) {
    throw new Error(
      `Helper Unpaired channel_id mismatch: ${helperUnpaired.channel_id} ≠ ${channelId}`,
    );
  }
  const unpairResponse = drainOne(helper, "Helper");
  console.log(
    `  [Helper] processAll(UnpairRequest) → Unpaired + UnpairResponse ${unpairResponse.length}B`,
  );

  const ownerEvents = await processAll(owner, unpairResponse);
  const ownerUnpaired = requireEvent(ownerEvents, "Unpaired", "Owner");
  if (ownerUnpaired.channel_id !== channelId.toString()) {
    throw new Error(
      `Owner Unpaired channel_id mismatch: ${ownerUnpaired.channel_id} ≠ ${channelId}`,
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

  await doPair(helper, owner, channelId, "ReplyTo");

  // Trigger an outbound Discovery request; it will be queued on the
  // owner's transport awaiting delivery.
  await owner.protocol.start(FlowKind.Discovery, { target: channelId });
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
    channelId.toString(),
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
  await doPair(helper2, ownerDefault, channelId, "ReplyTo/Default");
  await ownerDefault.protocol.start(FlowKind.Discovery, { target: channelId });
  const defaultOutbound = ownerDefault.transport.drain();
  const defaultMsg = defaultOutbound[0]!;
  const defaultSharedKey = await ownerDefault.secretStore.load(
    String(ownerDefault.protocol.secretId()),
    channelId.toString(),
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
 * `ReplicaVaultReceived` event carries the decoded `SecretContainer`
 * (vault.secrets / .helpers / .replicas / .owner_replica_id) plus the
 * helper share map.
 */
async function runReplicaPairingAndVaultSyncFlow(): Promise<void> {
  console.log("=== [Protocol] Replica pairing + vault sync ===\n");

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
  //    replica channel.
  const ownerFp = await owner.protocol.getFingerprint(destChannel);
  const destFp = await destination.protocol.getFingerprint(destChannel);
  if (ownerFp !== destFp) {
    throw new Error(
      `replica fingerprint mismatch: owner=${ownerFp} dest=${destFp}`,
    );
  }
  const ownerConfirmed = await owner.protocol.verifyFingerprint(destChannel, destFp);
  const destConfirmed = await destination.protocol.verifyFingerprint(destChannel, ownerFp);
  if (!ownerConfirmed || !destConfirmed) {
    throw new Error(
      `verifyFingerprint must return true on both sides (owner=${ownerConfirmed}, dest=${destConfirmed})`,
    );
  }
  console.log(`  fingerprint cross-confirmed (${ownerFp.length} chars)  ✓`);

  // 4. ProtectSecret across both helpers + the destination. Three
  //    envelopes leave the owner: two VSS shares (one per helper) and
  //    one ReplicaSecretPayload composite (for the destination).
  const secretData = new TextEncoder().encode("vault-payload-for-replica-and-helper");
  await owner.protocol.start(FlowKind.ProtectSecret, {
    secrets: [{ id: new Uint8Array([0x01]), name: "shared-vault", data: secretData }],
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
  //    ReplicaVaultReceived event with the full decoded vault.
  const destEvents = await processAll(destination, destEnvelope.message);
  const received = destEvents.find((e) => e.type === "ReplicaVaultReceived") as
    | Extract<DeRecEvent, { type: "ReplicaVaultReceived" }>
    | undefined;
  if (!received) {
    throw new Error(
      `Destination did not emit ReplicaVaultReceived; got [${destEvents.map((e) => e.type).join(", ")}]`,
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
  if (received.vault.secrets.length !== 1) {
    throw new Error(
      `vault.secrets.length expected 1, got ${received.vault.secrets.length}`,
    );
  }
  const receivedBytes = received.vault.secrets[0]!.data;
  if (
    receivedBytes.length !== secretData.length ||
    !receivedBytes.every((b, i) => b === secretData[i])
  ) {
    throw new Error("vault.secrets[0].data must round-trip the original secret bytes");
  }
  if (BigInt(received.vault.owner_replica_id) !== ownerReplicaId) {
    throw new Error(
      `vault.owner_replica_id must echo owner's replica_id (${ownerReplicaId}), got ${received.vault.owner_replica_id}`,
    );
  }
  if (received.vault.helpers.length !== 2) {
    throw new Error(
      `vault.helpers.length expected 2, got ${received.vault.helpers.length}`,
    );
  }
  if (received.vault.replicas.length !== 1) {
    throw new Error(
      `vault.replicas.length expected 1, got ${received.vault.replicas.length}`,
    );
  }
  const destInfo = received.vault.replicas[0]!;
  if (BigInt(destInfo.replica_id) !== destReplicaId) {
    throw new Error(
      `ReplicaInfo.replica_id expected ${destReplicaId}, got ${destInfo.replica_id}`,
    );
  }
  if (destInfo.sender_kind !== SenderKind.ReplicaDestination) {
    throw new Error(
      `ReplicaInfo.sender_kind must be ReplicaDestination (${SenderKind.ReplicaDestination}), got ${destInfo.sender_kind}`,
    );
  }
  if (received.shares.length !== 2) {
    throw new Error(
      `shares.length expected 2 (one per helper), got ${received.shares.length}`,
    );
  }
  console.log(
    `  ReplicaVaultReceived: vault=${received.vault.secrets.length}secret/${received.vault.helpers.length}helpers/${received.vault.replicas.length}replicas, shares=${received.shares.length}  ✓`,
  );

  // Drain helper outboxes from v=1 so the next round sees only v=2.
  helperA.transport.drain();
  helperB.transport.drain();

  // Vault version updates: the owner mutates the secret and re-runs
  // `ProtectSecret`; the destination must receive a fresh
  // `ReplicaVaultReceived` carrying `version=2` and the new payload.
  // The protocol auto-increments via `IShareStore.latestVersion()`;
  // the in-memory store exposes a side-channel setter so this test
  // can drive that contract without first running a full owner-side
  // store cycle.
  owner.shareStore.setOwnerVersion(secretId.toString(), 1);
  const secretDataV2 = new TextEncoder().encode("vault-payload-after-update");
  await owner.protocol.start(FlowKind.ProtectSecret, {
    secrets: [{ id: new Uint8Array([0x01]), name: "shared-vault", data: secretDataV2 }],
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
  const received2 = destEvents2.find((e) => e.type === "ReplicaVaultReceived") as
    | (DeRecEvent & { type: "ReplicaVaultReceived" })
    | undefined;
  if (!received2) {
    throw new Error(
      `v2: destination did not emit ReplicaVaultReceived; got [${destEvents2.map((e) => e.type).join(", ")}]`,
    );
  }
  if (received2.version !== 2) {
    throw new Error(`v2: expected version=2, got ${received2.version}`);
  }
  const v2Data = received2.vault.secrets[0]?.data;
  if (
    received2.vault.secrets.length !== 1 ||
    !v2Data ||
    v2Data.length !== secretDataV2.length ||
    !Array.from(secretDataV2).every((b, i) => b === v2Data[i])
  ) {
    throw new Error("v2: vault.secrets[0].data must round-trip the updated bytes");
  }
  console.log(
    `  ReplicaVaultReceived v=2: secret bytes updated, share count = ${received2.shares.length}  ✓`,
  );

  // Replica recovery transitivity: the Destination received
  // `vault.helpers[*].shared_key` inside the vault. Those keys must be
  // byte-identical to what each helper has stored locally for the
  // owner channel, because a Destination acting as a recovery delegate
  // uses them to authenticate as the Source toward each helper.
  const helperAStored = await helperA.secretStore.load(
    String(helperA.protocol.secretId()),
    String(helperAChannel),
    0,
  );
  const helperBStored = await helperB.secretStore.load(
    String(helperB.protocol.secretId()),
    String(helperBChannel),
    0,
  );
  if (!helperAStored || !helperBStored) {
    throw new Error("helpers must have stored their shared keys");
  }
  const vaultHelperA = received2.vault.helpers.find(
    (h) => BigInt(h.channel_id) === helperAChannel,
  );
  const vaultHelperB = received2.vault.helpers.find(
    (h) => BigInt(h.channel_id) === helperBChannel,
  );
  if (!vaultHelperA || !vaultHelperB) {
    throw new Error("vault.helpers missing entry for one of the helpers");
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
  if (!keysEqual(helperAStored, vaultHelperA.shared_key)) {
    throw new Error(
      "vault.helpers[HelperA].shared_key must match what HelperA stores locally",
    );
  }
  if (!keysEqual(helperBStored, vaultHelperB.shared_key)) {
    throw new Error(
      "vault.helpers[HelperB].shared_key must match what HelperB stores locally",
    );
  }
  console.log(
    "  vault.helpers[*].shared_key matches each helper's stored key — destination can act in source's stead  ✓",
  );

  // The vault also carries `vault.secrets[*].data` unencrypted, so
  // the Destination can fall back to its stored vault without
  // contacting any helper. The recovery model is "any one of: helper
  // quorum, vault on a single destination" — both paths recover the
  // same secret bytes.
  const v2DataCheck = received2.vault.secrets[0]?.data;
  if (
    !v2DataCheck ||
    v2DataCheck.length !== secretDataV2.length ||
    !Array.from(secretDataV2).every((b, i) => b === v2DataCheck[i])
  ) {
    throw new Error(
      "vault.secrets[0].data must be the raw recovered bytes",
    );
  }
  console.log(
    "  vault.secrets[0].data is the raw recovered secret — destination-only recovery is viable  ✓",
  );

  console.log("\n✓ Replica pairing + vault sync flow passed.\n");
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

  await doPair(helper, owner, channelId, "UpdateChannelInfo");
  console.log();

  const newUri = "https://owner.NEW.example.com";
  const newInfo = { name: "Owner-renamed", email: "owner.new@example.com" };

  // Mutate local state, then propagate.
  owner.protocol.setCommunicationInfo(newInfo);
  owner.protocol.setOwnTransport(newUri, "https");

  await owner.protocol.start(FlowKind.UpdateChannelInfo, {
    target: channelId,
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

  const helperStoredBytes = await helper.channelStore.load(
    String(helper.protocol.secretId()),
    String(channelId),
  );
  if (!helperStoredBytes) {
    throw new Error("helper channel record must still exist after UpdateChannelInfo");
  }
  const helperStored = JSON.parse(new TextDecoder().decode(helperStoredBytes));
  if (helperStored.transport.uri !== newUri) {
    throw new Error(
      `helper's stored transport.uri must reflect the announced update; got ${helperStored.transport.uri}`,
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


export async function runProtocolSmoke(): Promise<void> {
  console.log("━━━ [Protocol] Starting ━━━\n");

  await runPairingFlow();
  await runFingerprintMismatchFlow();
  await runHashedKeysPairingFlow();
  await runSharingFlow();
  await runDiscoveryAndRecoveryFlow();
  await runUnpairingFlow();
  await runUpdateChannelInfoFlow();
  await runReplyToFlow();
  await runReplicaIdWiringSadPathsFlow();
  await runReplicaPairingAndVaultSyncFlow();

  console.log("━━━ [Protocol] All passed. ━━━\n");
}
