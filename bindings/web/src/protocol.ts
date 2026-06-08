// SPDX-License-Identifier: Apache-2.0
// Protocol smoke tests: exercises pairing, sharing, and discovery+recovery
// using the low-level `DeRecProtocol` runtime (`start` / `process` / `accept`)
// backed by in-memory stores.
// No UI: every `ActionRequired` event a peer receives is auto-accepted via
// `processAll`. The store implementations mirror the reference app's
// `stores.ts` algorithms exactly (channel-link graph + BFS closure, keyed
// share store, recording transport), but are Map-backed instead of
// localStorage-backed.

import { ContactMode, DeRecProtocol, FlowKind, SenderKind, primitives } from "@derec-alliance/web";
import type {
  ChannelStore,
  ContactMessage,
  DeRecEvent,
  SecretStore,
  Share,
  ShareStore,
  Transport,
} from "@derec-alliance/web";


const kindName = (k: SenderKind): string => {
  switch (k) {
    case SenderKind.Owner:
      return "Owner";
    case SenderKind.Helper:
      return "Helper";
    case SenderKind.Replica:
      return "Replica";
    default:
      return `Unknown(${k})`;
  }
};


// kind 0 = SharedKey (32 raw bytes), kind 1 = PairingSecret (ephemeral),
// kind 2 = PairingContact (ephemeral). Keyed by `${channelId}:${kind}`.
class InMemorySecretStore implements SecretStore {
  private readonly data = new Map<string, Uint8Array>();

  private key(channelId: string, kind: 0 | 1 | 2): string {
    return `${channelId}:${kind}`;
  }

  async load(channelId: string, kind: 0 | 1 | 2): Promise<Uint8Array | null> {
    return this.data.get(this.key(channelId, kind)) ?? null;
  }

  // `missingPolicy` is honored by the Rust adapter; this in-memory impl
  // always returns nulls in input order and lets the adapter apply the
  // policy. A real backend (SQL, network) might choose to throw on `"fail"`.
  async loadMany(
    channelIds: string[],
    kind: 0 | 1 | 2,
    _missingPolicy: "skip" | "fail",
  ): Promise<Array<Uint8Array | null>> {
    return channelIds.map(
      (id) => this.data.get(this.key(id, kind)) ?? null,
    );
  }

  async save(channelId: string, kind: 0 | 1 | 2, value: Uint8Array): Promise<void> {
    this.data.set(this.key(channelId, kind), value);
  }

  async remove(channelId: string, kind: 0 | 1 | 2): Promise<void> {
    this.data.delete(this.key(channelId, kind));
  }
}

// Stores opaque channel-record bytes plus the channel-link graph.
// Linking is undirected, idempotent, and transitive; `linkedChannels`
// returns the transitive closure including `channelId` itself.
class InMemoryChannelStore implements ChannelStore {
  private readonly channels = new Map<string, Uint8Array>();
  private readonly links = new Map<string, Set<string>>();

  async load(channelId: string): Promise<Uint8Array | null> {
    return this.channels.get(channelId) ?? null;
  }

  async save(channelId: string, bytes: Uint8Array): Promise<void> {
    this.channels.set(channelId, bytes);
  }

  async listChannels(): Promise<string[]> {
    return Array.from(this.channels.keys());
  }

  async remove(channelId: string): Promise<boolean> {
    return this.channels.delete(channelId);
  }

  async linkChannel(a: string, b: string): Promise<void> {
    if (a === b) return;
    if (!this.links.has(a)) this.links.set(a, new Set());
    if (!this.links.has(b)) this.links.set(b, new Set());
    this.links.get(a)!.add(b);
    this.links.get(b)!.add(a);
  }

  /** Transitive closure of `channelId`, including `channelId` itself. */
  async linkedChannels(channelId: string): Promise<string[]> {
    const visited = new Set<string>();
    const queue: string[] = [channelId];
    while (queue.length > 0) {
      const curr = queue.shift()!;
      if (visited.has(curr)) continue;
      visited.add(curr);
      for (const linked of this.links.get(curr) ?? []) {
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
  // Keyed by (channelId, secretId, version). The string secretId mirrors the
  // wire contract — u64 as a decimal string.
  private readonly data = new Map<string, Map<string, Map<number, Share>>>();
  private ownerVersion: number | null = null;

  async load(channelId: string, secretId: string, versions: number[]): Promise<Share[]> {
    const bySecret = this.data.get(channelId);
    if (!bySecret) return [];
    const byVersion = bySecret.get(secretId);
    if (!byVersion) return [];
    const filter = versions.length > 0 ? new Set(versions) : null;
    const result: Share[] = [];
    for (const [v, share] of byVersion) {
      if (filter && !filter.has(v)) continue;
      result.push(share);
    }
    return result;
  }

  async save(channelId: string, share: Share): Promise<void> {
    let bySecret = this.data.get(channelId);
    if (!bySecret) {
      bySecret = new Map();
      this.data.set(channelId, bySecret);
    }
    let byVersion = bySecret.get(share.secretId);
    if (!byVersion) {
      byVersion = new Map();
      bySecret.set(share.secretId, byVersion);
    }
    byVersion.set(share.version, share);
  }

  /**
   * Load shares for several channels in one call, scoped to one secret.
   * Recovery feeds this the set from the channel store's `linkedChannels`.
   * Flat list — version-dedup is the caller's concern.
   */
  async loadMany(channelIds: string[], secretId: string, versions: number[]): Promise<Share[]> {
    const filter = versions.length > 0 ? new Set(versions) : null;
    const result: Share[] = [];
    for (const channelId of channelIds) {
      const bySecret = this.data.get(channelId);
      if (!bySecret) continue;
      const byVersion = bySecret.get(secretId);
      if (!byVersion) continue;
      for (const [v, share] of byVersion) {
        if (filter && !filter.has(v)) continue;
        result.push(share);
      }
    }
    return result;
  }

  /**
   * Discovery-only: every share across the given channels — all secrets,
   * all versions. Recovery/verification must scope by `secretId` instead.
   */
  async loadAll(channelIds: string[]): Promise<Share[]> {
    const result: Share[] = [];
    for (const channelId of channelIds) {
      const bySecret = this.data.get(channelId);
      if (!bySecret) continue;
      for (const byVersion of bySecret.values()) {
        for (const share of byVersion.values()) result.push(share);
      }
    }
    return result;
  }

  /**
   * Drop every share stored under `channelId` (all secret_ids, all versions).
   * Called by the unpair flow when a channel is torn down. Idempotent — a
   * non-existent channel is a no-op.
   */
  async removeChannel(channelId: string): Promise<void> {
    this.data.delete(channelId);
  }

  async latestVersion(): Promise<number | null> {
    return this.ownerVersion;
  }

  setOwnerVersion(version: number): void {
    this.ownerVersion = version;
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
}

const THRESHOLD = 2;
const KEEP_VERSIONS_COUNT = 3;

function makeNode(
  name: string,
  endpointUri: string,
  options: { autoReplyTo?: boolean } = {},
): Node {
  const channelStore = new InMemoryChannelStore();
  const shareStore = new InMemoryShareStore();
  const secretStore = new InMemorySecretStore();
  const transport = new RecordingTransport();
  const protocol = new DeRecProtocol(
    channelStore,
    shareStore,
    secretStore,
    transport,
    endpointUri,
    "https",
    THRESHOLD,
    KEEP_VERSIONS_COUNT,
    { name },
    null, // timeoutInSecs
    null, // autoRespondOnFailure
    null, // unpairAck
    options.autoReplyTo ?? null,
  );
  return { protocol, transport, channelStore, shareStore, secretStore };
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
  const ownerChannel = await owner.channelStore.load("1");
  const helperChannel = await helper.channelStore.load("1");
  if (!ownerChannel || !helperChannel) {
    throw new Error("HashedKeys pairing: both sides must have a stored channel record");
  }
  const ownerSharedKey = await owner.secretStore.load("1", 0);
  const helperSharedKey = await helper.secretStore.load("1", 0);
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
  const owner = makeNode("Owner", "https://owner.example.com");
  const helperA = makeNode("HelperA", "https://helper-a.example.com");
  const helperB = makeNode("HelperB", "https://helper-b.example.com");
  const channelIdA = 1n;
  const channelIdB = 2n;

  await doPair(helperA, owner, channelIdA, "Owner↔HelperA");
  await doPair(helperB, owner, channelIdB, "Owner↔HelperB");
  console.log();

  const secretData = new TextEncoder().encode("super-secret-value");
  await owner.protocol.start(FlowKind.ProtectSecret, {
    secretId: ownerSecretId,
    target: [channelIdA, channelIdB],
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
  const owner = makeNode("Owner", "https://owner.example.com");
  const helperA = makeNode("HelperA", "https://helper-a.example.com");
  const helperB = makeNode("HelperB", "https://helper-b.example.com");
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
    secretId: ownerSecretId,
    target: [channelA, channelB],
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


  console.log("  -- Recovery: re-pair on fresh channels --\n");

  for (const [helper, fresh, label] of [
    [helperA, recoveryChannelA, "HelperA"] as const,
    [helperB, recoveryChannelB, "HelperB"] as const,
  ]) {
    const contact: ContactMessage = await helper.protocol.createContact(fresh, ContactMode.InlineKeys);
    console.log(`  [${label}] createContact (recovery) channel_id=${contact.channel_id}`);

    const origChannel = label === "HelperA" ? channelA : channelB;
    await helper.channelStore.linkChannel(
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
  // only fans out to the recovery channels.
  await owner.channelStore.remove(channelA.toString());
  await owner.channelStore.remove(channelB.toString());
  console.log(`\n  [Owner]  removed original channels ${channelA}, ${channelB} to simulate state loss\n`);


  console.log("  -- Discovery: Owner asks each helper what it holds --\n");

  await owner.protocol.start(FlowKind.Discovery, {
    target: [recoveryChannelA, recoveryChannelB],
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
  // The reconstructed payload is the encoded secret bag; the original secret
  // bytes round-trip inside it.
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

  // Initiate unpair on the Owner side.
  await owner.protocol.start(FlowKind.Unpair, {
    target: channelId,
    memo: "decommissioning",
  });
  const unpairRequest = drainOne(owner, "Owner");
  console.log(
    `  [Owner]  start(Unpair) → UnpairRequest ${unpairRequest.length}B`,
  );

  // Helper auto-accepts (processAll satisfies ActionRequired events).
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

  // Owner processes the Ok response → Unpaired event + state dropped.
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
  const sharedKey = await owner.secretStore.load(channelId.toString(), 0);
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


export async function runProtocolSmoke(): Promise<void> {
  console.log("━━━ [Protocol] Starting ━━━\n");

  await runPairingFlow();
  await runHashedKeysPairingFlow();
  await runSharingFlow();
  await runDiscoveryAndRecoveryFlow();
  await runUnpairingFlow();
  await runReplyToFlow();

  console.log("━━━ [Protocol] All passed. ━━━\n");
}
