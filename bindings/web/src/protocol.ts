// SPDX-License-Identifier: Apache-2.0
//
// Protocol smoke tests: exercises pairing, sharing, and discovery+recovery
// using the low-level `DeRecProtocol` runtime (`start` / `process` / `accept`)
// backed by in-memory stores.
//
// No UI: every `ActionRequired` event a peer receives is auto-accepted via
// `processAll`. The store implementations mirror the reference app's
// `stores.ts` algorithms exactly (channel-link graph + BFS closure, keyed
// share store, recording transport), but are Map-backed instead of
// localStorage-backed.

import { DeRecProtocol, FlowKind, SenderKind } from "@derec-alliance/web";
import type {
  ChannelStore,
  ContactMessage,
  DeRecEvent,
  SecretStore,
  Share,
  ShareStore,
  Transport,
} from "@derec-alliance/web";

// ── Logging helpers ───────────────────────────────────────────────────────────

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

// ── In-memory stores ──────────────────────────────────────────────────────────

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

// ── RecordingTransport ────────────────────────────────────────────────────────

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

// ── Node factory ──────────────────────────────────────────────────────────────

interface Node {
  protocol: DeRecProtocol;
  transport: RecordingTransport;
  channelStore: InMemoryChannelStore;
  shareStore: InMemoryShareStore;
  secretStore: InMemorySecretStore;
}

const THRESHOLD = 2;
const KEEP_VERSIONS_COUNT = 3;

function makeNode(name: string, endpointUri: string, secretId: bigint): Node {
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
    secretId,
    { name },
  );
  return { protocol, transport, channelStore, shareStore, secretStore };
}

// ── Assertion helper ──────────────────────────────────────────────────────────

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

// ── Choreography helpers ──────────────────────────────────────────────────────

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
    await contactCreator.protocol.createContact(channelId);
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

// ── Sub-test: pairing flow ────────────────────────────────────────────────────

async function runPairingFlow(): Promise<void> {
  console.log("=== [Protocol] Pairing Flow ===\n");

  const owner = makeNode("Owner", "https://owner.example.com", 1n);
  const helper = makeNode("Helper", "https://helper.example.com", 2n);

  await doPair(helper, owner, 1n, "Pairing");

  console.log("\n✓ Pairing flow passed.\n");
}

// ── Sub-test: sharing flow ────────────────────────────────────────────────────

async function runSharingFlow(): Promise<void> {
  console.log("=== [Protocol] Sharing Flow ===\n");

  const ownerSecretId = 42n;
  const owner = makeNode("Owner", "https://owner.example.com", ownerSecretId);
  const helperA = makeNode("HelperA", "https://helper-a.example.com", 100n);
  const helperB = makeNode("HelperB", "https://helper-b.example.com", 200n);
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

// ── Sub-test: discovery & recovery flow ──────────────────────────────────────

// VSS sharing requires threshold ≥ 2, so this scenario pairs the Owner with
// TWO helpers and reconstructs the secret from both shares. Mirrors the Rust
// `bindings/rust/src/protocol.rs::run_discovery_and_recovery_flow`.
async function runDiscoveryAndRecoveryFlow(): Promise<void> {
  console.log("=== [Protocol] Discovery & Recovery Flow ===\n");

  const ownerSecretId = 123n;
  const owner = makeNode("Owner", "https://owner.example.com", ownerSecretId);
  const helperA = makeNode("HelperA", "https://helper-a.example.com", 7n);
  const helperB = makeNode("HelperB", "https://helper-b.example.com", 8n);
  const channelA = 1n;
  const channelB = 2n;
  const recoveryChannelA = 100n;
  const recoveryChannelB = 101n;

  const description = "wallet seed phrase";
  const secretBytes = new TextEncoder().encode("correct horse battery staple");

  // ── Setup: pair both helpers and distribute the secret to both ────────────

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

  // ── Recovery re-pair: each helper provisions a fresh contact ───────────────

  console.log("  -- Recovery: re-pair on fresh channels --\n");

  for (const [helper, fresh, label] of [
    [helperA, recoveryChannelA, "HelperA"] as const,
    [helperB, recoveryChannelB, "HelperB"] as const,
  ]) {
    const contact: ContactMessage = await helper.protocol.createContact(fresh);
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

  // ── Discovery: target only the recovery channels ──────────────────────────

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

  // ── Recovery: collect shares from both helpers and reconstruct ────────────

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

// ── Sub-test: unpairing flow ──────────────────────────────────────────────────
//
// Verifies that an Owner-initiated unpair (Required-ack mode, the default)
// produces a successful round-trip:
//   1. Owner → Helper: UnpairRequest
//   2. Helper processes → ActionRequired(Unpair) → accept() → Unpaired event
//      + UnpairResponse(Ok) outbound
//   3. Owner processes the response → Unpaired event + local state dropped
async function runUnpairingFlow(): Promise<void> {
  console.log("=== [Protocol] Unpairing Flow ===\n");

  const owner = makeNode("Owner", "https://owner.example.com", 1n);
  const helper = makeNode("Helper", "https://helper.example.com", 2n);
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

// ── Entry point ───────────────────────────────────────────────────────────────

export async function runProtocolSmoke(): Promise<void> {
  console.log("━━━ [Protocol] Starting ━━━\n");

  await runPairingFlow();
  await runSharingFlow();
  await runDiscoveryAndRecoveryFlow();
  await runUnpairingFlow();

  console.log("━━━ [Protocol] All passed. ━━━\n");
}
