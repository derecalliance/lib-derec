// SPDX-License-Identifier: Apache-2.0
//
// Protocol smoke tests: exercises all five flows using the higher-level
// `DeRecProtocol` orchestrator backed by in-memory stores.

import { DeRecProtocol, SenderKind } from "@derec-alliance/web";
import type { DeRecEvent } from "@derec-alliance/web";

// ── Logging helpers ───────────────────────────────────────────────────────────

const kindName = (k: SenderKind): string => {
  switch (k) {
    case SenderKind.OwnerNonRecovery: return "OwnerNonRecovery";
    case SenderKind.OwnerRecovery:    return "OwnerRecovery";
    case SenderKind.Helper:           return "Helper";
    default:                          return `Unknown(${k})`;
  }
};

// ── In-memory stores ──────────────────────────────────────────────────────────

class InMemorySecretStore {
  private sharedKeys = new Map<string, Uint8Array>();
  private pairingSecrets = new Map<string, Uint8Array>();

  async load(channelId: string, kind: 0 | 1): Promise<Uint8Array | null> {
    return (
      (kind === 0
        ? this.sharedKeys.get(channelId)
        : this.pairingSecrets.get(channelId)) ?? null
    );
  }

  async save(channelId: string, kind: 0 | 1, value: Uint8Array): Promise<void> {
    if (kind === 0) this.sharedKeys.set(channelId, value);
    else this.pairingSecrets.set(channelId, value);
  }

  async remove(channelId: string, kind: 0 | 1): Promise<void> {
    if (kind === 0) this.sharedKeys.delete(channelId);
    else this.pairingSecrets.delete(channelId);
  }
}

class InMemoryContactStore {
  private contacts = new Map<string, Uint8Array>();

  async load(channelId: string): Promise<Uint8Array | null> {
    return this.contacts.get(channelId) ?? null;
  }

  async save(channelId: string, contactBytes: Uint8Array): Promise<void> {
    this.contacts.set(channelId, contactBytes);
  }
}

class InMemoryShareStore {
  private data = new Map<string, Map<string, Map<number, Uint8Array>>>();

  private hex(bytes: Uint8Array): string {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  async load(
    channelId: string,
    secretId: Uint8Array,
    version: number,
  ): Promise<Uint8Array | null> {
    return (
      this.data.get(channelId)?.get(this.hex(secretId))?.get(version) ?? null
    );
  }

  async save(
    channelId: string,
    secretId: Uint8Array,
    version: number,
    encoded: Uint8Array,
  ): Promise<void> {
    if (!this.data.has(channelId)) this.data.set(channelId, new Map());
    const bySecret = this.data.get(channelId)!;
    const h = this.hex(secretId);
    if (!bySecret.has(h)) bySecret.set(h, new Map());
    bySecret.get(h)!.set(version, encoded);
  }

  async loadChannelsForSecret(
    secretId: Uint8Array,
    version: number,
  ): Promise<string[]> {
    const h = this.hex(secretId);
    const result: string[] = [];
    for (const [channelId, bySecret] of this.data) {
      if (bySecret.get(h)?.has(version)) result.push(channelId);
    }
    return result;
  }

  async loadSecretsForChannel(
    channelId: string,
  ): Promise<Array<[Uint8Array, number[]]>> {
    const bySecret = this.data.get(channelId);
    if (!bySecret) return [];
    return Array.from(bySecret.entries()).map(([h, byVersion]) => [
      new Uint8Array(h.match(/.{2}/g)!.map((s) => parseInt(s, 16))),
      Array.from(byVersion.keys()),
    ]);
  }

  copyShare(
    fromChannelId: string,
    toChannelId: string,
    secretId: Uint8Array,
    version: number,
  ): void {
    const bytes = this.data
      .get(fromChannelId)
      ?.get(this.hex(secretId))
      ?.get(version);
    if (!bytes) return;
    if (!this.data.has(toChannelId)) this.data.set(toChannelId, new Map());
    const bySecret = this.data.get(toChannelId)!;
    const h = this.hex(secretId);
    if (!bySecret.has(h)) bySecret.set(h, new Map());
    bySecret.get(h)!.set(version, bytes);
  }
}

// ── RecordingTransport ────────────────────────────────────────────────────────

class RecordingTransport {
  private outbox: Array<{
    endpoint: { protocol: string; uri: string };
    message: Uint8Array;
  }> = [];

  async send(
    endpoint: { protocol: string; uri: string },
    message: Uint8Array,
  ): Promise<void> {
    this.outbox.push({ endpoint, message });
  }

  drain(): Array<{ endpoint: { protocol: string; uri: string }; message: Uint8Array }> {
    return this.outbox.splice(0);
  }
}

// ── Factory ───────────────────────────────────────────────────────────────────

function makeProtocol(endpointUri: string) {
  const secretStore = new InMemorySecretStore();
  const contactStore = new InMemoryContactStore();
  const shareStore = new InMemoryShareStore();
  const transport = new RecordingTransport();
  const protocol = new DeRecProtocol(
    contactStore,
    shareStore,
    secretStore,
    transport,
    endpointUri,
    "https",
  );
  return { protocol, transport, shareStore };
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

// ── Shared pairing helper ─────────────────────────────────────────────────────

async function doPair(
  contactCreator: ReturnType<typeof makeProtocol>,
  initiator: ReturnType<typeof makeProtocol>,
  initiatorKind: SenderKind,
  channelId: bigint,
  label: string,
): Promise<void> {
  const contactBytes = await contactCreator.protocol.createContact(channelId);
  console.log(`  [${label}/ContactCreator] create_contact  channel_id=${channelId}  (${contactBytes.length} bytes)`);

  await initiator.protocol.startPairing(initiatorKind, contactBytes);
  const [reqMsg] = initiator.transport.drain();
  if (!reqMsg) throw new Error(`${label}: missing PairRequest`);
  console.log(`  [${label}/Initiator]     start_pairing(kind=${kindName(initiatorKind)})  → PairRequest: ${reqMsg.message.length} bytes`);

  const creatorEvents = await contactCreator.protocol.process(reqMsg.message);
  const creatorPairing = requireEvent(creatorEvents, "PairingComplete", `${label}/ContactCreator`);
  const [respMsg] = contactCreator.transport.drain();
  if (!respMsg) throw new Error(`${label}: missing PairResponse`);
  console.log(`  [${label}/ContactCreator] process(PairRequest)  → PairingComplete(kind=${kindName(creatorPairing.kind)})  PairResponse: ${respMsg.message.length} bytes`);

  const initiatorEvents = await initiator.protocol.process(respMsg.message);
  const initiatorPairing = requireEvent(initiatorEvents, "PairingComplete", `${label}/Initiator`);
  console.log(`  [${label}/Initiator]     process(PairResponse) → PairingComplete(kind=${kindName(initiatorPairing.kind)})`);
}

// ── Sub-test: pairing flow ────────────────────────────────────────────────────

async function runPairingFlow(): Promise<void> {
  console.log("=== [Protocol] Pairing Flow ===\n");

  const owner = makeProtocol("https://owner.example.com");
  const helper = makeProtocol("https://helper.example.com");

  await doPair(owner, helper, SenderKind.Helper, 1n, "Pairing");

  console.log("\n✓ Pairing flow passed.\n");
}

// ── Sub-test: sharing flow ────────────────────────────────────────────────────

async function runSharingFlow(): Promise<void> {
  console.log("=== [Protocol] Sharing Flow ===\n");

  const owner = makeProtocol("https://owner.example.com");
  const helperA = makeProtocol("https://helper-a.example.com");
  const helperB = makeProtocol("https://helper-b.example.com");
  const channelIdA = 1n;
  const channelIdB = 2n;

  await doPair(owner, helperA, SenderKind.Helper, channelIdA, "Owner↔HelperA");
  await doPair(owner, helperB, SenderKind.Helper, channelIdB, "Owner↔HelperB");
  console.log();

  const secretId = new Uint8Array([1, 2, 3]);
  const secretData = new TextEncoder().encode("super-secret-value");
  const secretVersion = 1;

  await owner.protocol.protectSecret(
    secretId, secretData, "smoke-test secret", secretVersion,
    2 /* threshold */, [channelIdA, channelIdB], [],
  );

  const outbound = owner.transport.drain();
  if (outbound.length !== 2) {
    throw new Error(`expected 2 StoreShareRequests, got ${outbound.length}`);
  }
  console.log(`\n  [Owner]  protectSecret  → ${outbound.length} StoreShareRequest(s) dispatched`);

  const helpers: Array<[ReturnType<typeof makeProtocol>, bigint, string]> = [
    [helperA, channelIdA, "HelperA"],
    [helperB, channelIdB, "HelperB"],
  ];

  for (let i = 0; i < outbound.length; i++) {
    const msg = outbound[i]!;
    const [helperSide, , label] = helpers[i]!;

    console.log(`\n  [${label}] process(StoreShareRequest)  ${msg.message.length} bytes`);
    const helperEvents = await helperSide.protocol.process(msg.message);
    const storeEv = requireEvent(helperEvents, "ShareStored", label);
    console.log(`          → ShareStored(channel_id=${storeEv.channel_id}, version=${storeEv.version})`);

    const [storeResp] = helperSide.transport.drain();
    if (!storeResp) throw new Error(`${label}: missing StoreShareResponse`);
    console.log(`  [${label}] sent StoreShareResponse  ${storeResp.message.length} bytes`);

    const ownerEvents = await owner.protocol.process(storeResp.message);
    const confirmEv = requireEvent(ownerEvents, "ShareConfirmed", "Owner");
    console.log(`  [Owner]  ShareConfirmed(channel_id=${confirmEv.channel_id}, version=${confirmEv.version})`);
  }

  console.log("\n✓ Sharing flow passed.\n");
}

// ── Sub-test: discovery & recovery flow ──────────────────────────────────────

async function runDiscoveryAndRecoveryFlow(): Promise<void> {
  console.log("=== [Protocol] Discovery & Recovery Flow ===\n");

  const owner = makeProtocol("https://owner.example.com");
  const helper = makeProtocol("https://helper.example.com");
  const channelId = 1n;
  const recoveryChannelId = 100n;

  const secretId = new Uint8Array([10, 20, 30, 40]);
  const secretData = new TextEncoder().encode("correct horse battery staple");
  const secretVersion = 1;

  // ── Initial pairing & sharing ──────────────────────────────────────────────

  console.log("  -- Setup: initial pairing & sharing --\n");

  await doPair(owner, helper, SenderKind.Helper, channelId, "InitialPairing");
  console.log();

  await owner.protocol.protectSecret(
    secretId, secretData, "wallet seed phrase", secretVersion,
    1 /* threshold */, [channelId], [],
  );
  const [storeReq] = owner.transport.drain();
  if (!storeReq) throw new Error("missing StoreShareRequest");
  console.log(`  [Owner]  protectSecret  → StoreShareRequest: ${storeReq.message.length} bytes`);

  await helper.protocol.process(storeReq.message);
  const [storeResp] = helper.transport.drain();
  if (!storeResp) throw new Error("missing StoreShareResponse");
  const ownerConfirmEvents = await owner.protocol.process(storeResp.message);
  requireEvent(ownerConfirmEvents, "ShareConfirmed", "Owner");
  console.log(`  [Helper] share stored  [Owner] ShareConfirmed\n`);

  // ── Recovery pairing ───────────────────────────────────────────────────────

  console.log("  -- Recovery: re-pair on a new channel --\n");

  const recoveryContactBytes = await helper.protocol.createContact(recoveryChannelId);
  console.log(`  [Helper] create_contact (recovery)  channel_id=${recoveryChannelId}  (${recoveryContactBytes.length} bytes)`);

  helper.shareStore.copyShare(
    channelId.toString(),
    recoveryChannelId.toString(),
    secretId,
    secretVersion,
  );
  console.log(`  [Helper] share copied to recovery channel (app-layer contact remapping)`);

  await owner.protocol.startPairing(SenderKind.OwnerRecovery, recoveryContactBytes);
  const [recovReq] = owner.transport.drain();
  if (!recovReq) throw new Error("missing recovery PairRequest");
  console.log(`  [Owner]  start_pairing(kind=OwnerRecovery)  → PairRequest: ${recovReq.message.length} bytes`);

  const helperPairEvents = await helper.protocol.process(recovReq.message);
  const helperPairing = requireEvent(helperPairEvents, "PairingComplete", "Helper");
  console.log(`  [Helper] process(recovery PairRequest)  → PairingComplete(kind=${kindName(helperPairing.kind)})`);

  const [recovResp] = helper.transport.drain();
  if (!recovResp) throw new Error("missing recovery PairResponse");

  const ownerPairEvents = await owner.protocol.process(recovResp.message);
  const ownerPairing = requireEvent(ownerPairEvents, "PairingComplete", "Owner");
  console.log(`  [Owner]  process(recovery PairResponse)  → PairingComplete(kind=${kindName(ownerPairing.kind)})`);

  if (ownerPairing.kind !== SenderKind.OwnerRecovery) {
    throw new Error(`expected kind=OwnerRecovery, got ${kindName(ownerPairing.kind)}`);
  }
  console.log(`\n  Recovery pairing complete  channel_id=${recoveryChannelId}\n`);

  // ── Discovery ──────────────────────────────────────────────────────────────

  console.log("  -- Discovery: Owner asks Helper which secrets it holds --\n");

  await owner.protocol.requestDiscovery(recoveryChannelId);
  const [discReq] = owner.transport.drain();
  if (!discReq) throw new Error("missing GetSecretIdsVersionsRequest");
  console.log(`  [Owner]  requestDiscovery  → GetSecretIdsVersionsRequest: ${discReq.message.length} bytes`);

  await helper.protocol.process(discReq.message);
  const [discResp] = helper.transport.drain();
  if (!discResp) throw new Error("missing GetSecretIdsVersionsResponse");
  console.log(`  [Helper] process(discovery request)  → GetSecretIdsVersionsResponse: ${discResp.message.length} bytes`);

  const discEvents = await owner.protocol.process(discResp.message);
  const discEv = requireEvent(discEvents, "SecretsDiscovered", "Owner");
  console.log(`  [Owner]  SecretsDiscovered  channel_id=${discEv.channel_id}  secrets=${discEv.secrets.length}`);

  const walletEntry = discEv.secrets.find(
    (s) =>
      s.secret_id.length === secretId.length &&
      s.secret_id.every((b, i) => b === secretId[i]),
  );
  if (!walletEntry) throw new Error("wallet seed not found in SecretsDiscovered");

  const walletVersion = walletEntry.versions.find((v) => v.version === secretVersion);
  if (!walletVersion) throw new Error(`version ${secretVersion} not in discovered entry`);
  if (walletVersion.description !== "wallet seed phrase") {
    throw new Error(`description mismatch: "${walletVersion.description}"`);
  }
  console.log(`    secret_id=${walletEntry.secret_id.length}B  version=${walletVersion.version}  description="${walletVersion.description}"  ✓`);
  console.log(`\n  Description round-tripped through discovery correctly.\n`);

  // ── Recovery ───────────────────────────────────────────────────────────────

  console.log("  -- Recovery: collect share and reconstruct secret --\n");

  await owner.protocol.recoverSecret(secretId, secretVersion, [recoveryChannelId]);
  const [shareReq] = owner.transport.drain();
  if (!shareReq) throw new Error("missing GetShareRequest");
  console.log(`  [Owner]  recoverSecret  → GetShareRequest: ${shareReq.message.length} bytes`);

  await helper.protocol.process(shareReq.message);
  const [shareResp] = helper.transport.drain();
  if (!shareResp) throw new Error("missing GetShareResponse");
  console.log(`  [Helper] process(GetShareRequest)  → GetShareResponse: ${shareResp.message.length} bytes`);

  const recovEvents = await owner.protocol.process(shareResp.message);
  const recovEv = requireEvent(recovEvents, "SecretRecovered", "Owner");

  if (!recovEv.secret || recovEv.secret.length === 0) {
    throw new Error("SecretRecovered: empty secret bytes");
  }
  const originalBytes = new TextEncoder().encode("correct horse battery staple");
  if (
    recovEv.secret.length !== originalBytes.length ||
    !recovEv.secret.every((b, i) => b === originalBytes[i])
  ) {
    throw new Error("SecretRecovered: bytes do not match original secret");
  }
  console.log(`  [Owner]  SecretRecovered  ${recovEv.secret.length} bytes — matches original ✓`);

  console.log("\n✓ Discovery & Recovery flow passed.\n");
}

// ── Entry point ───────────────────────────────────────────────────────────────

export async function runProtocolSmoke(): Promise<void> {
  console.log("━━━ [Protocol] Starting ━━━\n");

  await runPairingFlow();
  await runSharingFlow();
  await runDiscoveryAndRecoveryFlow();

  console.log("━━━ [Protocol] All passed. ━━━\n");
}
