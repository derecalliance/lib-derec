// SPDX-License-Identifier: Apache-2.0
//
// Primitives smoke tests: exercises every flow using the low-level
// `primitives.*` API (raw message produce/process functions).

import { primitives, SenderKind } from "@derec-alliance/web";

function sharedKey(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

export async function runPrimitivesSmoke(): Promise<void> {
  console.log("━━━ [Primitives] Starting ━━━\n");

  const secretId = new Uint8Array([1, 2, 3, 4, 255]);
  const secretData = new Uint8Array([5, 6, 7, 8, 255]);
  const channelIds = [1n, 2n, 3n];
  const threshold = 2;
  const version = 1;

  const sharedKeys = new Map<bigint, Uint8Array>();
  sharedKeys.set(1n, sharedKey(1));
  sharedKeys.set(2n, sharedKey(2));
  sharedKeys.set(3n, sharedKey(3));

  // ── Sharing flow ────────────────────────────────────────────────────────────

  console.log("=== [Primitives] Sharing Flow ===");

  const splitResult = primitives.sharing.request.split(
    secretId,
    secretData,
    channelIds,
    threshold,
    version
  );

  const shares = new Map<bigint, Uint8Array>();

  if ((splitResult as any)?.value instanceof Map) {
    for (const [k, v] of (splitResult as any).value.entries()) {
      shares.set(BigInt(k), v as Uint8Array);
    }
  } else if (Array.isArray((splitResult as any)?.value)) {
    for (const entry of (splitResult as any).value) {
      if (Array.isArray(entry) && entry.length === 2) {
        shares.set(BigInt(entry[0]), entry[1] as Uint8Array);
      }
    }
  } else if ((splitResult as any)?.value && typeof (splitResult as any).value === "object") {
    for (const [k, v] of Object.entries((splitResult as any).value)) {
      shares.set(BigInt(k), v as Uint8Array);
    }
  } else {
    throw new Error(`Unexpected split result shape: ${JSON.stringify(splitResult)}`);
  }

  if (shares.size !== channelIds.length) {
    throw new Error(`Sharing failed: expected ${channelIds.length} shares, got ${shares.size}`);
  }

  const storedEnvelopes = new Map<bigint, any>();

  for (const [channelId, shareBytes] of shares.entries()) {
    console.log(`  [split] channel=${channelId}  committed_share=${(shareBytes as any)?.length ?? 0} bytes`);
    if (!shareBytes || (shareBytes as any).length === 0) {
      throw new Error(`Sharing failed: empty CommittedDeRecShare for channel ${channelId}`);
    }

    const key = sharedKeys.get(channelId)!;
    const requestEnvelope = primitives.sharing.request.produce(
      channelId, version, secretId, shareBytes as Uint8Array, [], "", key
    );
    console.log(`  [request.produce] channel=${channelId}  channel_id=${(requestEnvelope as any)?.channel_id}`);
    if (!(requestEnvelope as any)?.channel_id) {
      throw new Error(`Sharing failed: invalid StoreShareRequest envelope for channel ${channelId}`);
    }
    storedEnvelopes.set(channelId, requestEnvelope);

    const processResult = primitives.sharing.response.produce(channelId, key, requestEnvelope);
    const responseEnvelope = (processResult as any)?.envelope ?? processResult;
    const committedShare: Uint8Array = (processResult as any)?.committed_share;
    const respSecretId: Uint8Array = (processResult as any)?.secret_id;
    const respVersion: number = (processResult as any)?.version;

    console.log(`  [response.produce] channel=${channelId}  committed_share=${committedShare?.length ?? 0}B  version=${respVersion}`);
    if (!committedShare || committedShare.length === 0) {
      throw new Error(`Sharing failed: empty committed_share for channel ${channelId}`);
    }
    if (!respSecretId || respSecretId.length === 0) {
      throw new Error(`Sharing failed: empty secret_id for channel ${channelId}`);
    }
    if (respVersion !== version) {
      throw new Error(`Sharing failed: version mismatch for channel ${channelId}: expected ${version}, got ${respVersion}`);
    }

    primitives.sharing.response.process(version, key, responseEnvelope);
    console.log(`  [response.process] channel=${channelId}  validated OK`);
  }

  console.log("✓ Sharing flow passed.\n");

  // ── Verification flow ───────────────────────────────────────────────────────

  console.log("=== [Primitives] Verification Flow ===");

  const someChannel = 1n;
  const otherChannel = 2n;
  const someSharedKey = sharedKeys.get(someChannel)!;
  const storedEnvelope1 = storedEnvelopes.get(someChannel)!;
  const storedEnvelope2 = storedEnvelopes.get(otherChannel)!;

  const verificationRequest = primitives.verification.request.produce(
    someChannel, secretId, version, someSharedKey
  );
  console.log(`  [request.produce] channel_id=${(verificationRequest as any)?.channel_id}`);
  if (!(verificationRequest as any)?.channel_id) {
    throw new Error("Verification failed: invalid request envelope");
  }

  const reqResult = primitives.verification.request.extract(verificationRequest, someSharedKey);
  const reqChannelId = BigInt((reqResult as any).channel_id ?? 0);
  const reqSecretId = new Uint8Array((reqResult as any).secret_id ?? []);
  const reqVersion: number = (reqResult as any).version ?? 0;
  const reqNonce = BigInt((reqResult as any).nonce ?? 0);
  console.log(`  [request.extract] channel_id=${reqChannelId}  nonce=${reqNonce}`);

  if (reqChannelId !== someChannel) throw new Error(`expected channel_id ${someChannel}, got ${reqChannelId}`);
  if (reqSecretId.length === 0) throw new Error("secret_id is empty");
  if (reqVersion !== version) throw new Error(`version mismatch: expected ${version}, got ${reqVersion}`);
  if (reqNonce === 0n) throw new Error("nonce must not be zero");

  const verificationResponse = primitives.verification.response.produce(
    someChannel, reqSecretId, reqVersion, reqNonce, someSharedKey, storedEnvelope1
  );
  console.log(`  [response.produce] channel_id=${(verificationResponse as any)?.channel_id}`);
  if (!(verificationResponse as any)?.channel_id) {
    throw new Error("Verification failed: invalid response envelope");
  }

  const resultTrue = primitives.verification.response.process(
    verificationResponse, someSharedKey, storedEnvelope1
  );
  console.log(`  [response.process] correct share  → ${resultTrue}  (expected true)`);
  if (!resultTrue) throw new Error("expected true for correct share");

  const resultFalse = primitives.verification.response.process(
    verificationResponse, someSharedKey, storedEnvelope2
  );
  console.log(`  [response.process] wrong share    → ${resultFalse}  (expected false)`);
  if (resultFalse) throw new Error("expected false for wrong share");

  console.log("✓ Verification flow passed.\n");

  // ── Discovery flow ──────────────────────────────────────────────────────────

  console.log("=== [Primitives] Discovery Flow ===");

  const discoveryChannelId = 1n;
  const discoverySharedKey = sharedKeys.get(discoveryChannelId)!;

  const discoveryRequest = primitives.discovery.request.produce(discoveryChannelId, discoverySharedKey);
  console.log(`  [request.produce] channel_id=${(discoveryRequest as any)?.channel_id}`);
  if (!(discoveryRequest as any)?.channel_id) throw new Error("Discovery failed: invalid request envelope");

  const discoveryReqExtracted = primitives.discovery.request.extract(discoveryRequest, discoverySharedKey);
  console.log(`  [request.extract] channel_id=${(discoveryReqExtracted as any).channel_id}`);
  if (!discoveryReqExtracted || BigInt((discoveryReqExtracted as any).channel_id) !== discoveryChannelId) {
    throw new Error("Discovery failed: unexpected channel_id after extract");
  }

  const helperSecretList = [
    { secret_id: secretId, versions: [{ version, description: "smoke-test secret" }] },
  ];
  const discoveryResponse = primitives.discovery.response.produce(
    discoveryChannelId, helperSecretList, discoverySharedKey
  );
  console.log(`  [response.produce] channel_id=${(discoveryResponse as any)?.channel_id}`);
  if (!(discoveryResponse as any)?.channel_id) throw new Error("Discovery failed: invalid response envelope");

  const discoveredSecrets = primitives.discovery.response.process(discoveryResponse, discoverySharedKey);
  console.log(`  [response.process] ${discoveredSecrets?.length ?? 0} secret(s) discovered`);
  if (!discoveredSecrets || discoveredSecrets.length === 0) throw new Error("Discovery failed: empty list");

  const entry = discoveredSecrets[0]!;
  console.log(`    secret_id=${entry.secret_id.length}B  version=${entry.versions[0]?.version}  description="${entry.versions[0]?.description}"`);
  if (!entry.secret_id || entry.secret_id.length === 0) throw new Error("empty secret_id");
  if (!entry.versions || entry.versions.length === 0) throw new Error("no versions");
  if (entry.versions[0]!.version !== version) throw new Error(`version mismatch: ${entry.versions[0]!.version}`);
  if (entry.versions[0]!.description !== "smoke-test secret") throw new Error(`description mismatch`);
  if (!secretId.every((b: number, i: number) => b === entry.secret_id[i])) throw new Error("secret_id bytes do not match");

  console.log("✓ Discovery flow passed.\n");

  // ── Recovery flow ───────────────────────────────────────────────────────────

  console.log("=== [Primitives] Recovery Flow ===");

  const shareRequest1 = primitives.recovery.request.produce(1n, secretId, version, sharedKeys.get(1n)!);
  const shareResponse1 = primitives.recovery.response.produce(secretId, 1n, storedEnvelopes.get(1n)!, shareRequest1, sharedKeys.get(1n)!);
  const shareRequest2 = primitives.recovery.request.produce(2n, secretId, version, sharedKeys.get(2n)!);
  const shareResponse2 = primitives.recovery.response.produce(secretId, 2n, storedEnvelopes.get(2n)!, shareRequest2, sharedKeys.get(2n)!);
  const shareRequest3 = primitives.recovery.request.produce(3n, secretId, version, sharedKeys.get(3n)!);
  const shareResponse3 = primitives.recovery.response.produce(secretId, 3n, storedEnvelopes.get(3n)!, shareRequest3, sharedKeys.get(3n)!);

  console.log(`  [request.produce] channels 1, 2, 3  request envelopes generated`);
  console.log(`  [response.produce] channels 1, 2, 3  response envelopes generated`);

  const recoveryResponses = [
    { response: shareResponse1, shared_key: sharedKeys.get(1n)! },
    { response: shareResponse2, shared_key: sharedKeys.get(2n)! },
    { response: shareResponse3, shared_key: sharedKeys.get(3n)! },
  ];

  const recovered = primitives.recovery.response.recover(recoveryResponses, secretId, version);
  console.log(`  [response.recover] recovered ${recovered?.length ?? 0} bytes`);

  if (!recovered || recovered.length === 0) throw new Error("Recovery failed: empty result");
  if (!recovered.every((b: number, i: number) => b === secretData[i])) {
    throw new Error("Recovery failed: recovered secret does not match original");
  }
  console.log("  secret bytes match original ✓");
  console.log("✓ Recovery flow passed.\n");

  // ── Pairing flow ────────────────────────────────────────────────────────────

  console.log("=== [Primitives] Pairing Flow ===");

  const pairingChannelId = 1n;
  const roleHelper = SenderKind.Helper;
  const roleOwner = SenderKind.OwnerNonRecovery;

  const createContactResult = primitives.pairing.request.create_contact(
    pairingChannelId,
    { protocol: "https", uri: "https://example.com/alice" }
  );
  console.log(`  [request.create_contact] contact_message present=${!!(createContactResult as any)?.contact_message}  key_material=${(createContactResult as any)?.secret_key_material?.length ?? 0}B`);
  if (!(createContactResult as any)?.contact_message) throw new Error("Pairing failed: missing contact_message");

  const pairingRequestResult = primitives.pairing.request.produce(
    roleHelper,
    { protocol: "https", uri: "https://example.com/helper" },
    (createContactResult as any).contact_message
  );
  console.log(`  [request.produce] envelope present=${!!(pairingRequestResult as any)?.envelope}`);
  if (!(pairingRequestResult as any)?.envelope) throw new Error("Pairing failed: missing envelope");

  const pairingResponseResult = primitives.pairing.response.produce(
    roleOwner,
    (pairingRequestResult as any).envelope,
    (createContactResult as any).secret_key_material
  );
  console.log(`  [response.produce] pairing_shared_key=${(pairingResponseResult as any)?.pairing_shared_key?.length ?? 0}B`);
  if (!(pairingResponseResult as any)?.pairing_shared_key?.length) throw new Error("Pairing failed: empty pairing_shared_key");

  const pairingProcessResult = primitives.pairing.response.process(
    (pairingRequestResult as any).initiator_contact_message,
    (pairingResponseResult as any).envelope,
    (pairingRequestResult as any).secret_key_material
  );
  console.log(`  [response.process] pairing_shared_key=${(pairingProcessResult as any)?.pairing_shared_key?.length ?? 0}B`);
  if (!(pairingProcessResult as any)?.pairing_shared_key?.length) throw new Error("Pairing failed: empty pairing_shared_key");

  const ownerKey: Uint8Array = (pairingResponseResult as any).pairing_shared_key;
  const helperKey: Uint8Array = (pairingProcessResult as any).pairing_shared_key;
  const keysMatch = ownerKey.length === helperKey.length &&
    ownerKey.every((b: number, i: number) => b === helperKey[i]);
  console.log(`  shared keys match: ${keysMatch}`);
  if (!keysMatch) throw new Error("Pairing failed: shared keys do not match");

  console.log("✓ Pairing flow passed.\n");

  console.log("━━━ [Primitives] All passed. ━━━\n");
}
