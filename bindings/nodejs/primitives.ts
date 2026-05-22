// SPDX-License-Identifier: Apache-2.0
//
// Primitives smoke tests: exercises every flow using the low-level
// `primitives.*` API (raw message produce / extract / process functions).
//
// Mirrors the current Rust primitive smoke test
// (`bindings/rust/src/primitives.rs`) one-for-one, against the post-refactor
// signatures:
//   - `secret_id` is a u64 → pass a `bigint`
//   - `version` is a u32 → pass a `number`
//   - channel ids are u64 → pass a `bigint`
//   - shared keys / serialized material are `Uint8Array`
//   - pairing responses go through `pairing.response.accept` (the old
//     `pairing.response.produce` was removed) then `pairing.response.process`
//
// The `primitives` namespace is the `any`-typed escape hatch from
// `@derec-alliance/nodejs`; every step's argument/return object shape is
// documented in `library/src/wasm/primitives/*`. Returns are deliberately
// untyped, so this file pins the relevant fields explicitly.

import { primitives, SenderKind } from "@derec-alliance/nodejs";

// ── Helpers ───────────────────────────────────────────────────────────────────

function sharedKey(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

function asBytes(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) return value;
  if (Array.isArray(value)) return new Uint8Array(value as number[]);
  throw new Error(`expected byte array, got ${typeof value}`);
}

interface DiscoveredEntry {
  secret_id: number;
  versions: Array<{ version: number; description: string }>;
}

// ── Entry point ───────────────────────────────────────────────────────────────

export function runPrimitivesSmoke(): void {
  console.log("━━━ [Primitives] Starting ━━━\n");

  const secretId = 0x0102_0304_05ffn;
  const secretData = new Uint8Array([5, 6, 7, 8, 255]);
  const channelIds: bigint[] = [1n, 2n, 3n];
  const threshold = 2;
  const version = 1;

  const sharedKeys = new Map<bigint, Uint8Array>();
  sharedKeys.set(1n, sharedKey(1));
  sharedKeys.set(2n, sharedKey(2));
  sharedKeys.set(3n, sharedKey(3));

  const keyFor = (channelId: bigint): Uint8Array => {
    const key = sharedKeys.get(channelId);
    if (!key) throw new Error(`missing shared key for channel ${channelId}`);
    return key;
  };

  // ── Sharing flow ────────────────────────────────────────────────────────────

  console.log("=== [Primitives] Sharing Flow ===");

  const splitResult = primitives.sharing.request.split(
    secretId,
    secretData,
    channelIds,
    threshold,
    version,
  );

  // Wire shape: `{ value: { [channelId: u64]: Uint8Array } }`. Tolerate Map /
  // array-of-pairs / plain-object encodings since `serde_wasm_bindgen` map
  // serialization can vary by host.
  const shares = new Map<bigint, Uint8Array>();
  const splitValue: unknown = (splitResult as { value?: unknown } | null)?.value;

  if (splitValue instanceof Map) {
    for (const [k, v] of splitValue.entries()) {
      shares.set(BigInt(k as string | number | bigint), asBytes(v));
    }
  } else if (Array.isArray(splitValue)) {
    for (const entry of splitValue as unknown[]) {
      if (Array.isArray(entry) && entry.length === 2) {
        shares.set(BigInt(entry[0] as string | number | bigint), asBytes(entry[1]));
      }
    }
  } else if (splitValue && typeof splitValue === "object") {
    for (const [k, v] of Object.entries(splitValue as Record<string, unknown>)) {
      shares.set(BigInt(k), asBytes(v));
    }
  } else {
    throw new Error(
      `Unexpected split result shape: ${JSON.stringify(splitResult)}`,
    );
  }

  if (shares.size !== channelIds.length) {
    throw new Error(
      `Sharing failed: expected ${channelIds.length} shares, got ${shares.size}`,
    );
  }

  // The Helper persists the decrypted StoreShareRequest envelope; recovery and
  // verification both reuse it as the stored-request input.
  const storedEnvelopes = new Map<bigint, unknown>();

  for (const [channelId, shareBytes] of shares.entries()) {
    console.log(
      `  [split] channel=${channelId}  committed_share=${shareBytes.length} bytes`,
    );
    if (shareBytes.length === 0) {
      throw new Error(
        `Sharing failed: empty CommittedDeRecShare for channel ${channelId}`,
      );
    }

    const decoded = primitives.sharing.decode_committed_share(shareBytes) as {
      de_rec_share?: { version?: number; x?: Uint8Array; y?: Uint8Array };
      commitment?: Uint8Array;
      merkle_path?: unknown[];
    };
    console.log(
      `    de_rec_share.version=${decoded.de_rec_share?.version}  ` +
        `x=${decoded.de_rec_share?.x?.length ?? 0}B  ` +
        `y=${decoded.de_rec_share?.y?.length ?? 0}B  ` +
        `commitment=${decoded.commitment?.length ?? 0}B  ` +
        `merkle_path_nodes=${decoded.merkle_path?.length ?? 0}`,
    );

    const key = keyFor(channelId);
    const requestEnvelope = primitives.sharing.request.produce(
      channelId,
      version,
      secretId,
      shareBytes,
      [],
      "",
      key,
    ) as { channel_id?: unknown };
    console.log(
      `  [request.produce] channel=${channelId}  channel_id=${requestEnvelope.channel_id}`,
    );
    if (!requestEnvelope.channel_id) {
      throw new Error(
        `Sharing failed: invalid StoreShareRequest envelope for channel ${channelId}`,
      );
    }
    storedEnvelopes.set(channelId, requestEnvelope);

    const processResult = primitives.sharing.response.produce(
      channelId,
      key,
      requestEnvelope,
    ) as {
      envelope?: unknown;
      committed_share?: Uint8Array;
      secret_id?: number;
      version?: number;
    };
    const responseEnvelope = processResult.envelope ?? processResult;
    const committedShare = processResult.committed_share;
    const respSecretId = processResult.secret_id;
    const respVersion = processResult.version;

    console.log(
      `  [response.produce] channel=${channelId}  committed_share=${committedShare?.length ?? 0}B  version=${respVersion}`,
    );
    if (!committedShare || committedShare.length === 0) {
      throw new Error(
        `Sharing failed: empty committed_share for channel ${channelId}`,
      );
    }
    if (respSecretId === undefined || respSecretId !== Number(secretId)) {
      throw new Error(
        `Sharing failed: secret_id mismatch for channel ${channelId}: expected ${Number(secretId)}, got ${respSecretId}`,
      );
    }
    if (respVersion !== version) {
      throw new Error(
        `Sharing failed: version mismatch for channel ${channelId}: expected ${version}, got ${respVersion}`,
      );
    }

    primitives.sharing.response.process(version, key, responseEnvelope);
    console.log(`  [response.process] channel=${channelId}  validated OK`);
  }

  console.log("✓ Sharing flow passed.\n");

  // ── Verification flow ───────────────────────────────────────────────────────

  console.log("=== [Primitives] Verification Flow ===");

  const someChannel = 1n;
  const otherChannel = 2n;
  const someSharedKey = keyFor(someChannel);
  const storedEnvelope1 = storedEnvelopes.get(someChannel);
  const storedEnvelope2 = storedEnvelopes.get(otherChannel);
  if (!storedEnvelope1 || !storedEnvelope2) {
    throw new Error("Verification failed: missing stored share envelope(s)");
  }

  const verificationRequest = primitives.verification.request.produce(
    someChannel,
    secretId,
    version,
    someSharedKey,
  ) as { channel_id?: unknown };
  console.log(`  [request.produce] channel_id=${verificationRequest.channel_id}`);
  if (!verificationRequest.channel_id) {
    throw new Error("Verification failed: invalid request envelope");
  }

  const reqResult = primitives.verification.request.extract(
    verificationRequest,
    someSharedKey,
  ) as {
    channel_id?: bigint | number;
    secret_id?: bigint | number;
    version?: number;
    nonce?: bigint | number;
  };
  const reqChannelId = BigInt(reqResult.channel_id ?? 0);
  const reqSecretId = BigInt(reqResult.secret_id ?? 0);
  const reqVersion = reqResult.version ?? 0;
  const reqNonce = BigInt(reqResult.nonce ?? 0);
  console.log(
    `  [request.extract] channel_id=${reqChannelId}  secret_id=${reqSecretId}  nonce=${reqNonce}`,
  );

  if (reqChannelId !== someChannel) {
    throw new Error(`expected channel_id ${someChannel}, got ${reqChannelId}`);
  }
  if (reqSecretId !== secretId) {
    throw new Error(`secret_id mismatch: expected ${secretId}, got ${reqSecretId}`);
  }
  if (reqVersion !== version) {
    throw new Error(`version mismatch: expected ${version}, got ${reqVersion}`);
  }
  if (reqNonce === 0n) throw new Error("nonce must not be zero");

  const verificationResponse = primitives.verification.response.produce(
    someChannel,
    reqSecretId,
    reqVersion,
    reqNonce,
    someSharedKey,
    storedEnvelope1,
  ) as { channel_id?: unknown };
  console.log(`  [response.produce] channel_id=${verificationResponse.channel_id}`);
  if (!verificationResponse.channel_id) {
    throw new Error("Verification failed: invalid response envelope");
  }

  const resultTrue = primitives.verification.response.process(
    verificationResponse,
    someSharedKey,
    storedEnvelope1,
  );
  console.log(`  [response.process] correct share  → ${resultTrue}  (expected true)`);
  if (!resultTrue) throw new Error("expected true for correct share");

  const resultFalse = primitives.verification.response.process(
    verificationResponse,
    someSharedKey,
    storedEnvelope2,
  );
  console.log(`  [response.process] wrong share    → ${resultFalse}  (expected false)`);
  if (resultFalse) throw new Error("expected false for wrong share");

  console.log("✓ Verification flow passed.\n");

  // ── Discovery flow ──────────────────────────────────────────────────────────

  console.log("=== [Primitives] Discovery Flow ===");

  const discoveryChannelId = 1n;
  const discoverySharedKey = keyFor(discoveryChannelId);

  const discoveryRequest = primitives.discovery.request.produce(
    discoveryChannelId,
    discoverySharedKey,
  ) as { channel_id?: unknown };
  console.log(`  [request.produce] channel_id=${discoveryRequest.channel_id}`);
  if (!discoveryRequest.channel_id) {
    throw new Error("Discovery failed: invalid request envelope");
  }

  const discoveryReqExtracted = primitives.discovery.request.extract(
    discoveryRequest,
    discoverySharedKey,
  ) as { channel_id?: bigint | number };
  console.log(`  [request.extract] channel_id=${discoveryReqExtracted.channel_id}`);
  if (BigInt(discoveryReqExtracted.channel_id ?? 0) !== discoveryChannelId) {
    throw new Error("Discovery failed: unexpected channel_id after extract");
  }

  const helperSecretList = [
    {
      secret_id: secretId,
      versions: [{ version, description: "smoke-test secret" }],
    },
  ];
  const discoveryResponse = primitives.discovery.response.produce(
    discoveryChannelId,
    helperSecretList,
    discoverySharedKey,
  ) as { channel_id?: unknown };
  console.log(`  [response.produce] channel_id=${discoveryResponse.channel_id}`);
  if (!discoveryResponse.channel_id) {
    throw new Error("Discovery failed: invalid response envelope");
  }

  const discoveredSecrets: DiscoveredEntry[] =
    primitives.discovery.response.process(discoveryResponse, discoverySharedKey);
  console.log(
    `  [response.process] ${discoveredSecrets.length} secret(s) discovered`,
  );
  if (discoveredSecrets.length === 0) {
    throw new Error("Discovery failed: empty list");
  }

  const entry = discoveredSecrets[0]!;
  const firstVersion = entry.versions[0];
  console.log(
    `    secret_id=${entry.secret_id}  version=${firstVersion?.version}  description="${firstVersion?.description}"`,
  );
  if (entry.secret_id !== Number(secretId)) {
    throw new Error(
      `secret_id mismatch: expected ${Number(secretId)}, got ${entry.secret_id}`,
    );
  }
  if (!firstVersion) throw new Error("no versions");
  if (firstVersion.version !== version) {
    throw new Error(`version mismatch: ${firstVersion.version}`);
  }
  if (firstVersion.description !== "smoke-test secret") {
    throw new Error(`description mismatch: "${firstVersion.description}"`);
  }

  console.log("✓ Discovery flow passed.\n");

  // ── Recovery flow ───────────────────────────────────────────────────────────

  console.log("=== [Primitives] Recovery Flow ===");

  const storedFor = (channelId: bigint): unknown => {
    const stored = storedEnvelopes.get(channelId);
    if (!stored) {
      throw new Error(`missing stored share envelope for channel ${channelId}`);
    }
    return stored;
  };

  const makeShareReq = (channelId: bigint): unknown =>
    primitives.recovery.request.produce(
      channelId,
      secretId,
      version,
      keyFor(channelId),
    );
  const makeShareResp = (channelId: bigint, req: unknown): unknown =>
    primitives.recovery.response.produce(
      secretId,
      channelId,
      storedFor(channelId),
      req,
      keyFor(channelId),
    );

  const shareRequest1 = makeShareReq(1n);
  const shareResponse1 = makeShareResp(1n, shareRequest1);
  const shareRequest2 = makeShareReq(2n);
  const shareResponse2 = makeShareResp(2n, shareRequest2);
  const shareRequest3 = makeShareReq(3n);
  const shareResponse3 = makeShareResp(3n, shareRequest3);

  console.log(`  [request.produce] channels 1, 2, 3  request envelopes generated`);
  console.log(`  [response.produce] channels 1, 2, 3  response envelopes generated`);

  const recoveryResponses = [
    { response: shareResponse1, shared_key: keyFor(1n) },
    { response: shareResponse2, shared_key: keyFor(2n) },
    { response: shareResponse3, shared_key: keyFor(3n) },
  ];

  const recovered: Uint8Array = primitives.recovery.response.recover(
    recoveryResponses,
    secretId,
    version,
  );
  console.log(`  [response.recover] recovered ${recovered.length} bytes`);

  if (recovered.length === 0) throw new Error("Recovery failed: empty result");
  if (
    recovered.length !== secretData.length ||
    !recovered.every((b, i) => b === secretData[i])
  ) {
    throw new Error("Recovery failed: recovered secret does not match original");
  }
  console.log("  secret bytes match original ✓");
  console.log("✓ Recovery flow passed.\n");

  // ── Pairing flow ────────────────────────────────────────────────────────────

  console.log("=== [Primitives] Pairing Flow ===");

  const pairingChannelId = 1n;
  const roleHelper = SenderKind.Helper;
  const roleOwner = SenderKind.Owner;

  // Initiator creates an out-of-band contact.
  const createContactResult = primitives.pairing.request.create_contact(
    pairingChannelId,
    { protocol: "https", uri: "https://example.com/alice" },
  ) as { contact_message?: unknown; secret_key_material?: Uint8Array };
  console.log(
    `  [request.create_contact] contact_message present=${!!createContactResult.contact_message}  ` +
      `key_material=${createContactResult.secret_key_material?.length ?? 0}B`,
  );
  if (!createContactResult.contact_message) {
    throw new Error("Pairing failed: missing contact_message");
  }
  if (!createContactResult.secret_key_material?.length) {
    throw new Error("Pairing failed: empty secret_key_material");
  }

  // Responder produces a pairing request from the contact.
  const pairingRequestResult = primitives.pairing.request.produce(
    roleHelper,
    { protocol: "https", uri: "https://example.com/helper" },
    createContactResult.contact_message,
  ) as {
    envelope?: unknown;
    initiator_contact_message?: unknown;
    secret_key_material?: Uint8Array;
  };
  console.log(
    `  [request.produce] envelope present=${!!pairingRequestResult.envelope}`,
  );
  if (!pairingRequestResult.envelope) {
    throw new Error("Pairing failed: missing envelope");
  }
  const responderSecretKeyMaterial = pairingRequestResult.secret_key_material;
  if (!responderSecretKeyMaterial?.length) {
    throw new Error("Pairing failed: empty responder secret_key_material");
  }

  // Initiator accepts the request and derives the initiator-side shared key.
  const pairingAcceptResult = primitives.pairing.response.accept(
    roleOwner,
    pairingRequestResult.envelope,
    createContactResult.secret_key_material,
  ) as { envelope?: unknown; pairing_shared_key?: Uint8Array };
  console.log(
    `  [response.accept]  pairing_shared_key=${pairingAcceptResult.pairing_shared_key?.length ?? 0}B`,
  );
  if (!pairingAcceptResult.pairing_shared_key?.length) {
    throw new Error("Pairing failed: empty pairing_shared_key (accept)");
  }
  if (!pairingAcceptResult.envelope) {
    throw new Error("Pairing failed: missing response envelope (accept)");
  }

  // Responder processes the response and derives the responder-side shared key.
  const pairingProcessResult = primitives.pairing.response.process(
    pairingRequestResult.initiator_contact_message,
    pairingAcceptResult.envelope,
    responderSecretKeyMaterial,
  ) as { pairing_shared_key?: Uint8Array };
  console.log(
    `  [response.process] pairing_shared_key=${pairingProcessResult.pairing_shared_key?.length ?? 0}B`,
  );
  if (!pairingProcessResult.pairing_shared_key?.length) {
    throw new Error("Pairing failed: empty pairing_shared_key (process)");
  }

  const ownerKey = pairingAcceptResult.pairing_shared_key;
  const helperKey = pairingProcessResult.pairing_shared_key;
  const keysMatch =
    ownerKey.length === helperKey.length &&
    ownerKey.every((b, i) => b === helperKey[i]);
  console.log(`  shared keys match: ${keysMatch}`);
  if (!keysMatch) throw new Error("Pairing failed: shared keys do not match");

  console.log("✓ Pairing flow passed.\n");

  console.log("━━━ [Primitives] All passed. ━━━\n");
}
