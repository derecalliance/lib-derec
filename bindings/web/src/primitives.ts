// SPDX-License-Identifier: Apache-2.0
//
// Primitives smoke tests: exercises every flow using the low-level
// `primitives.*` API (raw message produce / extract / process functions).
//
// Mirrors the Rust primitive smoke test (`bindings/rust/src/primitives.rs`).
// The chain in each flow is request.produce → request.extract → response.produce
// → response.extract → response.process, matching the current Rust signatures
// one-for-one.

import {
  primitives,
  SenderKind,
  type ContactMessage,
  type GetShareResponseMessage,
  type PairRequestMessage,
  type PairResponseMessage,
  type SecretVersionEntry,
  type StoreShareRequestMessage,
} from "@derec-alliance/web";

function sharedKey(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

export function runPrimitivesSmoke(): void {
  console.log("━━━ [Primitives] Starting ━━━\n");

  const secretId = 0x0102_0304_05ffn;
  const secretData = new Uint8Array([5, 6, 7, 8, 255]);
  const channelIds: bigint[] = [1n, 2n, 3n];
  const threshold = 2;
  const version = 1;

  const sharedKeys = new Map<bigint, Uint8Array>();
  for (const id of channelIds) sharedKeys.set(id, sharedKey(Number(id)));
  const keyFor = (id: bigint): Uint8Array => {
    const k = sharedKeys.get(id);
    if (!k) throw new Error(`missing shared key for channel ${id}`);
    return k;
  };

  // ── Sharing ───────────────────────────────────────────────────────────────

  console.log("=== [Primitives] Sharing Flow ===");

  const { shares } = primitives.sharing.request.split(
    channelIds,
    secretId,
    version,
    secretData,
    threshold,
  );
  if (shares.size !== channelIds.length) {
    throw new Error(
      `Sharing failed: expected ${channelIds.length} shares, got ${shares.size}`,
    );
  }

  // Helper-side persisted store-share inner request — reused later by
  // verification and recovery, mirroring how a real helper would persist it.
  const storedShareRequests = new Map<bigint, StoreShareRequestMessage>();

  for (const id of channelIds) {
    const key = keyFor(id);
    const committedShare = shares.get(id);
    if (!committedShare) throw new Error(`no committed share for channel ${id}`);

    const requestEnvelope = primitives.sharing.request.produce(
      id, version, secretId, committedShare, [], "", key,
    );
    console.log(`  [request.produce] channel=${id} envelope=${requestEnvelope.envelope.length}B`);

    // Helper side: extract then produce response.
    const { request } = primitives.sharing.request.extract(
      requestEnvelope.envelope, key,
    );
    storedShareRequests.set(id, request);

    const responseResult = primitives.sharing.response.produce(id, request, key);
    if (responseResult.secret_id !== secretId) {
      throw new Error(`secret_id mismatch on channel ${id}`);
    }
    if (responseResult.version !== version) {
      throw new Error(`version mismatch on channel ${id}`);
    }

    // Owner side: extract then process.
    const { response } = primitives.sharing.response.extract(
      responseResult.envelope, key,
    );
    primitives.sharing.response.process(version, response);
    console.log(`  [response.process] channel=${id} validated OK`);
  }

  console.log("✓ Sharing flow passed.\n");

  // ── Verification ──────────────────────────────────────────────────────────

  console.log("=== [Primitives] Verification Flow ===");

  const verifyChannel = 1n;
  const verifyKey = keyFor(verifyChannel);
  const storedFor1 = storedShareRequests.get(1n)!;
  const storedFor2 = storedShareRequests.get(2n)!;

  // Owner side: produce request.
  const verifyReqEnvelope = primitives.verification.request.produce(
    verifyChannel, secretId, version, verifyKey,
  );

  // Helper side: extract + produce response (the share content is the inner
  // `share` field from the stored StoreShareRequest).
  const { request: verifyRequest } = primitives.verification.request.extract(
    verifyReqEnvelope.envelope, verifyKey,
  );
  if (verifyRequest.secret_id !== secretId) {
    throw new Error("verification request secret_id mismatch");
  }
  const verifyRespEnvelope = primitives.verification.response.produce(
    verifyChannel, verifyRequest, verifyKey, storedFor1.share,
  );

  // Owner side: extract + process against the correct and wrong share.
  const { response: verifyResponse } = primitives.verification.response.extract(
    verifyRespEnvelope.envelope, verifyKey,
  );
  const valid = primitives.verification.response.process(verifyResponse, storedFor1.share);
  if (!valid) throw new Error("expected true for matching share");
  const invalid = primitives.verification.response.process(verifyResponse, storedFor2.share);
  if (invalid) throw new Error("expected false for wrong share");
  console.log(`  [response.process] correct=true wrong=false  ✓`);

  console.log("✓ Verification flow passed.\n");

  // ── Discovery ─────────────────────────────────────────────────────────────

  console.log("=== [Primitives] Discovery Flow ===");

  const discChannel = 1n;
  const discKey = keyFor(discChannel);

  const discReqEnvelope = primitives.discovery.request.produce(discChannel, discKey);
  const _discRequest = primitives.discovery.request.extract(discReqEnvelope.envelope, discKey);

  const helperSecretList: SecretVersionEntry[] = [
    {
      secret_id: secretId,
      versions: [{ version, description: "smoke-test secret" }],
    },
  ];
  const discRespEnvelope = primitives.discovery.response.produce(
    discChannel, helperSecretList, discKey,
  );

  const { response: discResponse } = primitives.discovery.response.extract(
    discRespEnvelope.envelope, discKey,
  );
  const discResult = primitives.discovery.response.process(discResponse);
  if (discResult.secret_list.length === 0) {
    throw new Error("discovery: empty secret_list");
  }
  const entry = discResult.secret_list[0]!;
  if (entry.secret_id !== secretId) {
    throw new Error(`discovery: secret_id mismatch (${entry.secret_id} vs ${secretId})`);
  }
  console.log(`  [response.process] ${discResult.secret_list.length} secret(s) discovered`);

  console.log("✓ Discovery flow passed.\n");

  // ── Recovery ──────────────────────────────────────────────────────────────

  console.log("=== [Primitives] Recovery Flow ===");

  const collectedResponses: GetShareResponseMessage[] = [];
  for (const id of channelIds) {
    const key = keyFor(id);
    const stored = storedShareRequests.get(id);
    if (!stored) throw new Error(`missing stored share for channel ${id}`);

    const reqEnvelope = primitives.recovery.request.produce(id, secretId, version, key);
    const { request } = primitives.recovery.request.extract(reqEnvelope.envelope, key);

    const respEnvelope = primitives.recovery.response.produce(id, request, stored, key);
    const { response } = primitives.recovery.response.extract(respEnvelope.envelope, key);
    collectedResponses.push(response);
  }

  const recovered = primitives.recovery.response.recover(secretId, version, collectedResponses);
  if (recovered.secret_data.length !== secretData.length) {
    throw new Error(`recovery: length mismatch ${recovered.secret_data.length} vs ${secretData.length}`);
  }
  if (!recovered.secret_data.every((b, i) => b === secretData[i])) {
    throw new Error("recovery: bytes do not match original secret");
  }
  console.log(`  [response.recover] recovered ${recovered.secret_data.length}B — matches original ✓`);

  console.log("✓ Recovery flow passed.\n");

  // ── Pairing ───────────────────────────────────────────────────────────────

  console.log("=== [Primitives] Pairing Flow ===");

  const pairingChannelId = 1n;

  // Contact initiator (Owner) creates the out-of-band ContactMessage.
  const contact = primitives.pairing.request.create_contact(
    pairingChannelId,
    { protocol: 0, uri: "https://example.com/alice" },
  );

  // Responder (Helper) produces a pairing request from the contact.
  const pairingRequest = primitives.pairing.request.produce(
    SenderKind.Helper,
    { protocol: 0, uri: "https://example.com/helper" },
    contact.contact_message,
    null,
  );

  // Initiator extracts the request and produces a response.
  const { request: pairRequest }: { request: PairRequestMessage } =
    primitives.pairing.request.extract(pairingRequest.envelope, contact.secret_key);
  const produced = primitives.pairing.response.produce(
    SenderKind.Owner, pairRequest, contact.secret_key, null,
  );

  // Responder extracts the response and processes it.
  const { response: pairResponse }: { response: PairResponseMessage } =
    primitives.pairing.response.extract(produced.envelope, pairingRequest.secret_key);
  const processed = primitives.pairing.response.process(
    pairingRequest.initiator_contact_message as ContactMessage,
    pairResponse,
    pairingRequest.secret_key,
  );

  if (produced.shared_key.length !== processed.shared_key.length ||
      !produced.shared_key.every((b, i) => b === processed.shared_key[i])) {
    throw new Error("pairing: shared keys do not match");
  }
  console.log(`  shared keys match (${produced.shared_key.length}B)  ✓`);

  console.log("✓ Pairing flow passed.\n");

  console.log("━━━ [Primitives] All passed. ━━━\n");
}
