// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.
// Primitives smoke tests: exercises every flow using the low-level
// `primitives.*` API (raw message produce / extract / process functions).
// Mirrors the Rust primitive smoke test (`smoke-tests/rust/src/primitives.rs`).
// The chain in each flow is request.produce → request.extract → response.produce
// → response.extract → response.process, matching the current Rust signatures
// one-for-one.

import {
  ContactMode,
  primitives,
  SenderKind,
  type ContactMessage,
  type GetShareResponseMessage,
  type PairRequestMessage,
  type PairResponseMessage,
  type PrePairRequestMessage,
  type PrePairResponseMessage,
  type SecretVersionEntry,
  type StoreShareRequestMessage,
  type WeightedChannel,
} from "@derec-alliance/nodejs";

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


  console.log("=== [Primitives] Sharing Flow ===");

  const channels: WeightedChannel[] = channelIds.map((id) => [id, 1]);

  const { shares } = primitives.sharing.request.split(
    channels,
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
      id, version, secretId, committedShare, 0, "", key,
    );
    console.log(`  [request.produce] channel=${id} envelope=${requestEnvelope.envelope.length}B`);

    // Helper side: extract then produce response.
    const { request } = primitives.sharing.request.extract(
      requestEnvelope.envelope, key,
    );
    if (request.keep_version !== 0) {
      throw new Error(`keep_version mismatch on channel ${id}: ${request.keep_version}`);
    }
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


  console.log("=== [Primitives] Weighted Sharing Flow ===");

  // Channel 12 holds 3 subshares (weight 3); channels 11 and 13 hold
  // one each (unweighted). Threshold 4 means channel 12 alone is one subshare
  // short, but channel 12 + channel 11 reach it exactly (3 + 1 = 4).
  //
  // This package has no protobuf decoder, so the per-channel subshare count
  // is proven structurally — through what `recovery.response.recover` can
  // and cannot reconstruct — rather than by decoding the committed share's
  // `de_rec_share` bytes.
  const weightedChannelIds: bigint[] = [11n, 12n, 13n];
  const weightedThreshold = 4;
  const weightedSecretId = 0x0102_0304_05fen;
  const weightedVersion = 1;
  const weightedSecretData = new Uint8Array([9, 8, 7, 6, 5]);
  const weightedChannels: WeightedChannel[] = [[11n, 1], [12n, 3], [13n, 1]];

  const weightedKeys = new Map<bigint, Uint8Array>();
  for (const id of weightedChannelIds) weightedKeys.set(id, sharedKey(Number(id)));

  const { shares: weightedShares } = primitives.sharing.request.split(
    weightedChannels,
    weightedSecretId,
    weightedVersion,
    weightedSecretData,
    weightedThreshold,
  );
  if (weightedShares.size !== weightedChannelIds.length) {
    throw new Error(
      `Weighted split: expected ${weightedChannelIds.length} shares, got ${weightedShares.size}`,
    );
  }

  const weightedStoredRequests = new Map<bigint, StoreShareRequestMessage>();
  for (const id of weightedChannelIds) {
    const key = weightedKeys.get(id)!;
    const committedShare = weightedShares.get(id)!;
    const requestEnvelope = primitives.sharing.request.produce(
      id, weightedVersion, weightedSecretId, committedShare, 0, "", key,
    );
    const { request } = primitives.sharing.request.extract(requestEnvelope.envelope, key);
    weightedStoredRequests.set(id, request);
  }
  console.log(`  [request.split] weights={channel 12: 3} → ${weightedShares.size} committed shares`);

  const recoverFromWeighted = (ids: bigint[]): Uint8Array => {
    const responses: GetShareResponseMessage[] = [];
    for (const id of ids) {
      const key = weightedKeys.get(id)!;
      const stored = weightedStoredRequests.get(id)!;
      const reqEnvelope = primitives.recovery.request.produce(id, weightedSecretId, weightedVersion, key);
      const { request } = primitives.recovery.request.extract(reqEnvelope.envelope, key);
      const respEnvelope = primitives.recovery.response.produce(id, request, stored, key);
      const { response } = primitives.recovery.response.extract(respEnvelope.envelope, key);
      responses.push(response);
    }
    return primitives.recovery.response.recover(weightedSecretId, weightedVersion, responses).secret_data;
  };

  // Channel 12 alone carries 3 subshares — one short of threshold 4 — so
  // reconstruction must fail.
  let insufficientWeightRejected = false;
  try {
    recoverFromWeighted([12n]);
  } catch (e) {
    const code = String((e as { code: unknown }).code);
    if (code !== "reconstruction_failed") {
      throw new Error(`weighted recovery(channel 12 alone): expected reconstruction_failed, got ${code}`);
    }
    insufficientWeightRejected = true;
  }
  if (!insufficientWeightRejected) {
    throw new Error("weighted recovery: channel 12 alone (3 subshares) must not meet threshold 4");
  }
  console.log("  [recover] channel 12 alone (3 subshares < 4) refused (reconstruction_failed)  ✓");

  // Channel 12 (3 subshares) + channel 11 (1 subshare) reach the threshold exactly.
  const recoveredWeighted = recoverFromWeighted([11n, 12n]);
  if (
    recoveredWeighted.length !== weightedSecretData.length ||
    !recoveredWeighted.every((b, i) => b === weightedSecretData[i])
  ) {
    throw new Error("weighted recovery: reconstructed bytes do not match the original secret");
  }
  console.log("  [recover] channel 11 + channel 12 (1 + 3 = 4 subshares) recovered the secret  ✓");

  console.log("✓ Weighted sharing flow passed.\n");


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
  const valid = primitives.verification.response.process(verifyRequest, verifyResponse, storedFor1.share);
  if (!valid) throw new Error("expected true for matching share");
  const invalid = primitives.verification.response.process(verifyRequest, verifyResponse, storedFor2.share);
  if (invalid) throw new Error("expected false for wrong share");
  console.log(`  [response.process] correct=true wrong=false  ✓`);

  console.log("✓ Verification flow passed.\n");


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


  console.log("=== [Primitives] Pairing Flow (INLINE_KEYS) ===");

  const pairingChannelId = 1n;

  // Contact initiator (Owner) creates the out-of-band ContactMessage. The
  // contact carries the keys inline — no PrePair round-trip is needed.
  const contact = primitives.pairing.request.create_contact(
    pairingChannelId,
    ContactMode.InlineKeys,
    [{ protocol: 0, uri: "https://example.com/alice" }],
  );

  // Responder (Helper) produces a pairing request from the contact.
  const pairingRequest = primitives.pairing.request.produce(
    SenderKind.Helper,
    [{ protocol: 0, uri: "https://example.com/helper" }],
    contact.contact_message,
    null,
    null,
  );

  // Initiator extracts the request and produces a response.
  const { request: pairRequest }: { request: PairRequestMessage } =
    primitives.pairing.request.extract(pairingRequest.envelope, contact.secret_key, null);
  const produced = primitives.pairing.response.produce(
    pairingChannelId, pairRequest, contact.secret_key, null, null,
  );

  // Responder extracts the response and processes it.
  const { response: pairResponse }: { response: PairResponseMessage } =
    primitives.pairing.response.extract(produced.envelope, pairingRequest.secret_key);
  const processed = primitives.pairing.response.process(
    pairingRequest.initiator_contact_message as ContactMessage,
    pairResponse,
    pairingRequest.secret_key,
    null,
  );

  if (produced.shared_key.length !== processed.shared_key.length ||
      !produced.shared_key.every((b, i) => b === processed.shared_key[i])) {
    throw new Error("pairing: shared keys do not match");
  }
  if (produced.channel_id !== processed.channel_id) {
    throw new Error(
      `pairing: rekeyed channel id mismatch (produce=${produced.channel_id} process=${processed.channel_id})`,
    );
  }
  if (produced.channel_id === pairingChannelId) {
    throw new Error("pairing: rekeyed channel id must differ from the pre-rekey id");
  }
  console.log(`  shared keys match (${produced.shared_key.length}B)  ✓`);
  console.log(`  channel id rekeyed: ${pairingChannelId} → ${produced.channel_id}  ✓`);

  // ── Contact codec: the core's one encoder/decoder for the out-of-band bytes
  {
    const wire = primitives.pairing.request.encode_contact(contact.contact_message);
    const decoded = primitives.pairing.request.decode_contact(wire);
    const reencoded = primitives.pairing.request.encode_contact(decoded);
    if (reencoded.length !== wire.length || !reencoded.every((b, i) => b === wire[i])) {
      throw new Error("contact codec: decode → encode must reproduce the core's bytes");
    }
    if (decoded.channel_id !== pairingChannelId || decoded.nonce !== contact.contact_message.nonce) {
      throw new Error("contact codec: decoded contact lost its channel id or nonce");
    }
    console.log("  contact codec round-trips to the core's bytes  ✓");

    const expectCode = (what: string, code: string, f: () => unknown): void => {
      try {
        f();
      } catch (e) {
        const got = String((e as { code: unknown }).code);
        if (got !== code) throw new Error(`${what}: expected ${code}, got ${got}`);
        console.log(`  ${what} refused (${code})  ✓`);
        return;
      }
      throw new Error(`${what}: expected ${code}, nothing was thrown`);
    };
    expectCode("encode_contact(InlineKeys + binding hash)", "invalid_contact_message", () =>
      primitives.pairing.request.encode_contact({
        ...decoded,
        contact_binding_hash: new Uint8Array(48),
      } as ContactMessage),
    );
    expectCode("decode_contact(garbage)", "protobuf_decode", () =>
      primitives.pairing.request.decode_contact(new Uint8Array([0xff, 0xff, 0xff])),
    );

    // ── Parameter-range compatibility is enforced by the primitives
    const shareSize = (min: bigint, max: bigint) => ({
      min_share_size: min,
      max_share_size: max,
      min_time_between_verifications: 0n,
      max_time_between_verifications: 0x7fff_ffff_ffff_ffffn,
      min_time_between_share_updates: 0n,
      max_time_between_share_updates: 0x7fff_ffff_ffff_ffffn,
      min_unresponsive_deletion_timeout: 0n,
      max_unresponsive_deletion_timeout: 0x7fff_ffff_ffff_ffffn,
      min_unresponsive_deactivation_timeout: 0n,
      max_unresponsive_deactivation_timeout: 0x7fff_ffff_ffff_ffffn,
    });
    const creatorRange = shareSize(1_000_000_000n, 5_000_000_000n);
    const scannerRange = shareSize(10_000_000n, 500_000_000n);

    const ranged = primitives.pairing.request.produce(
      SenderKind.Helper,
      [{ protocol: 0, uri: "https://example.com/helper" }],
      contact.contact_message,
      null,
      scannerRange,
    );
    expectCode("request.extract(disjoint range)", "incompatible_parameter_range", () =>
      primitives.pairing.request.extract(ranged.envelope, contact.secret_key, creatorRange),
    );
    const { request: unchecked } =
      primitives.pairing.request.extract(ranged.envelope, contact.secret_key, null);
    expectCode("response.produce(disjoint range)", "incompatible_parameter_range", () =>
      primitives.pairing.response.produce(
        pairingChannelId, unchecked, contact.secret_key, null, creatorRange,
      ),
    );
    const accepted = primitives.pairing.response.produce(
      pairingChannelId, pairRequest, contact.secret_key, null, creatorRange,
    );
    const { response: rangedResponse } =
      primitives.pairing.response.extract(accepted.envelope, pairingRequest.secret_key);
    expectCode("response.process(disjoint range)", "incompatible_parameter_range", () =>
      primitives.pairing.response.process(
        pairingRequest.initiator_contact_message as ContactMessage,
        rangedResponse,
        pairingRequest.secret_key,
        scannerRange,
      ),
    );
  }

  console.log("✓ Pairing flow (INLINE_KEYS) passed.\n");

  // HASHED_KEYS contacts carry only a SHA-384 commitment to the initiator's
  // public keys (small enough for QR), so before pairing can proceed the
  // scanner must fetch the actual keys over the wire via the plaintext
  // `PrePair` round-trip and verify them against the commitment.

  console.log("=== [Primitives] Pairing Flow (HASHED_KEYS + PrePair) ===");

  const hashedKeysChannelId = 2n;

  // Alice creates a HASHED_KEYS contact. The transport MUST be ephemeral
  // because the PrePair messages cross the wire as plaintext.
  const hkContact = primitives.pairing.request.create_contact(
    hashedKeysChannelId,
    ContactMode.HashedKeys,
    [{ protocol: 0, uri: "https://example.com/alice/ephemeral" }],
  );

  if (hkContact.contact_message.contact_mode !== ContactMode.HashedKeys) {
    throw new Error("HASHED_KEYS contact must advertise contact_mode = HashedKeys");
  }
  if (hkContact.contact_message.mlkem_encapsulation_key !== undefined) {
    throw new Error("HASHED_KEYS contact must NOT carry the ML-KEM key inline");
  }
  if (hkContact.contact_message.ecies_public_key !== undefined) {
    throw new Error("HASHED_KEYS contact must NOT carry the ECIES key inline");
  }
  const bindingHash = hkContact.contact_message.contact_binding_hash;
  if (!bindingHash || bindingHash.length !== 48) {
    throw new Error("HASHED_KEYS contact must carry a 48-byte SHA-384 binding hash");
  }
  console.log(`  contact carries 48-byte binding hash, no inline keys  ✓`);


  // Bob (the scanner) sends a plaintext PrePair request asking for the keys.
  const prePairRequestEnvelope = primitives.pairing.request.produce_pre_pair(
    [{ protocol: 0, uri: "https://example.com/helper/ephemeral" }],
    hkContact.contact_message,
  );

  // Alice decodes the inbound plaintext request.
  const { request: prePairReq }: { request: PrePairRequestMessage } =
    primitives.pairing.request.extract_pre_pair(prePairRequestEnvelope.envelope);
  if (prePairReq.nonce !== hkContact.contact_message.nonce) {
    throw new Error("PrePair request must echo the contact's nonce");
  }

  // Alice publishes the public keys back to Bob.
  const prePairResponseEnvelope = primitives.pairing.response.produce_pre_pair(
    hashedKeysChannelId, prePairReq, hkContact.secret_key,
  );

  // Bob decodes the inbound plaintext response.
  const { response: prePairResp }: { response: PrePairResponseMessage } =
    primitives.pairing.response.extract_pre_pair(prePairResponseEnvelope.envelope);

  // Bob recomputes the SHA-384 binding hash and validates it against the
  // commitment from the original contact. Any tampering on the plaintext
  // PrePair leg surfaces here.
  const validated = primitives.pairing.response.process_pre_pair(
    hkContact.contact_message, prePairResp,
  );
  console.log(`  PrePair validated (mlkem=${validated.mlkem_encapsulation_key.length}B, ecies=${validated.ecies_public_key.length}B, nonce echoed)  ✓`);


  // Bob synthesizes a "filled-in" contact by copying the validated keys
  // into a clone of the HASHED_KEYS contact, then flips contact_mode to
  // InlineKeys and drops the binding hash. `produce` enforces the
  // InlineKeys invariant, so this rewrite is required — it mirrors the
  // protocol orchestrator's `on_pre_pair_response` logic.
  const { contact_binding_hash: _omitBindingHash, ...hkContactBase } =
    hkContact.contact_message;
  const filledInContact: ContactMessage = {
    ...hkContactBase,
    contact_mode: ContactMode.InlineKeys,
    mlkem_encapsulation_key: validated.mlkem_encapsulation_key,
    ecies_public_key: validated.ecies_public_key,
    fingerprint_commitment: validated.fingerprint_commitment,
  };

  const hkPairingRequest = primitives.pairing.request.produce(
    SenderKind.Helper,
    [{ protocol: 0, uri: "https://example.com/helper" }],
    filledInContact,
    null,
    null,
  );
  const { request: hkPairRequest }: { request: PairRequestMessage } =
    primitives.pairing.request.extract(hkPairingRequest.envelope, hkContact.secret_key, null);
  const hkProduced = primitives.pairing.response.produce(
    hashedKeysChannelId, hkPairRequest, hkContact.secret_key, null, null,
  );
  const { response: hkPairResponse }: { response: PairResponseMessage } =
    primitives.pairing.response.extract(hkProduced.envelope, hkPairingRequest.secret_key);
  const hkProcessed = primitives.pairing.response.process(
    hkPairingRequest.initiator_contact_message as ContactMessage,
    hkPairResponse,
    hkPairingRequest.secret_key,
    null,
  );
  if (hkProduced.shared_key.length !== hkProcessed.shared_key.length ||
      !hkProduced.shared_key.every((b, i) => b === hkProcessed.shared_key[i])) {
    throw new Error("HASHED_KEYS pairing: shared keys do not match");
  }
  if (hkProduced.channel_id !== hkProcessed.channel_id) {
    throw new Error(
      `HASHED_KEYS pairing: rekeyed channel id mismatch (produce=${hkProduced.channel_id} process=${hkProcessed.channel_id})`,
    );
  }
  if (hkProduced.channel_id === hashedKeysChannelId) {
    throw new Error("HASHED_KEYS pairing: rekeyed channel id must differ from the pre-rekey id");
  }
  console.log(`  shared keys match (${hkProduced.shared_key.length}B)  ✓`);
  console.log(`  channel id rekeyed: ${hashedKeysChannelId} → ${hkProduced.channel_id}  ✓`);

  console.log("✓ Pairing flow (HASHED_KEYS + PrePair) passed.\n");

  // NO_KEYS contacts carry neither keys nor a commitment; the nonce is the
  // only correlator, so the application supplies it (typically a short,
  // human-typable value) instead of letting the library draw a random one.

  console.log("=== [Primitives] Contact creation (NO_KEYS + explicit nonce) ===");

  const noKeysChannelId = 3n;
  const noKeysNonce = 424242n;
  const nkContact = primitives.pairing.request.create_contact(
    noKeysChannelId,
    ContactMode.NoKeys,
    [{ protocol: 0, uri: "https://example.com/alice/ephemeral" }],
    noKeysNonce,
  );
  if (nkContact.contact_message.contact_mode !== ContactMode.NoKeys) {
    throw new Error("NO_KEYS contact must advertise contact_mode = NoKeys");
  }
  if (BigInt(nkContact.contact_message.nonce) !== noKeysNonce) {
    throw new Error(
      `NO_KEYS contact must carry the caller's nonce (expected ${noKeysNonce}, got ${nkContact.contact_message.nonce})`,
    );
  }
  console.log(`  contact carries the caller-supplied nonce ${noKeysNonce}  ✓`);

  console.log("✓ Contact creation (NO_KEYS + explicit nonce) passed.\n");

  // NO_KEYS pairing: the contact creator generates key material only when the
  // PrePair request arrives, and the scanner accepts the published keys with
  // no commitment to check them against. The nonce is the only thing that
  // authenticates the request, and the pairing is confirmed by comparing the
  // shared key's fingerprint out of band.

  console.log("=== [Primitives] Pairing Flow (NO_KEYS + PrePair + fingerprint) ===");

  // Bob (the scanner) asks for keys the contact does not carry.
  const nkPrePairRequestEnvelope = primitives.pairing.request.produce_pre_pair(
    [{ protocol: 0, uri: "https://example.com/helper/ephemeral" }],
    nkContact.contact_message,
  );

  // Alice decodes the request and MUST match its nonce against the contact
  // she issued before answering.
  const { request: nkPrePairReq }: { request: PrePairRequestMessage } =
    primitives.pairing.request.extract_pre_pair(nkPrePairRequestEnvelope.envelope);
  if (BigInt(nkPrePairReq.nonce) !== BigInt(nkContact.contact_message.nonce)) {
    throw new Error("NO_KEYS PrePair request must echo the contact's nonce");
  }

  // Alice generates this pairing's key material now; she MUST persist it,
  // because the pair request that follows is encrypted to it.
  const nkPrePairResponseEnvelope = primitives.pairing.response.produce_pre_pair_no_keys(
    noKeysChannelId, nkPrePairReq,
  );
  if (nkPrePairResponseEnvelope.secret_key_material.length === 0) {
    throw new Error("NO_KEYS PrePair response must return secret key material");
  }

  // Bob decodes the response and accepts the published keys.
  const { response: nkPrePairResp }: { response: PrePairResponseMessage } =
    primitives.pairing.response.extract_pre_pair(nkPrePairResponseEnvelope.envelope);
  const nkAccepted = primitives.pairing.response.process_pre_pair_no_keys(
    nkContact.contact_message, nkPrePairResp,
  );
  if (BigInt(nkAccepted.nonce) !== noKeysNonce) {
    throw new Error("NO_KEYS PrePair response must echo the contact's nonce");
  }
  console.log(`  PrePair accepted (mlkem=${nkAccepted.mlkem_encapsulation_key.length}B, ecies=${nkAccepted.ecies_public_key.length}B, nonce echoed)  ✓`);

  // Same filled-in contact rewrite as HASHED_KEYS: copy the accepted keys
  // into the contact and flip it to InlineKeys.
  const { contact_binding_hash: _nkOmitBindingHash, ...nkContactBase } =
    nkContact.contact_message;
  const nkFilledInContact: ContactMessage = {
    ...nkContactBase,
    contact_mode: ContactMode.InlineKeys,
    mlkem_encapsulation_key: nkAccepted.mlkem_encapsulation_key,
    ecies_public_key: nkAccepted.ecies_public_key,
    fingerprint_commitment: nkAccepted.fingerprint_commitment,
  };

  const nkPairingRequest = primitives.pairing.request.produce(
    SenderKind.Helper,
    [{ protocol: 0, uri: "https://example.com/helper" }],
    nkFilledInContact,
    null,
    null,
  );
  const { request: nkPairRequest }: { request: PairRequestMessage } =
    primitives.pairing.request.extract(
      nkPairingRequest.envelope, nkPrePairResponseEnvelope.secret_key_material,
      null,
    );
  const nkProduced = primitives.pairing.response.produce(
    noKeysChannelId, nkPairRequest, nkPrePairResponseEnvelope.secret_key_material, null, null,
  );
  const { response: nkPairResponse }: { response: PairResponseMessage } =
    primitives.pairing.response.extract(nkProduced.envelope, nkPairingRequest.secret_key);
  const nkProcessed = primitives.pairing.response.process(
    nkPairingRequest.initiator_contact_message as ContactMessage,
    nkPairResponse,
    nkPairingRequest.secret_key,
    null,
  );
  if (nkProduced.shared_key.length !== nkProcessed.shared_key.length ||
      !nkProduced.shared_key.every((b, i) => b === nkProcessed.shared_key[i])) {
    throw new Error("NO_KEYS pairing: shared keys do not match");
  }
  if (nkProduced.channel_id !== nkProcessed.channel_id) {
    throw new Error(
      `NO_KEYS pairing: rekeyed channel id mismatch (produce=${nkProduced.channel_id} process=${nkProcessed.channel_id})`,
    );
  }
  console.log(`  shared keys match (${nkProduced.shared_key.length}B)  ✓`);

  // Both sides MUST compare this out of band before using the channel.
  const creatorFingerprint = primitives.pairing.fingerprint(nkProduced.shared_key);
  const scannerFingerprint = primitives.pairing.fingerprint(nkProcessed.shared_key);
  if (creatorFingerprint.length === 0 || creatorFingerprint !== scannerFingerprint) {
    throw new Error(
      `NO_KEYS pairing: fingerprints must be equal and non-empty (creator=${creatorFingerprint} scanner=${scannerFingerprint})`,
    );
  }
  console.log(`  fingerprints match (${creatorFingerprint})  ✓`);

  let shortKeyRefused = false;
  try {
    primitives.pairing.fingerprint(new Uint8Array(31));
  } catch {
    shortKeyRefused = true;
  }
  if (!shortKeyRefused) {
    throw new Error("fingerprint must refuse a 31-byte key");
  }
  console.log(`  31-byte key refused  ✓`);

  console.log("✓ Pairing flow (NO_KEYS + PrePair + fingerprint) passed.\n");

  // Every contact mode commits to a fingerprint nonce before the scanner
  // contributes its keys: an InlineKeys contact carries the commitment, a
  // HashedKeys or NoKeys PrePair response carries it with the keys, and the
  // accepted PairResponse reveals the nonce. The channel key mixes the nonce
  // in, so a nonce that does not open the commitment is refused.
  {
    const sameBytes = (a: Uint8Array, b: Uint8Array): boolean =>
      a.length === b.length && a.every((x, i) => x === b[i]);
    const expectPairingError = (what: string, code: string, f: () => unknown): void => {
      try {
        f();
      } catch (e) {
        const { category, code: got } = e as { category?: string; code?: string };
        if (category !== "pairing" || got !== code) {
          throw new Error(`${what}: expected pairing/${code}, got ${category}/${got}`);
        }
        console.log(`  ${what} refused (pairing/${code})  ✓`);
        return;
      }
      throw new Error(`${what}: expected pairing/${code}, nothing was thrown`);
    };

    // An InlineKeys handshake up to the scanner holding the decoded pair
    // response.
    const inlineKeysHandshake = () => {
      const fpChannelId = 31n;
      const fpContact = primitives.pairing.request.create_contact(
        fpChannelId,
        ContactMode.InlineKeys,
        [{ protocol: 0, uri: "https://example.com/alice" }],
      );
      const fpPairingRequest = primitives.pairing.request.produce(
        SenderKind.Helper,
        [{ protocol: 0, uri: "https://example.com/helper" }],
        fpContact.contact_message,
        null,
        null,
      );
      const { request: fpRequest } = primitives.pairing.request.extract(
        fpPairingRequest.envelope, fpContact.secret_key, null,
      );
      const fpProduced = primitives.pairing.response.produce(
        fpChannelId, fpRequest, fpContact.secret_key, null, null,
      );
      const { response: fpResponse } = primitives.pairing.response.extract(
        fpProduced.envelope, fpPairingRequest.secret_key,
      );
      return {
        contact: fpPairingRequest.initiator_contact_message as ContactMessage,
        response: fpResponse,
        scannerSecret: fpPairingRequest.secret_key,
        creatorKey: fpProduced.shared_key,
      };
    };

    // A NoKeys contact, a PrePair request for it, and the creator's answer.
    const noKeysPrePairAnswer = () => {
      const nkFpContact = primitives.pairing.request.create_contact(
        32n,
        ContactMode.NoKeys,
        [{ protocol: 0, uri: "https://example.com/alice/ephemeral" }],
        4321n,
      ).contact_message;
      const { request: nkFpRequest } = primitives.pairing.request.extract_pre_pair(
        primitives.pairing.request.produce_pre_pair(
          [{ protocol: 0, uri: "https://example.com/helper/ephemeral" }],
          nkFpContact,
        ).envelope,
      );
      const answer = primitives.pairing.response.produce_pre_pair_no_keys(32n, nkFpRequest);
      const { response: nkFpResponse } =
        primitives.pairing.response.extract_pre_pair(answer.envelope);
      return { contact: nkFpContact, request: nkFpRequest, response: nkFpResponse };
    };

    console.log("=== [Primitives] Fingerprint nonce opens the creator's commitment ===");
    {
      const { contact: fpContact, response, scannerSecret, creatorKey } = inlineKeysHandshake();
      if (fpContact.fingerprint_commitment?.length !== 32) {
        throw new Error("an InlineKeys contact must carry a 32-byte fingerprint commitment");
      }
      if (response.fingerprint_nonce?.length !== 32) {
        throw new Error("an accepted pair response must reveal a 32-byte fingerprint nonce");
      }
      console.log("  contact commits, pair response reveals a 32-byte nonce  ✓");
      const fpProcessed = primitives.pairing.response.process(
        fpContact, response, scannerSecret, null,
      );
      if (!sameBytes(fpProcessed.shared_key, creatorKey)) {
        throw new Error("fingerprint nonce: both sides must derive the same channel key");
      }
      const creatorFp = primitives.pairing.fingerprint(creatorKey);
      const scannerFp = primitives.pairing.fingerprint(fpProcessed.shared_key);
      if (creatorFp !== scannerFp) {
        throw new Error(`fingerprint nonce: fingerprints differ (creator=${creatorFp} scanner=${scannerFp})`);
      }
      console.log(`  shared keys and fingerprints match (${creatorFp})  ✓`);
    }
    console.log("✓ Fingerprint nonce opens the creator's commitment passed.\n");

    console.log("=== [Primitives] Tampered fingerprint nonce is refused ===");
    {
      const { contact: fpContact, response, scannerSecret } = inlineKeysHandshake();
      const tampered = Uint8Array.from(response.fingerprint_nonce!);
      tampered[0] = tampered[0]! ^ 1;
      expectPairingError("response.process(tampered fingerprint nonce)", "fingerprint_commitment_mismatch", () =>
        primitives.pairing.response.process(
          fpContact, { ...response, fingerprint_nonce: tampered }, scannerSecret, null,
        ),
      );
    }
    console.log("✓ Tampered fingerprint nonce is refused passed.\n");

    console.log("=== [Primitives] PrePair response without a fingerprint commitment is refused ===");
    {
      const hkFpContact = primitives.pairing.request.create_contact(
        33n,
        ContactMode.HashedKeys,
        [{ protocol: 0, uri: "https://example.com/alice/ephemeral" }],
      );
      const { request: hkFpRequest } = primitives.pairing.request.extract_pre_pair(
        primitives.pairing.request.produce_pre_pair(
          [{ protocol: 0, uri: "https://example.com/helper/ephemeral" }],
          hkFpContact.contact_message,
        ).envelope,
      );
      const { response: hkFpResponse } = primitives.pairing.response.extract_pre_pair(
        primitives.pairing.response.produce_pre_pair(
          33n, hkFpRequest, hkFpContact.secret_key,
        ).envelope,
      );
      if (hkFpResponse.fingerprint_commitment?.length !== 32) {
        throw new Error("a HASHED_KEYS PrePair response must carry a 32-byte fingerprint commitment");
      }
      const { fingerprint_commitment: _hkOmitCommitment, ...hkUncommitted } = hkFpResponse;
      expectPairingError("process_pre_pair(no commitment)", "invalid_pair_response_message", () =>
        primitives.pairing.response.process_pre_pair(hkFpContact.contact_message, hkUncommitted),
      );

      const { contact: nkFpContact, response: nkFpResponse } = noKeysPrePairAnswer();
      if (nkFpResponse.fingerprint_commitment?.length !== 32) {
        throw new Error("a NO_KEYS PrePair response must carry a 32-byte fingerprint commitment");
      }
      const { fingerprint_commitment: _nkOmitCommitment, ...nkUncommitted } = nkFpResponse;
      expectPairingError("process_pre_pair_no_keys(no commitment)", "invalid_pair_response_message", () =>
        primitives.pairing.response.process_pre_pair_no_keys(nkFpContact, nkUncommitted),
      );
    }
    console.log("✓ PrePair response without a fingerprint commitment is refused passed.\n");

    // A relay on the NoKeys PrePair leg answers with its own keys and copies
    // the creator's commitment, the only one it has seen. That commitment
    // covers the creator's keys and opens only with the creator's nonce, so
    // the relay's own nonce cannot open it.
    console.log("=== [Primitives] Relay reusing the creator's commitment is refused ===");
    {
      const { contact: nkFpContact, request: nkFpRequest, response: creatorAnswer } =
        noKeysPrePairAnswer();
      const relay = primitives.pairing.response.produce_pre_pair_no_keys(32n, nkFpRequest);
      const { response: relayed } = primitives.pairing.response.extract_pre_pair(relay.envelope);
      const creatorCommitment = creatorAnswer.fingerprint_commitment;
      if (!creatorCommitment) {
        throw new Error("the creator's NO_KEYS PrePair response must carry a fingerprint commitment");
      }

      // Nothing binds NoKeys keys to the contact, so the scanner accepts them.
      const relayValidated = primitives.pairing.response.process_pre_pair_no_keys(
        nkFpContact,
        { ...relayed, fingerprint_commitment: creatorCommitment },
      );
      const relayFilledIn: ContactMessage = {
        ...nkFpContact,
        contact_mode: ContactMode.InlineKeys,
        mlkem_encapsulation_key: relayValidated.mlkem_encapsulation_key,
        ecies_public_key: relayValidated.ecies_public_key,
        fingerprint_commitment: relayValidated.fingerprint_commitment,
      };

      const relayPairingRequest = primitives.pairing.request.produce(
        SenderKind.Helper,
        [{ protocol: 0, uri: "https://example.com/helper" }],
        relayFilledIn,
        null,
        null,
      );
      const { request: relayRequest } = primitives.pairing.request.extract(
        relayPairingRequest.envelope, relay.secret_key_material, null,
      );
      const relayProduced = primitives.pairing.response.produce(
        32n, relayRequest, relay.secret_key_material, null, null,
      );
      const { response: relayResponse } = primitives.pairing.response.extract(
        relayProduced.envelope, relayPairingRequest.secret_key,
      );
      expectPairingError("response.process(relay's nonce)", "fingerprint_commitment_mismatch", () =>
        primitives.pairing.response.process(
          relayPairingRequest.initiator_contact_message as ContactMessage,
          relayResponse,
          relayPairingRequest.secret_key,
          null,
        ),
      );
    }
    console.log("✓ Relay reusing the creator's commitment is refused passed.\n");
  }

  console.log("━━━ [Primitives] All passed. ━━━\n");
}
