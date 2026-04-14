import { primitives } from "@derec-alliance/nodejs";

const secretId = new Uint8Array([1, 2, 3, 4, 255]);
const secretData = new Uint8Array([5, 6, 7, 8, 255]);
const channelIds = [1n, 2n, 3n];
const threshold = 2;
const version = 1;

function sharedKey(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

const sharedKeys = new Map<bigint, Uint8Array>();
sharedKeys.set(1n, sharedKey(1));
sharedKeys.set(2n, sharedKey(2));
sharedKeys.set(3n, sharedKey(3));

// ---- Sharing flow ----

const splitResult = primitives.sharing.request.split(
  secretId,
  secretData,
  channelIds,
  threshold,
  version
);

// Normalize shares result into a JS Map (channel ID → CommittedDeRecShare bytes)
const shares = new Map<bigint, Uint8Array>();

if (splitResult?.value instanceof Map) {
  for (const [k, v] of splitResult.value.entries()) {
    shares.set(BigInt(k), v);
  }
} else if (Array.isArray(splitResult?.value)) {
  for (const entry of splitResult.value) {
    if (Array.isArray(entry) && entry.length === 2) {
      shares.set(BigInt(entry[0]), entry[1]);
    }
  }
} else if (splitResult?.value && typeof splitResult.value === "object") {
  for (const [k, v] of Object.entries(splitResult.value)) {
    shares.set(BigInt(k), v as Uint8Array);
  }
} else {
  throw new Error(
    `Unexpected split result shape: ${JSON.stringify(splitResult)}`
  );
}

if (shares.size !== channelIds.length) {
  throw new Error(`Sharing failed: expected ${channelIds.length} shares but got ${shares.size}`);
}

for (const [channelId, shareBytes] of shares.entries()) {
  console.log(`channel = ${channelId}, committed share bytes = ${shareBytes?.length ?? 0}`);
  if (!shareBytes || shareBytes.length === 0) {
    throw new Error(`Sharing failed: empty CommittedDeRecShare bytes for channel ${channelId}`);
  }
  const decoded = primitives.sharing.decode_committed_share(shareBytes);
  console.log(`  decoded CommittedDeRecShare[${channelId}]:`);
  console.log(`    de_rec_share.version = ${(decoded as any).de_rec_share?.version}`);
  console.log(`    de_rec_share.secret_id bytes = ${(decoded as any).de_rec_share?.secret_id?.length ?? 0}`);
  console.log(`    de_rec_share.x bytes = ${(decoded as any).de_rec_share?.x?.length ?? 0}`);
  console.log(`    de_rec_share.y bytes = ${(decoded as any).de_rec_share?.y?.length ?? 0}`);
  console.log(`    de_rec_share.encrypted_secret bytes = ${(decoded as any).de_rec_share?.encrypted_secret?.length ?? 0}`);
  console.log(`    commitment bytes = ${(decoded as any).commitment?.length ?? 0}`);
  console.log(`    merkle_path nodes = ${(decoded as any).merkle_path?.length ?? 0}`);
}

// Produce encrypted StoreShareRequestMessage envelopes for each channel.
const storedEnvelopes = new Map<bigint, any>();

for (const [channelId, shareBytes] of shares.entries()) {
  const key = sharedKeys.get(channelId)!;
  const requestEnvelope = primitives.sharing.request.produce(
    channelId,
    version,
    secretId,
    shareBytes,
    [],
    "",
    key
  );
  console.log(`store_share_request[${channelId}] channel_id=${requestEnvelope?.channel_id}`);
  if (!requestEnvelope || !requestEnvelope.channel_id) {
    throw new Error(`Sharing failed: invalid store share request envelope for channel ${channelId}`);
  }
  storedEnvelopes.set(channelId, requestEnvelope);

  // Helper side: produce response
  const processResult = primitives.sharing.response.produce(channelId, key, requestEnvelope);
  const responseEnvelope = processResult?.envelope ?? processResult;
  const committedShareBytes: Uint8Array = processResult?.committed_share;
  const secretIdBytes: Uint8Array = processResult?.secret_id;
  const responseVersion: number = processResult?.version;

  console.log(`store_share_response[${channelId}] channel_id=${responseEnvelope?.channel_id}`);
  if (!committedShareBytes || committedShareBytes.length === 0) {
    throw new Error(`Sharing failed: empty committed_share bytes for channel ${channelId}`);
  }
  if (!secretIdBytes || secretIdBytes.length === 0) {
    throw new Error(`Sharing failed: empty secret_id bytes for channel ${channelId}`);
  }
  if (responseVersion !== version) {
    throw new Error(`Sharing failed: version mismatch for channel ${channelId}: expected ${version}, got ${responseVersion}`);
  }

  // Owner side: validate response
  primitives.sharing.response.process(version, key, responseEnvelope);
  console.log(`store_share_response validated ok[${channelId}]`);
}

console.log("Sharing flow test passed.");

// ---- Verification flow ----

const someChannel = 1n;
const otherChannel = 2n;

const someSharedKey = sharedKeys.get(someChannel)!;
const storedEnvelope1 = storedEnvelopes.get(someChannel)!;
const storedEnvelope2 = storedEnvelopes.get(otherChannel)!;

// Owner side: produce request
const verificationRequest = primitives.verification.request.produce(
  someChannel,
  secretId,
  version,
  someSharedKey
);
console.log("verification_request_produce channel_id:", verificationRequest?.channel_id);
if (!verificationRequest || !verificationRequest.channel_id) {
  throw new Error("Verification failed: invalid request envelope");
}

// Helper side: extract request
const reqResult = primitives.verification.request.extract(
  verificationRequest,
  someSharedKey
);
const reqChannelId: bigint = BigInt((reqResult as any).channel_id ?? 0);
const reqSecretId: Uint8Array = new Uint8Array((reqResult as any).secret_id ?? []);
const reqVersion: number = (reqResult as any).version ?? 0;
const reqNonce: bigint = BigInt((reqResult as any).nonce ?? 0);

if (reqChannelId !== someChannel) {
  throw new Error(`Verification failed: expected channel_id ${someChannel}, got ${reqChannelId}`);
}
if (reqSecretId.length === 0) {
  throw new Error("Verification failed: secret_id is empty");
}
if (reqVersion !== version) {
  throw new Error(`Verification failed: expected version ${version}, got ${reqVersion}`);
}
if (reqNonce === 0n) {
  throw new Error("Verification failed: nonce must not be zero");
}

// Helper side: produce response
const verificationResponse = primitives.verification.response.produce(
  someChannel,
  reqSecretId,
  reqVersion,
  reqNonce,
  someSharedKey,
  storedEnvelope1
);
console.log("verification_response_produce channel_id:", verificationResponse?.channel_id);
if (!verificationResponse || !verificationResponse.channel_id) {
  throw new Error("Verification failed: invalid response envelope");
}

// Owner side: verify correct share → true
const verificationExpectedTrue = primitives.verification.response.process(
  verificationResponse,
  someSharedKey,
  storedEnvelope1
);
console.log("verification_response_process (expected true):", verificationExpectedTrue);
if (!verificationExpectedTrue) {
  throw new Error("Verification failed: expected true for correct share");
}

// Owner side: verify wrong share → false
const verificationExpectedFalse = primitives.verification.response.process(
  verificationResponse,
  someSharedKey,
  storedEnvelope2
);
console.log("verification_response_process (expected false):", verificationExpectedFalse);
if (verificationExpectedFalse) {
  throw new Error("Verification failed: expected false for wrong share");
}

console.log("Verification flow test passed.");

// ---- Recovery flow ----

const shareRequest1 = primitives.recovery.request.produce(1n, secretId, version, sharedKeys.get(1n)!);
console.log("recovery_request_produce[1] channel_id:", shareRequest1?.channel_id);

const shareResponse1 = primitives.recovery.response.produce(
  secretId, 1n, storedEnvelopes.get(1n)!, shareRequest1, sharedKeys.get(1n)!
);
console.log("recovery_response_produce[1] channel_id:", shareResponse1?.channel_id);

const shareRequest2 = primitives.recovery.request.produce(2n, secretId, version, sharedKeys.get(2n)!);
const shareResponse2 = primitives.recovery.response.produce(
  secretId, 2n, storedEnvelopes.get(2n)!, shareRequest2, sharedKeys.get(2n)!
);

const shareRequest3 = primitives.recovery.request.produce(3n, secretId, version, sharedKeys.get(3n)!);
const shareResponse3 = primitives.recovery.response.produce(
  secretId, 3n, storedEnvelopes.get(3n)!, shareRequest3, sharedKeys.get(3n)!
);

const recoveryResponses = [
  { response: shareResponse1, shared_key: sharedKeys.get(1n)! },
  { response: shareResponse2, shared_key: sharedKeys.get(2n)! },
  { response: shareResponse3, shared_key: sharedKeys.get(3n)! },
];

const recovered = primitives.recovery.response.recover(recoveryResponses, secretId, version);
console.log("recovery_response_recover recovered bytes:", recovered?.length ?? 0);

if (!recovered || recovered.length === 0) {
  throw new Error("Recovery failed: empty recovered secret");
}
if (!recovered.every((b: number, i: number) => b === secretData[i])) {
  throw new Error("Recovery failed: recovered secret does not match original");
}

console.log("Recovery flow test passed.");

// ---- Pairing flow ----

console.log("--------------------   Pairing Functions   --------------------");

const channelId = 1n;
const roleHelper = 2;
const roleOwner = 0;

const createContactResult = primitives.pairing.request.create_contact(
  channelId,
  { protocol: "https", uri: "https://example.com/alice" }
);
console.log("pairing_request_create_contact contact_message:", createContactResult?.contact_message);
console.log("pairing_request_create_contact secret_key_material bytes:", createContactResult?.secret_key_material?.length ?? 0);
if (!createContactResult?.contact_message) {
  throw new Error("Pairing failed: missing contact_message");
}
if (!createContactResult?.secret_key_material || createContactResult.secret_key_material.length === 0) {
  throw new Error("Pairing failed: empty secret_key_material");
}

const pairingRequestResult = primitives.pairing.request.produce(
  roleHelper,
  { protocol: "https", uri: "https://example.com/helper" },
  createContactResult.contact_message
);
console.log("pairing_request_produce:", pairingRequestResult);
if (!pairingRequestResult?.envelope) {
  throw new Error("Pairing failed: missing envelope in pairing request result");
}
if (!pairingRequestResult?.secret_key_material || pairingRequestResult.secret_key_material.length === 0) {
  throw new Error("Pairing failed: empty secret_key_material in pairing request result");
}

const pairingResponseResult = primitives.pairing.response.produce(
  roleOwner,
  pairingRequestResult.envelope,
  createContactResult.secret_key_material
);
console.log("pairing_response_produce:", pairingResponseResult);
if (!pairingResponseResult?.envelope) {
  throw new Error("Pairing failed: missing envelope in pairing response result");
}
if (!pairingResponseResult?.pairing_shared_key || pairingResponseResult.pairing_shared_key.length === 0) {
  throw new Error("Pairing failed: empty pairing_shared_key");
}

const pairingProcessResult = primitives.pairing.response.process(
  pairingRequestResult.initiator_contact_message,
  pairingResponseResult.envelope,
  pairingRequestResult.secret_key_material
);
console.log("pairing_response_process:", pairingProcessResult);
if (!pairingProcessResult?.pairing_shared_key || pairingProcessResult.pairing_shared_key.length === 0) {
  throw new Error("Pairing failed: empty pairing_shared_key in processed result");
}

const ownerKey = pairingResponseResult.pairing_shared_key;
const helperKey = pairingProcessResult.pairing_shared_key;
const keysMatch = ownerKey.length === helperKey.length && ownerKey.every((b: number, i: number) => b === helperKey[i]);
console.log("pairing shared keys match:", keysMatch);
if (!keysMatch) {
  throw new Error("Pairing failed: shared keys do not match");
}

console.log("Pairing flow test passed.");
console.log("All Node.js smoke tests passed.");
