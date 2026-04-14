import * as derec from "@derec-alliance/nodejs";
const secretId = new Uint8Array([1, 2, 3, 4, 255]);
const secretData = new Uint8Array([5, 6, 7, 8, 255]);
const channelIds = [1n, 2n, 3n];
const threshold = 2;
const version = 1;
function sharedKey(byte) {
    return new Uint8Array(32).fill(byte);
}
const sharedKeys = new Map();
sharedKeys.set(1n, sharedKey(1));
sharedKeys.set(2n, sharedKey(2));
sharedKeys.set(3n, sharedKey(3));
// ---- Sharing flow ----
const protectSecretResult = derec.protect_secret(secretId, secretData, channelIds, threshold, version);
// Normalize shares result into a JS Map (channel ID → CommittedDeRecShare bytes)
const shares = new Map();
if (protectSecretResult instanceof Map) {
    for (const [k, v] of protectSecretResult.entries()) {
        shares.set(BigInt(k), v);
    }
}
else if (protectSecretResult?.value instanceof Map) {
    for (const [k, v] of protectSecretResult.value.entries()) {
        shares.set(BigInt(k), v);
    }
}
else if (Array.isArray(protectSecretResult)) {
    for (const entry of protectSecretResult) {
        if (Array.isArray(entry) && entry.length === 2) {
            shares.set(BigInt(entry[0]), entry[1]);
        }
        else if (entry?.channel_id !== undefined && entry?.share !== undefined) {
            shares.set(BigInt(entry.channel_id), entry.share);
        }
    }
}
else if (Array.isArray(protectSecretResult?.value)) {
    for (const entry of protectSecretResult.value) {
        if (Array.isArray(entry) && entry.length === 2) {
            shares.set(BigInt(entry[0]), entry[1]);
        }
        else if (entry?.channel_id !== undefined && entry?.share !== undefined) {
            shares.set(BigInt(entry.channel_id), entry.share);
        }
    }
}
else if (protectSecretResult?.value && typeof protectSecretResult.value === "object") {
    for (const [k, v] of Object.entries(protectSecretResult.value)) {
        shares.set(BigInt(k), v);
    }
}
else {
    throw new Error(`Unexpected protect_secret result shape: ${JSON.stringify(protectSecretResult)}`);
}
if (shares.size !== channelIds.length) {
    throw new Error(`Sharing failed: expected ${channelIds.length} shares but got ${shares.size}`);
}
for (const [channelId, shareBytes] of shares.entries()) {
    console.log(`channel = ${channelId}, committed share bytes = ${shareBytes?.length ?? 0}`);
    if (!shareBytes || shareBytes.length === 0) {
        throw new Error(`Sharing failed: empty CommittedDeRecShare bytes for channel ${channelId}`);
    }
    // Decode CommittedDeRecShare to inspect its contents.
    const decoded = derec.decode_committed_share(shareBytes);
    console.log(`  decoded CommittedDeRecShare[${channelId}]:`);
    console.log(`    de_rec_share.version = ${decoded.de_rec_share?.version}`);
    console.log(`    de_rec_share.secret_id bytes = ${decoded.de_rec_share?.secret_id?.length ?? 0}`);
    console.log(`    de_rec_share.x bytes = ${decoded.de_rec_share?.x?.length ?? 0}`);
    console.log(`    de_rec_share.y bytes = ${decoded.de_rec_share?.y?.length ?? 0}`);
    console.log(`    de_rec_share.encrypted_secret bytes = ${decoded.de_rec_share?.encrypted_secret?.length ?? 0}`);
    console.log(`    commitment bytes = ${decoded.commitment?.length ?? 0}`);
    console.log(`    merkle_path nodes = ${decoded.merkle_path?.length ?? 0}`);
    for (let i = 0; i < (decoded.merkle_path?.length ?? 0); i++) {
        const node = decoded.merkle_path[i];
        console.log(`      merkle_path[${i}] is_left=${node.is_left} hash_bytes=${node.hash?.length ?? 0}`);
    }
}
// Produce encrypted StoreShareRequestMessage envelopes for each channel.
// produce_store_share_request_message now returns a DeRecMessage JS object directly.
const storedEnvelopes = new Map();
for (const [channelId, shareBytes] of shares.entries()) {
    const key = sharedKeys.get(channelId);
    const requestEnvelope = derec.produce_store_share_request_message(channelId, version, shareBytes, [], "", key);
    console.log(`store_share_request[${channelId}] channel_id=${requestEnvelope?.channel_id} message_type=${requestEnvelope?.message_type} sequence=${requestEnvelope?.sequence}`);
    if (!requestEnvelope || !requestEnvelope.channel_id) {
        throw new Error(`Sharing failed: invalid store share request envelope for channel ${channelId}`);
    }
    storedEnvelopes.set(channelId, requestEnvelope);
    // Process the request from the Helper side (takes a DeRecMessage JS object).
    const processResult = derec.produce_store_share_response_message(channelId, key, requestEnvelope);
    const responseEnvelope = processResult?.envelope ?? processResult;
    const committedShareBytes = processResult?.committed_share;
    const secretIdBytes = processResult?.secret_id;
    const responseVersion = processResult?.version;
    console.log(`store_share_response[${channelId}] channel_id=${responseEnvelope?.channel_id} message_type=${responseEnvelope?.message_type} sequence=${responseEnvelope?.sequence}`);
    // Decode the stored CommittedDeRecShare from the response.
    if (committedShareBytes && committedShareBytes.length > 0) {
        const decodedStored = derec.decode_committed_share(committedShareBytes);
        console.log(`  stored CommittedDeRecShare[${channelId}]:`);
        console.log(`    de_rec_share.version = ${decodedStored.de_rec_share?.version}`);
        console.log(`    commitment bytes = ${decodedStored.commitment?.length ?? 0}`);
        console.log(`    merkle_path nodes = ${decodedStored.merkle_path?.length ?? 0}`);
    }
    console.log(`committed_share[${channelId}] bytes = ${committedShareBytes?.length ?? 0}`);
    console.log(`secret_id[${channelId}] bytes = ${secretIdBytes?.length ?? 0}`);
    console.log(`version[${channelId}] = ${responseVersion}`);
    if (!committedShareBytes || committedShareBytes.length === 0) {
        throw new Error(`Sharing failed: empty committed_share bytes for channel ${channelId}`);
    }
    if (!secretIdBytes || secretIdBytes.length === 0) {
        throw new Error(`Sharing failed: empty secret_id bytes for channel ${channelId}`);
    }
    if (responseVersion !== version) {
        throw new Error(`Sharing failed: version mismatch for channel ${channelId}: expected ${version}, got ${responseVersion}`);
    }
    // process_store_share_response_message takes a DeRecMessage JS object.
    derec.process_store_share_response_message(version, key, responseEnvelope);
    console.log(`store_share_response validated ok[${channelId}]`);
}
console.log("Sharing flow test passed.");
// ---- Verification flow ----
const someChannel = 1n;
const otherChannel = 2n;
const someSharedKey = sharedKeys.get(someChannel);
const storedEnvelope1 = storedEnvelopes.get(someChannel);
const storedEnvelope2 = storedEnvelopes.get(otherChannel);
// Owner side: produce the verification request (returns a DeRecMessage JS object).
const verificationRequest = derec.produce_verify_share_request_message(someChannel, secretId, version, someSharedKey);
console.log("produce_verify_share_request_message channel_id:", verificationRequest?.channel_id);
console.log("produce_verify_share_request_message message_type:", verificationRequest?.message_type);
if (!verificationRequest || !verificationRequest.channel_id) {
    throw new Error("Verification failed: invalid request envelope");
}
// Helper side: decode + decrypt the request (takes a DeRecMessage JS object).
const reqResult = derec.extract_verify_share_request(verificationRequest, someSharedKey);
console.log("extract_verify_share_request channel_id:", reqResult.channel_id);
console.log("extract_verify_share_request secret_id bytes:", reqResult.secret_id?.length ?? 0);
console.log("extract_verify_share_request version:", reqResult.version);
console.log("extract_verify_share_request nonce:", reqResult.nonce);
const reqChannelId = BigInt(reqResult.channel_id ?? 0);
const reqSecretId = new Uint8Array(reqResult.secret_id ?? []);
const reqVersion = reqResult.version ?? 0;
const reqNonce = BigInt(reqResult.nonce ?? 0);
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
// Helper side: build the response (takes stored request as a DeRecMessage JS object).
const verificationResponse = derec.produce_verify_share_response_message(someChannel, reqSecretId, reqVersion, reqNonce, someSharedKey, storedEnvelope1);
console.log("produce_verify_share_response_message channel_id:", verificationResponse?.channel_id);
if (!verificationResponse || !verificationResponse.channel_id) {
    throw new Error("Verification failed: invalid response envelope");
}
// Owner side: verify the response (takes DeRecMessage JS objects).
const verificationExpectedTrue = derec.process_verify_share_response_message(verificationResponse, someSharedKey, storedEnvelope1);
console.log("process_verify_share_response_message (expected true):", verificationExpectedTrue);
if (!verificationExpectedTrue) {
    throw new Error("Verification failed: expected true for correct share");
}
const verificationExpectedFalse = derec.process_verify_share_response_message(verificationResponse, someSharedKey, storedEnvelope2);
console.log("process_verify_share_response_message (expected false):", verificationExpectedFalse);
if (verificationExpectedFalse) {
    throw new Error("Verification failed: expected false for wrong share");
}
console.log("Verification flow test passed.");
// ---- Recovery flow ----
// produce_get_share_request_message returns a DeRecMessage JS object.
const shareRequest1 = derec.produce_get_share_request_message(1n, secretId, version, sharedKeys.get(1n));
console.log("produce_get_share_request_message[1] channel_id:", shareRequest1?.channel_id);
// produce_get_share_response_message takes DeRecMessage JS objects and returns one.
const shareResponse1 = derec.produce_get_share_response_message(secretId, 1n, storedEnvelopes.get(1n), shareRequest1, sharedKeys.get(1n));
console.log("produce_get_share_response_message[1] channel_id:", shareResponse1?.channel_id);
const shareRequest2 = derec.produce_get_share_request_message(2n, secretId, version, sharedKeys.get(2n));
console.log("produce_get_share_request_message[2] channel_id:", shareRequest2?.channel_id);
const shareResponse2 = derec.produce_get_share_response_message(secretId, 2n, storedEnvelopes.get(2n), shareRequest2, sharedKeys.get(2n));
console.log("produce_get_share_response_message[2] channel_id:", shareResponse2?.channel_id);
const shareRequest3 = derec.produce_get_share_request_message(3n, secretId, version, sharedKeys.get(3n));
console.log("produce_get_share_request_message[3] channel_id:", shareRequest3?.channel_id);
const shareResponse3 = derec.produce_get_share_response_message(secretId, 3n, storedEnvelopes.get(3n), shareRequest3, sharedKeys.get(3n));
console.log("produce_get_share_response_message[3] channel_id:", shareResponse3?.channel_id);
// recover_from_share_responses takes { response: DeRecMessageJs, shared_key } entries.
const recoveryResponses = [
    {
        response: shareResponse1,
        shared_key: sharedKeys.get(1n),
    },
    {
        response: shareResponse2,
        shared_key: sharedKeys.get(2n),
    },
    {
        response: shareResponse3,
        shared_key: sharedKeys.get(3n),
    },
];
const recovered = derec.recover_from_share_responses(recoveryResponses, secretId, version);
console.log("recover_from_share_responses recovered bytes:", recovered?.length ?? 0);
if (!recovered || recovered.length === 0) {
    throw new Error("Recovery failed: empty recovered secret");
}
if (!recovered.every((b, i) => b === secretData[i])) {
    throw new Error("Recovery failed: recovered secret does not match original");
}
console.log("Recovery flow test passed.");
// ---- Pairing flow ----
console.log("--------------------   Pairing Functions   --------------------");
const channelId = 1n;
const roleHelper = 2;
const roleOwner = 0;
// create_contact_message takes { protocol: string, uri: string } and returns
// { contact_message: ContactMessageJs, secret_key_material: Uint8Array }.
const createContactMessageResult = derec.create_contact_message(channelId, { protocol: "https", uri: "https://example.com/alice" });
console.log("create_contact_message contact_message:", createContactMessageResult?.contact_message);
console.log("create_contact_message secret_key_material bytes:", createContactMessageResult?.secret_key_material?.length ?? 0);
if (!createContactMessageResult?.contact_message) {
    throw new Error("Pairing failed: missing contact_message");
}
if (!createContactMessageResult?.secret_key_material || createContactMessageResult.secret_key_material.length === 0) {
    throw new Error("Pairing failed: empty secret_key_material");
}
// produce_pairing_request_message takes the ContactMessage JS object.
const producePairingRequestMessageResult = derec.produce_pairing_request_message(roleHelper, { protocol: "https", uri: "https://example.com/helper" }, createContactMessageResult.contact_message);
console.log("produce_pairing_request_message:", producePairingRequestMessageResult);
// console.log("produce_pairing_request_message initiator_contact_message:", producePairingRequestMessageResult?.initiator_contact_message);
// console.log("produce_pairing_request_message secret_key_material bytes:", producePairingRequestMessageResult?.secret_key_material?.length ?? 0);
if (!producePairingRequestMessageResult?.envelope) {
    throw new Error("Pairing failed: missing envelope in pairing request result");
}
if (!producePairingRequestMessageResult?.secret_key_material || producePairingRequestMessageResult.secret_key_material.length === 0) {
    throw new Error("Pairing failed: empty secret_key_material in pairing request result");
}
// produce_pairing_response_message takes the DeRecMessage JS object.
const producePairingResponseMessageResult = derec.produce_pairing_response_message(roleOwner, producePairingRequestMessageResult.envelope, createContactMessageResult.secret_key_material);
console.log("produce_pairing_response_message:", producePairingResponseMessageResult);
if (!producePairingResponseMessageResult?.envelope) {
    throw new Error("Pairing failed: missing envelope in pairing response result");
}
if (!producePairingResponseMessageResult?.pairing_shared_key || producePairingResponseMessageResult.pairing_shared_key.length === 0) {
    throw new Error("Pairing failed: empty pairing_shared_key");
}
// process_pairing_response_message takes ContactMessage and DeRecMessage JS objects.
const processPairingResponseMessageResult = derec.process_pairing_response_message(producePairingRequestMessageResult.initiator_contact_message, producePairingResponseMessageResult.envelope, producePairingRequestMessageResult.secret_key_material);
console.log("process_pairing_response_message:", processPairingResponseMessageResult);
if (!processPairingResponseMessageResult?.pairing_shared_key || processPairingResponseMessageResult.pairing_shared_key.length === 0) {
    throw new Error("Pairing failed: empty pairing_shared_key in processed result");
}
const ownerKey = producePairingResponseMessageResult.pairing_shared_key;
const helperKey = processPairingResponseMessageResult.pairing_shared_key;
const keysMatch = ownerKey.length === helperKey.length && ownerKey.every((b, i) => b === helperKey[i]);
console.log("pairing shared keys match:", keysMatch);
if (!keysMatch) {
    throw new Error("Pairing failed: shared keys do not match");
}
console.log("Pairing flow test passed.");
console.log("All Node.js smoke tests passed.");
//# sourceMappingURL=index.js.map