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
// protect_secret now takes a plain array of channel IDs (no shared keys needed).
const protectSecretResult = derec.protect_secret(secretId, secretData, channelIds, threshold, version);
console.log("protect_secret:", protectSecretResult);
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
}
// Produce encrypted StoreShareRequestMessage envelopes for each channel.
const storedShares = new Map();
for (const [channelId, shareBytes] of shares.entries()) {
    const key = sharedKeys.get(channelId);
    const storeResult = derec.produce_store_share_request_message(channelId, version, shareBytes, [], "", key);
    const wireBytes = storeResult?.wire_bytes ?? storeResult;
    console.log(`store_share_request[${channelId}] wire bytes = ${wireBytes?.length ?? 0}`);
    if (!wireBytes || wireBytes.length === 0) {
        throw new Error(`Sharing failed: empty store share request wire bytes for channel ${channelId}`);
    }
    storedShares.set(channelId, wireBytes);
    // Process the request from the Helper side.
    const processResult = derec.produce_store_share_response_message(channelId, key, wireBytes);
    const responseBytes = processResult?.wire_bytes ?? processResult;
    const committedShareBytes = processResult?.committed_share;
    console.log(`store_share_response[${channelId}] wire bytes = ${responseBytes?.length ?? 0}`);
    console.log(`committed_share[${channelId}] bytes = ${committedShareBytes?.length ?? 0}`);
    if (!responseBytes || responseBytes.length === 0) {
        throw new Error(`Sharing failed: empty response wire bytes for channel ${channelId}`);
    }
    if (!committedShareBytes || committedShareBytes.length === 0) {
        throw new Error(`Sharing failed: empty committed_share bytes for channel ${channelId}`);
    }
    derec.process_store_share_response_message(version, key, responseBytes);
    console.log(`store_share_response validated ok[${channelId}]`);
}
console.log("Sharing flow test passed.");
const someChannel = 1n;
const otherChannel = 2n;
const someSharedKey = sharedKeys.get(someChannel);
const storedWire1 = storedShares.get(someChannel);
const storedWire2 = storedShares.get(otherChannel);
const verificationRequest = derec.generate_verification_request(secretId, someChannel, version, someSharedKey);
console.log("generate_verification_request:", verificationRequest);
const verificationResponse = derec.generate_verification_response(secretId, someChannel, someSharedKey, storedWire1, verificationRequest.wire_bytes);
console.log("generate_verification_response:", verificationResponse);
const verificationExpectedTrue = derec.verify_share_response(secretId, someChannel, someSharedKey, storedWire1, verificationResponse.wire_bytes);
console.log("verify_share_response (expected true):", verificationExpectedTrue);
const verificationExpectedFalse = derec.verify_share_response(secretId, someChannel, someSharedKey, storedWire2, verificationResponse.wire_bytes);
console.log("verify_share_response (expected false):", verificationExpectedFalse);
const shareRequest1 = derec.generate_share_request(1n, secretId, version, sharedKeys.get(1n));
console.log("generate_share_request[1]:", shareRequest1);
const shareResponse1 = derec.generate_share_response(secretId, 1n, storedShares.get(1n), shareRequest1, sharedKeys.get(1n));
console.log("generate_share_response[1]:", shareResponse1);
const shareRequest2 = derec.generate_share_request(2n, secretId, version, sharedKeys.get(2n));
console.log("generate_share_request[2]:", shareRequest2);
const shareResponse2 = derec.generate_share_response(secretId, 2n, storedShares.get(2n), shareRequest2, sharedKeys.get(2n));
console.log("generate_share_response[2]:", shareResponse2);
const shareRequest3 = derec.generate_share_request(3n, secretId, version, sharedKeys.get(3n));
console.log("generate_share_request[3]:", shareRequest3);
const shareResponse3 = derec.generate_share_response(secretId, 3n, storedShares.get(3n), shareRequest3, sharedKeys.get(3n));
console.log("generate_share_response[3]:", shareResponse3);
const recoveryResponses = [
    {
        response_bytes: shareResponse1,
        shared_key: sharedKeys.get(1n),
    },
    {
        response_bytes: shareResponse2,
        shared_key: sharedKeys.get(2n),
    },
    {
        response_bytes: shareResponse3,
        shared_key: sharedKeys.get(3n),
    },
];
try {
    const recovered = derec.recover_from_share_responses(recoveryResponses, secretId, version);
    console.log("recover_from_share_responses:", recovered);
}
catch (e) {
    console.error("Error recovering from share responses:", e);
}
console.log("--------------------   Pairing Functions   --------------------");
const channelId = 1n;
const roleHelper = 2;
const roleSharer = 0;
const aliceTransportProtocol = { protocol: "https", uri: "https://example.com/alice" };
const createContactMessageResult = derec.create_contact_message(channelId, aliceTransportProtocol);
console.log("create_contact_message:", createContactMessageResult);
const producePairingRequestMessageResult = derec.produce_pairing_request_message(roleHelper, { protocol: "https", uri: "https://example.com/helper" }, createContactMessageResult.wire_bytes);
console.log("produce_pairing_request_message:", producePairingRequestMessageResult);
const producePairingResponseMessageResult = derec.produce_pairing_response_message(roleSharer, producePairingRequestMessageResult.wire_bytes, createContactMessageResult.secret_key_material);
console.log("produce_pairing_response_message:", producePairingResponseMessageResult);
const processPairingResponseMessageResult = derec.process_pairing_response_message(producePairingRequestMessageResult.initiator_contact_message, producePairingResponseMessageResult.wire_bytes, producePairingRequestMessageResult.secret_key_material);
console.log("process_pairing_response_message:", processPairingResponseMessageResult);
const validOwnerMessage = producePairingRequestMessageResult.wire_bytes;
console.log("pairRequestWireBytes:", validOwnerMessage);
console.log("is Uint8Array:", validOwnerMessage instanceof Uint8Array);
console.log("length:", validOwnerMessage?.length);
//# sourceMappingURL=index.js.map
