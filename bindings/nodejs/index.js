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
// protect_secret expects a sequence with explicit channel_id fields
const channels = channelIds.map((channelId) => ({
    channel_id: channelId,
    shared_key: sharedKeys.get(channelId),
}));
const protectSecretResult = derec.protect_secret(secretId, secretData, channels, threshold, version, [], null);
console.log("protect_secret:", protectSecretResult);
// Normalize shares result into a JS Map
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
const someChannel = 1n;
const otherChannel = 2n;
const someShare = shares.get(someChannel);
if (!someShare) {
    throw new Error("missing share for channel 1");
}
const otherShare = shares.get(otherChannel);
if (!otherShare) {
    throw new Error("missing share for channel 2");
}
const someSharedKey = sharedKeys.get(someChannel);
if (!someSharedKey) {
    throw new Error("missing shared key for channel 1");
}
const verificationRequest = derec.generate_verification_request(secretId, someChannel, version, someSharedKey);
console.log("generate_verification_request:", verificationRequest);
const verificationResponse = derec.generate_verification_response(secretId, someChannel, someSharedKey, someShare, verificationRequest.wire_bytes);
console.log("generate_verification_response:", verificationResponse);
const verificationExpectedTrue = derec.verify_share_response(secretId, someChannel, someSharedKey, someShare, verificationResponse.wire_bytes);
console.log("verify_share_response (expected true):", verificationExpectedTrue);
const verificationExpectedFalse = derec.verify_share_response(secretId, someChannel, someSharedKey, otherShare, verificationResponse.wire_bytes);
console.log("verify_share_response (expected false):", verificationExpectedFalse);
const shareRequest1 = derec.generate_share_request(1n, secretId, version, sharedKeys.get(1n));
console.log("generate_share_request[1]:", shareRequest1);
const shareResponse1 = derec.generate_share_response(secretId, 1n, shares.get(1n), shareRequest1, sharedKeys.get(1n));
console.log("generate_share_response[1]:", shareResponse1);
const shareRequest2 = derec.generate_share_request(2n, secretId, version, sharedKeys.get(2n));
console.log("generate_share_request[2]:", shareRequest2);
const shareResponse2 = derec.generate_share_response(secretId, 2n, shares.get(2n), shareRequest2, sharedKeys.get(2n));
console.log("generate_share_response[2]:", shareResponse2);
const shareRequest3 = derec.generate_share_request(3n, secretId, version, sharedKeys.get(3n));
console.log("generate_share_request[3]:", shareRequest3);
const shareResponse3 = derec.generate_share_response(secretId, 3n, shares.get(3n), shareRequest3, sharedKeys.get(3n));
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
const processPairingResponseMessageResult = derec.process_pairing_response_message(createContactMessageResult.wire_bytes, producePairingResponseMessageResult.wire_bytes, producePairingRequestMessageResult.secret_key_material);
console.log("process_pairing_response_message:", processPairingResponseMessageResult);
const validOwnerMessage = producePairingRequestMessageResult.wire_bytes;
console.log("pairRequestWireBytes:", validOwnerMessage);
console.log("is Uint8Array:", validOwnerMessage instanceof Uint8Array);
console.log("length:", validOwnerMessage?.length);
//# sourceMappingURL=index.js.map