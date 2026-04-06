import init, * as derec from "@derec-alliance/web";

function asBytes(value: unknown): Uint8Array {
    if (value instanceof Uint8Array) {
        return value;
    }

    if (Array.isArray(value)) {
        return Uint8Array.from(value);
    }

    throw new Error(`Expected byte array, got: ${JSON.stringify(value)}`);
}

function extractWireBytes(value: unknown): Uint8Array {
    if (value instanceof Uint8Array || Array.isArray(value)) {
        return asBytes(value);
    }

    if (value && typeof value === "object" && "wire_bytes" in value) {
        return asBytes((value as { wire_bytes: unknown }).wire_bytes);
    }

    throw new Error(`Expected wire bytes or object with wire_bytes, got: ${JSON.stringify(value)}`);
}

function sharedKey(byte: number): Uint8Array {
    return new Uint8Array(32).fill(byte);
}

async function main() {
    await init();

    const secretId = new Uint8Array([1, 2, 3, 4, 255]);
    const secretData = new Uint8Array([5, 6, 7, 8, 255]);
    const channelIds = [1n, 2n, 3n];
    const threshold = 2;
    const version = 1;

    const sharedKeys = new Map<bigint, Uint8Array>();
    sharedKeys.set(1n, sharedKey(1));
    sharedKeys.set(2n, sharedKey(2));
    sharedKeys.set(3n, sharedKey(3));

    // protect_secret now takes a plain array of channel IDs (no shared keys needed).
    const protectSecretResult = derec.protect_secret(
        secretId,
        secretData,
        channelIds,
        threshold,
        version
    );
    console.log("protect_secret:", protectSecretResult);

    // Normalize shares result into a JS Map (channel ID → CommittedDeRecShare bytes)
    const shares = new Map<bigint, Uint8Array>();

    if (protectSecretResult instanceof Map) {
        for (const [k, v] of protectSecretResult.entries()) {
            shares.set(BigInt(k), asBytes(v));
        }
    } else if ((protectSecretResult as any)?.value instanceof Map) {
        for (const [k, v] of (protectSecretResult as any).value.entries()) {
            shares.set(BigInt(k), asBytes(v));
        }
    } else if (Array.isArray(protectSecretResult)) {
        for (const entry of protectSecretResult) {
            if (Array.isArray(entry) && entry.length === 2) {
                shares.set(BigInt(entry[0]), asBytes(entry[1]));
            } else if (entry?.channel_id !== undefined && entry?.share !== undefined) {
                shares.set(BigInt(entry.channel_id), asBytes(entry.share));
            }
        }
    } else if (Array.isArray((protectSecretResult as any)?.value)) {
        for (const entry of (protectSecretResult as any).value) {
            if (Array.isArray(entry) && entry.length === 2) {
                shares.set(BigInt(entry[0]), asBytes(entry[1]));
            } else if (entry?.channel_id !== undefined && entry?.share !== undefined) {
                shares.set(BigInt(entry.channel_id), asBytes(entry.share));
            }
        }
    } else if ((protectSecretResult as any)?.value && typeof (protectSecretResult as any).value === "object") {
        for (const [k, v] of Object.entries((protectSecretResult as any).value)) {
            shares.set(BigInt(k), asBytes(v));
        }
    } else {
        throw new Error(
            `Unexpected protect_secret result shape: ${JSON.stringify(protectSecretResult)}`
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
    }

    // Produce encrypted StoreShareRequestMessage envelopes for each channel.
    const storedShares = new Map<bigint, Uint8Array>();

    for (const [channelId, shareBytes] of shares.entries()) {
        const key = sharedKeys.get(channelId)!;
        const storeResult = derec.produce_store_share_request_message(
            channelId,
            version,
            shareBytes,
            [],
            "",
            key
        );
        const wireBytes = extractWireBytes(storeResult);
        console.log(`store_share_request[${channelId}] wire bytes = ${wireBytes?.length ?? 0}`);
        if (!wireBytes || wireBytes.length === 0) {
            throw new Error(`Sharing failed: empty store share request wire bytes for channel ${channelId}`);
        }
        storedShares.set(channelId, wireBytes);

        // Process the request from the Helper side.
        const processResult = derec.produce_store_share_response_message(channelId, key, wireBytes);
        const responseBytes = extractWireBytes(processResult);
        const committedShareBytes = asBytes((processResult as any).committed_share);
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

    const someSharedKey = sharedKeys.get(someChannel)!;
    const storedWire1 = storedShares.get(someChannel)!;
    const storedWire2 = storedShares.get(otherChannel)!;

    const verificationRequestResult = derec.generate_verification_request(
        secretId,
        someChannel,
        version,
        someSharedKey
    );
    console.log("generate_verification_request:", verificationRequestResult);

    const verificationRequestWireBytes = extractWireBytes(verificationRequestResult);

    const verificationResponseResult = derec.generate_verification_response(
        secretId,
        someChannel,
        someSharedKey,
        storedWire1,
        verificationRequestWireBytes
    );
    console.log("generate_verification_response:", verificationResponseResult);

    const verificationResponseWireBytes = extractWireBytes(verificationResponseResult);

    const verificationExpectedTrue = derec.verify_share_response(
        secretId,
        someChannel,
        someSharedKey,
        storedWire1,
        verificationResponseWireBytes
    );
    console.log("verify_share_response (expected true):", verificationExpectedTrue);

    const verificationExpectedFalse = derec.verify_share_response(
        secretId,
        someChannel,
        someSharedKey,
        storedWire2,
        verificationResponseWireBytes
    );
    console.log("verify_share_response (expected false):", verificationExpectedFalse);

    const shareRequest1Result = derec.generate_share_request(
        1n,
        secretId,
        version,
        sharedKeys.get(1n)!
    );
    console.log("generate_share_request[1]:", shareRequest1Result);

    const shareRequest1WireBytes = extractWireBytes(shareRequest1Result);

    const shareResponse1Result = derec.generate_share_response(
        secretId,
        1n,
        storedShares.get(1n)!,
        shareRequest1WireBytes,
        sharedKeys.get(1n)!
    );
    console.log("generate_share_response[1]:", shareResponse1Result);

    const shareResponse1WireBytes = extractWireBytes(shareResponse1Result);

    const shareRequest2Result = derec.generate_share_request(
        2n,
        secretId,
        version,
        sharedKeys.get(2n)!
    );
    console.log("generate_share_request[2]:", shareRequest2Result);

    const shareRequest2WireBytes = extractWireBytes(shareRequest2Result);

    const shareResponse2Result = derec.generate_share_response(
        secretId,
        2n,
        storedShares.get(2n)!,
        shareRequest2WireBytes,
        sharedKeys.get(2n)!
    );
    console.log("generate_share_response[2]:", shareResponse2Result);

    const shareResponse2WireBytes = extractWireBytes(shareResponse2Result);

    const shareRequest3Result = derec.generate_share_request(
        3n,
        secretId,
        version,
        sharedKeys.get(3n)!
    );
    console.log("generate_share_request[3]:", shareRequest3Result);

    const shareRequest3WireBytes = extractWireBytes(shareRequest3Result);

    const shareResponse3Result = derec.generate_share_response(
        secretId,
        3n,
        storedShares.get(3n)!,
        shareRequest3WireBytes,
        sharedKeys.get(3n)!
    );
    console.log("generate_share_response[3]:", shareResponse3Result);

    const shareResponse3WireBytes = extractWireBytes(shareResponse3Result);

    const recoveryResponses = [
        {
            response_bytes: shareResponse1WireBytes,
            shared_key: sharedKeys.get(1n)!,
        },
        {
            response_bytes: shareResponse2WireBytes,
            shared_key: sharedKeys.get(2n)!,
        },
        {
            response_bytes: shareResponse3WireBytes,
            shared_key: sharedKeys.get(3n)!,
        },
    ];

    try {
        const recovered = derec.recover_from_share_responses(
            recoveryResponses,
            secretId,
            version
        );
        console.log("recover_from_share_responses:", recovered);
    } catch (e) {
        console.error("Error recovering from share responses:", e);
    }

    console.log("--------------------   Pairing Functions   --------------------");

    const channelId = 1n;
    const roleHelper = 2;
    const roleSharer = 0;

    const aliceTransportProtocol = { protocol: "https", uri: "https://example.com/alice" };
    const createContactMessageResult = derec.create_contact_message(
        channelId,
        aliceTransportProtocol
    );
    console.log("create_contact_message:", createContactMessageResult);

    const contactWireBytes = extractWireBytes(
        (createContactMessageResult as any).wire_bytes !== undefined
            ? (createContactMessageResult as any).wire_bytes
            : createContactMessageResult
    );

    const contactSecretKeyMaterial = asBytes(
        (createContactMessageResult as any).secret_key_material
    );

    const producePairingRequestMessageResult = derec.produce_pairing_request_message(
        roleHelper,
        { protocol: "https", uri: "https://example.com/helper" },
        contactWireBytes
    );
    console.log("produce_pairing_request_message:", producePairingRequestMessageResult);

    const pairRequestWireBytes = extractWireBytes(
        (producePairingRequestMessageResult as any).wire_bytes !== undefined
            ? (producePairingRequestMessageResult as any).wire_bytes
            : producePairingRequestMessageResult
    );

    const pairRequestSecretKeyMaterial = asBytes(
        (producePairingRequestMessageResult as any).secret_key_material
    );

    const producePairingResponseMessageResult = derec.produce_pairing_response_message(
        roleSharer,
        pairRequestWireBytes,
        contactSecretKeyMaterial
    );
    console.log("produce_pairing_response_message:", producePairingResponseMessageResult);

    const pairResponseWireBytes = extractWireBytes(
        (producePairingResponseMessageResult as any).wire_bytes !== undefined
            ? (producePairingResponseMessageResult as any).wire_bytes
            : producePairingResponseMessageResult
    );

    const initiatorContactMessage = (producePairingRequestMessageResult as any).initiator_contact_message;

    const processPairingResponseMessageResult = derec.process_pairing_response_message(
        initiatorContactMessage,
        pairResponseWireBytes,
        pairRequestSecretKeyMaterial
    );
    console.log("process_pairing_response_message:", processPairingResponseMessageResult);

    console.log("pairRequestWireBytes:", pairRequestWireBytes);
    console.log("is Uint8Array:", pairRequestWireBytes instanceof Uint8Array);
    console.log("length:", pairRequestWireBytes.length);

    const app = document.getElementById("app");
    if (app) {
        app.textContent = "DeRec web smoke test completed. Check the browser console.";
    }
}

main().catch((error) => {
    console.error("Web smoke test failed:", error);

    const app = document.getElementById("app");
    if (app) {
        app.textContent = `DeRec web smoke test failed: ${String(error)}`;
    }
});
