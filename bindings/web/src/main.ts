import init, { primitives } from "@derec-alliance/web";

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

    // ---- Sharing flow ----

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
        throw new Error(`Sharing failed: expected ${channelIds.length} shares but got ${shares.size}`);
    }

    for (const [channelId, shareBytes] of shares.entries()) {
        console.log(`channel = ${channelId}, committed share bytes = ${(shareBytes as any)?.length ?? 0}`);
        if (!shareBytes || (shareBytes as any).length === 0) {
            throw new Error(`Sharing failed: empty CommittedDeRecShare bytes for channel ${channelId}`);
        }
    }

    const storedEnvelopes = new Map<bigint, any>();

    for (const [channelId, shareBytes] of shares.entries()) {
        const key = sharedKeys.get(channelId)!;
        const requestEnvelope = primitives.sharing.request.produce(
            channelId,
            version,
            secretId,
            shareBytes as Uint8Array,
            [],
            "",
            key
        );
        console.log(`sharing_request_produce[${channelId}] channel_id=${(requestEnvelope as any)?.channel_id}`);
        if (!(requestEnvelope as any)?.channel_id) {
            throw new Error(`Sharing failed: invalid store share request envelope for channel ${channelId}`);
        }
        storedEnvelopes.set(channelId, requestEnvelope);

        const processResult = primitives.sharing.response.produce(channelId, key, requestEnvelope);
        const responseEnvelope = (processResult as any)?.envelope ?? processResult;
        const committedShareBytes: Uint8Array = (processResult as any)?.committed_share;
        const secretIdBytes: Uint8Array = (processResult as any)?.secret_id;
        const responseVersion: number = (processResult as any)?.version;

        if (!committedShareBytes || committedShareBytes.length === 0) {
            throw new Error(`Sharing failed: empty committed_share bytes for channel ${channelId}`);
        }
        if (!secretIdBytes || secretIdBytes.length === 0) {
            throw new Error(`Sharing failed: empty secret_id bytes for channel ${channelId}`);
        }
        if (responseVersion !== version) {
            throw new Error(`Sharing failed: version mismatch for channel ${channelId}: expected ${version}, got ${responseVersion}`);
        }

        primitives.sharing.response.process(version, key, responseEnvelope);
        console.log(`sharing_response_process validated ok[${channelId}]`);
    }

    console.log("Sharing flow test passed.");

    // ---- Verification flow ----

    const someChannel = 1n;
    const otherChannel = 2n;

    const someSharedKey = sharedKeys.get(someChannel)!;
    const storedEnvelope1 = storedEnvelopes.get(someChannel)!;
    const storedEnvelope2 = storedEnvelopes.get(otherChannel)!;

    const verificationRequest = primitives.verification.request.produce(
        someChannel, secretId, version, someSharedKey
    );
    if (!(verificationRequest as any)?.channel_id) {
        throw new Error("Verification failed: invalid request envelope");
    }

    const reqResult = primitives.verification.request.extract(verificationRequest, someSharedKey);
    const reqChannelId: bigint = BigInt((reqResult as any).channel_id ?? 0);
    const reqSecretId: Uint8Array = new Uint8Array((reqResult as any).secret_id ?? []);
    const reqVersion: number = (reqResult as any).version ?? 0;
    const reqNonce: bigint = BigInt((reqResult as any).nonce ?? 0);

    console.log("verification_request_extract channel_id:", reqChannelId, "nonce:", reqNonce);

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

    const verificationResponse = primitives.verification.response.produce(
        someChannel, reqSecretId, reqVersion, reqNonce, someSharedKey, storedEnvelope1
    );
    if (!(verificationResponse as any)?.channel_id) {
        throw new Error("Verification failed: invalid response envelope");
    }

    const verificationExpectedTrue = primitives.verification.response.process(
        verificationResponse, someSharedKey, storedEnvelope1
    );
    console.log("verification_response_process (expected true):", verificationExpectedTrue);
    if (!verificationExpectedTrue) {
        throw new Error("Verification failed: expected true for correct share");
    }

    const verificationExpectedFalse = primitives.verification.response.process(
        verificationResponse, someSharedKey, storedEnvelope2
    );
    console.log("verification_response_process (expected false):", verificationExpectedFalse);
    if (verificationExpectedFalse) {
        throw new Error("Verification failed: expected false for wrong share");
    }

    console.log("Verification flow test passed.");

    // ---- Recovery flow ----

    const shareRequest1 = primitives.recovery.request.produce(1n, secretId, version, sharedKeys.get(1n)!);
    const shareResponse1 = primitives.recovery.response.produce(
        secretId, 1n, storedEnvelopes.get(1n)!, shareRequest1, sharedKeys.get(1n)!
    );

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
    if (!(createContactResult as any)?.contact_message) {
        throw new Error("Pairing failed: missing contact_message");
    }

    const pairingRequestResult = primitives.pairing.request.produce(
        roleHelper,
        { protocol: "https", uri: "https://example.com/helper" },
        (createContactResult as any).contact_message
    );
    if (!(pairingRequestResult as any)?.envelope) {
        throw new Error("Pairing failed: missing envelope in pairing request result");
    }

    const pairingResponseResult = primitives.pairing.response.produce(
        roleOwner,
        (pairingRequestResult as any).envelope,
        (createContactResult as any).secret_key_material
    );
    if (!(pairingResponseResult as any)?.pairing_shared_key || (pairingResponseResult as any).pairing_shared_key.length === 0) {
        throw new Error("Pairing failed: empty pairing_shared_key");
    }

    const pairingProcessResult = primitives.pairing.response.process(
        (pairingRequestResult as any).initiator_contact_message,
        (pairingResponseResult as any).envelope,
        (pairingRequestResult as any).secret_key_material
    );
    if (!(pairingProcessResult as any)?.pairing_shared_key || (pairingProcessResult as any).pairing_shared_key.length === 0) {
        throw new Error("Pairing failed: empty pairing_shared_key in processed result");
    }

    const ownerKey: Uint8Array = (pairingResponseResult as any).pairing_shared_key;
    const helperKey: Uint8Array = (pairingProcessResult as any).pairing_shared_key;
    const keysMatch = ownerKey.length === helperKey.length && ownerKey.every((b: number, i: number) => b === helperKey[i]);
    console.log("pairing shared keys match:", keysMatch);
    if (!keysMatch) {
        throw new Error("Pairing failed: shared keys do not match");
    }

    console.log("Pairing flow test passed.");
    console.log("All web smoke tests passed.");

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
