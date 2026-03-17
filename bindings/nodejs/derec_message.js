function asUint8Array(value) {
    return value instanceof Uint8Array ? value : Uint8Array.from(value);
}
export function runDeRecMessageTest(api, message) {
    const parsedMessage = asUint8Array(message);
    // if (!(parsedMessage instanceof Uint8Array)) {
    //   throw new Error("runDeRecMessageTest expected message to be a Uint8Array");
    // }
    if (parsedMessage.length === 0) {
        throw new Error("runDeRecMessageTest expected message to be non-empty");
    }
    const senderHash = new Uint8Array(48).fill(0x11);
    const receiverHash = new Uint8Array(48).fill(0x22);
    const secretId = new Uint8Array([1, 2, 3, 4]);
    const signer = {
        senderKeyHash() {
            return senderHash;
        },
        sign(payload) {
            const prefix = new Uint8Array([9, 9, 9]);
            const out = new Uint8Array(prefix.length + payload.length);
            out.set(prefix, 0);
            out.set(payload, prefix.length);
            return out;
        },
    };
    const verifier = {
        verify(signedPayload) {
            return {
                payload: signedPayload.slice(3),
                signerKeyHash: senderHash,
            };
        },
    };
    const encrypter = {
        recipientKeyId() {
            return 42;
        },
        recipientKeyHash() {
            return receiverHash;
        },
        encrypt(payload) {
            return Uint8Array.from(payload).reverse();
        },
    };
    const decrypter = {
        recipientKeyId() {
            return 42;
        },
        recipientKeyHash() {
            return receiverHash;
        },
        decrypt(payload) {
            return Uint8Array.from(payload).reverse();
        },
    };
    console.log("Building DeRecMessage with owner message length:", parsedMessage.length);
    const derecMessageBytes = api.build_derec_message(senderHash, receiverHash, secretId, [parsedMessage], [], BigInt(Date.now()));
    console.log("DeRecMessage size:", derecMessageBytes.length);
    const wireBytes = api.encode_derec_message(derecMessageBytes, signer, encrypter);
    console.log("Wire message size:", wireBytes.length);
    const decodedMessageBytes = api.decode_derec_message(wireBytes, decrypter, verifier);
    console.log("Decoded message size:", decodedMessageBytes.length);
    const equal = derecMessageBytes.length === decodedMessageBytes.length &&
        derecMessageBytes.every((v, i) => v === decodedMessageBytes[i]);
    console.log("Roundtrip OK:", equal);
}
//# sourceMappingURL=derec_message.js.map