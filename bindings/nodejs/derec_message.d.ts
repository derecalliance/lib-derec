export type Signer = {
    senderKeyHash(): Uint8Array;
    sign(payload: Uint8Array): Uint8Array;
};
export type Encrypter = {
    recipientKeyId(): number;
    recipientKeyHash(): Uint8Array;
    encrypt(payload: Uint8Array): Uint8Array;
};
export type Decrypter = {
    recipientKeyId(): number;
    recipientKeyHash(): Uint8Array;
    decrypt(payload: Uint8Array): Uint8Array;
};
export type Verifier = {
    verify(signedPayload: Uint8Array): {
        payload: Uint8Array;
        signerKeyHash: Uint8Array;
    };
};
export type DeRecMessageApi = {
    build_derec_message(sender: Uint8Array, receiver: Uint8Array, secret_id: Uint8Array, owner_messages: any, helper_messages: any, timestamp_seconds?: bigint | null, timestamp_nanos?: number | null): Uint8Array;
    encode_derec_message(message_bytes: Uint8Array, signer: Signer, encrypter: Encrypter): Uint8Array;
    decode_derec_message(wire_bytes: Uint8Array, decrypter: Decrypter, verifier: Verifier): Uint8Array;
};
export declare function runDeRecMessageTest(api: DeRecMessageApi, message: Uint8Array | number[]): void;
//# sourceMappingURL=derec_message.d.ts.map