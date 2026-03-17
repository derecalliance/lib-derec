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
  build_derec_message(
    sender: Uint8Array,
    receiver: Uint8Array,
    secretId: Uint8Array,
    ownerMessages: Uint8Array[],
    helperMessages: Uint8Array[],
    timestampSeconds?: bigint | number,
    timestampNanos?: number
  ): Uint8Array;

  encode_derec_message(
    messageBytes: Uint8Array,
    signer: Signer,
    encrypter: Encrypter
  ): Uint8Array;

  decode_derec_message(
    wireBytes: Uint8Array,
    decrypter: Decrypter,
    verifier: Verifier
  ): Uint8Array;
};

export function runDeRecMessageTest(
  api: DeRecMessageApi,
  message: Uint8Array
): void {
  const senderHash = new Uint8Array(48).fill(0x11);
  const receiverHash = new Uint8Array(48).fill(0x22);
  const secretId = new Uint8Array([1, 2, 3, 4]);

  const signer: Signer = {
    senderKeyHash() {
      return senderHash;
    },
    sign(payload: Uint8Array) {
      const prefix = new Uint8Array([9, 9, 9]);
      const out = new Uint8Array(prefix.length + payload.length);
      out.set(prefix, 0);
      out.set(payload, prefix.length);
      return out;
    },
  };

  const verifier: Verifier = {
    verify(signedPayload: Uint8Array) {
      return {
        payload: signedPayload.slice(3),
        signerKeyHash: senderHash,
      };
    },
  };

  const encrypter: Encrypter = {
    recipientKeyId() {
      return 42;
    },
    recipientKeyHash() {
      return receiverHash;
    },
    encrypt(payload: Uint8Array) {
      return Uint8Array.from(payload).reverse();
    },
  };

  const decrypter: Decrypter = {
    recipientKeyId() {
      return 42;
    },
    recipientKeyHash() {
      return receiverHash;
    },
    decrypt(payload: Uint8Array) {
      return Uint8Array.from(payload).reverse();
    },
  };

  const derecMessageBytes = api.build_derec_message(
    senderHash,
    receiverHash,
    secretId,
    [message],
    [],
    BigInt(Date.now())
  );

  console.log("DeRecMessage size:", derecMessageBytes.length);

  const wireBytes = api.encode_derec_message(
    derecMessageBytes,
    signer,
    encrypter
  );

  console.log("Wire message size:", wireBytes.length);

  const decodedMessageBytes = api.decode_derec_message(
    wireBytes,
    decrypter,
    verifier
  );

  console.log("Decoded message size:", decodedMessageBytes.length);

  const equal =
    derecMessageBytes.length === decodedMessageBytes.length &&
    derecMessageBytes.every((v, i) => v === decodedMessageBytes[i]);

  console.log("Roundtrip OK:", equal);
}
