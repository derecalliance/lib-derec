// SPDX-License-Identifier: Apache-2.0

/** Initializes the WebAssembly module. Must be called before using any primitives function. */
export { default as init } from "./derec_library.js";

export declare const primitives: {
  pairing: {
    request: {
      /** Creates a ContactMessage used to bootstrap pairing. */
      create_contact(channel_id: bigint, transport_protocol: any): any;
      /** Serializes a ContactMessage JS object into raw protobuf bytes. */
      encode_contact(contact_message: any): Uint8Array;
      /** Deserializes a ContactMessage from raw protobuf bytes. */
      decode_contact(bytes: Uint8Array): any;
      /** Produces a pairing request envelope from a contact message. */
      produce(kind: number, transport_protocol: any, contact_message: any): any;
    };
    response: {
      /** Produces a pairing response envelope and derives the initiator-side shared key. */
      produce(kind: number, pair_request: any, pairing_secret_key_material: Uint8Array): any;
      /** Processes a pairing response envelope and derives the responder-side shared key. */
      process(contact_message: any, pair_response: any, pairing_secret_key_material: Uint8Array): any;
    };
  };
  sharing: {
    request: {
      /** Splits a secret into verifiable committed shares, one per helper channel. */
      split(secret_id: Uint8Array, secret_data: Uint8Array, channels: any, threshold: number, version: number): any;
      /** Wraps a committed helper share into an encrypted delivery envelope. */
      produce(channel_id: bigint, version: number, secret_id: Uint8Array, committed_share: Uint8Array, keep_list: any, description: string, shared_key: Uint8Array): any;
    };
    response: {
      /** Processes an incoming sharing request on behalf of a Helper. */
      produce(channel_id: bigint, shared_key: Uint8Array, request: any): any;
      /** Validates a sharing response received from a Helper. */
      process(version: number, shared_key: Uint8Array, response: any): void;
    };
    /** Decodes a serialized CommittedDeRecShare protobuf into a plain JS object. */
    decode_committed_share(bytes: Uint8Array): any;
  };
  verification: {
    request: {
      /** Generates a verification request envelope (Owner side, step 1). */
      produce(channel_id: bigint, secret_id: Uint8Array, version: number, shared_key: Uint8Array): any;
      /** Decodes and decrypts a verification request envelope (Helper side, step 1). */
      extract(request: any, shared_key: Uint8Array): any;
    };
    response: {
      /** Generates a verification response envelope (Helper side, step 2). */
      produce(channel_id: bigint, secret_id: Uint8Array, version: number, nonce: bigint, shared_key: Uint8Array, stored_request: any): any;
      /** Decodes and decrypts a verification response envelope (Owner side, step 2). */
      extract(response: any, shared_key: Uint8Array): any;
      /** Verifies a verification response (Owner side, step 3). */
      process(response: any, shared_key: Uint8Array, stored_request: any): boolean;
    };
  };
  recovery: {
    request: {
      /** Produces a recovery share request envelope. */
      produce(channel_id: bigint, secret_id: Uint8Array, version: number, shared_key: Uint8Array): any;
    };
    response: {
      /** Produces a recovery share response envelope (Helper side). */
      produce(secret_id: Uint8Array, channel_id: bigint, stored_share_request: any, request: any, shared_key: Uint8Array): any;
      /** Recovers the original secret from helper recovery responses (Owner side). */
      recover(responses: any, secret_id: Uint8Array, version: number): Uint8Array;
    };
  };
};
