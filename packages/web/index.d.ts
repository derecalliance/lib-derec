// SPDX-License-Identifier: Apache-2.0

/** Initializes the WebAssembly module. Must be called before using any primitives function. */
export { default as init } from "./derec_library.js";

// ── Store interfaces ──────────────────────────────────────────────────────────

/** Storage for cryptographic secrets (shared keys and pairing secrets). */
export interface SecretStore {
  /** kind 0 = SharedKey (32 bytes), kind 1 = PairingSecret (serialized). */
  load(channelId: string, kind: 0 | 1): Promise<Uint8Array | null | undefined>;
  save(channelId: string, kind: 0 | 1, value: Uint8Array): Promise<void>;
  remove(channelId: string, kind: 0 | 1): Promise<void>;
}

/** Storage for peer contact messages (protobuf-encoded). */
export interface ContactStore {
  load(channelId: string): Promise<Uint8Array | null | undefined>;
  save(channelId: string, contactBytes: Uint8Array): Promise<void>;
}

/** Storage for secret shares (raw encoded StoreShareRequestMessage bytes). */
export interface ShareStore {
  load(channelId: string, secretId: Uint8Array, version: number): Promise<Uint8Array | null | undefined>;
  save(channelId: string, secretId: Uint8Array, version: number, encoded: Uint8Array): Promise<void>;
  loadChannelsForSecret(secretId: Uint8Array, version: number): Promise<string[]>;
  /** Returns Array of [secretId, versions] tuples. */
  loadSecretsForChannel(channelId: string): Promise<Array<[Uint8Array, number[]]>>;
}

/** Outbound message delivery. */
export interface Transport {
  send(endpoint: { protocol: string; uri: string }, message: Uint8Array): Promise<void>;
}

// ── Sender kind ───────────────────────────────────────────────────────────────

export enum SenderKind {
  OwnerNonRecovery = 0,
  OwnerRecovery = 1,
  Helper = 2,
}

// ── Contact message ──────────────────────────────────────────────────────────

/** Plain JS representation of a protobuf ContactMessage, as returned by `createContact`. */
export interface ContactMessage {
  channel_id: string;
  nonce: string;
  transport_protocol: { uri: string; protocol: string };
  mlkem_encapsulation_key: Uint8Array;
  ecies_public_key: Uint8Array;
}

// ── Event types ───────────────────────────────────────────────────────────────

export type DeRecEvent =
  | { type: "PairingComplete"; channel_id: string; kind: SenderKind }
  | { type: "ShareStored"; channel_id: string; version: number }
  | { type: "ShareConfirmed"; channel_id: string; version: number }
  | { type: "ShareVerified"; channel_id: string; version: number }
  | { type: "SecretsDiscovered"; channel_id: string; secrets: Array<{ secret_id: Uint8Array; versions: Array<{ version: number; description: string }> }> }
  | { type: "RecoveryShareReceived"; channel_id: string; shares_received: number }
  | { type: "RecoveryShareError"; channel_id: string; shares_received: number; error: string }
  | { type: "SecretRecovered"; secret: Uint8Array }
  | { type: "NoOp" };

// ── Higher-level orchestrator ─────────────────────────────────────────────────

/**
 * Higher-level DeRec protocol orchestrator.
 *
 * Wraps all five protocol flows (pairing, sharing, verification, discovery,
 * recovery). The application feeds incoming wire bytes to `process()` and
 * reacts to the returned `DeRecEvent` array.
 *
 * Call `await init()` before constructing this class.
 *
 * # Kind values for `startPairing`
 * - `SenderKind.OwnerNonRecovery` — standard sharing setup
 * - `SenderKind.OwnerRecovery` — recovering a lost secret
 * - `SenderKind.Helper` — accepting a pairing from an Owner
 */
export declare class DeRecProtocol {
  /**
   * @param contactStore  JS object implementing `ContactStore`.
   * @param shareStore    JS object implementing `ShareStore`.
   * @param secretStore   JS object implementing `SecretStore`.
   * @param transport     JS object implementing `Transport`.
   * @param ownTransportUri      URI this node advertises to peers (e.g. `"https://me.example.com/derec"`).
   * @param ownTransportProtocol Protocol string — currently must be `"https"`.
   */
  constructor(
    contactStore: ContactStore,
    shareStore: ShareStore,
    secretStore: SecretStore,
    transport: Transport,
    ownTransportUri: string,
    ownTransportProtocol: string,
  ): DeRecProtocol;

  /** Generate a contact message. Returns a plain JS `ContactMessage` object. */
  createContact(channelId?: bigint | null): Promise<ContactMessage>;

  /**
   * Begin pairing after receiving a peer's contact out-of-band.
   * @param kind    Role this node plays in the pairing handshake.
   * @param contact Plain JS `ContactMessage` object (from `createContact` or decoded from protobuf).
   * @returns The `channel_id` as a `bigint`.
   */
  startPairing(kind: SenderKind, contact: ContactMessage): Promise<bigint>;

  /**
   * Request discovery from a Helper (step 2 of recovery).
   * Call after PairingComplete { kind: 1 } and out-of-band authentication.
   */
  requestDiscovery(channelId: bigint): Promise<void>;

  /** Split a secret and send one share to each of the specified Helpers. */
  protectSecret(
    secretId: Uint8Array,
    secretData: Uint8Array,
    description: string,
    version: number,
    threshold: number,
    helpers: bigint[],
    keepList: number[],
  ): Promise<void>;

  /** Send verification challenges to all Helpers holding a share for (secretId, version). */
  verifyShares(secretId: Uint8Array, version: number): Promise<void>;

  /** Request shares from Helpers to recover a secret. Emits SecretRecovered on success. */
  recoverSecret(secretId: Uint8Array, version: number, helpers: bigint[]): Promise<void>;

  /**
   * Feed any incoming wire bytes to the protocol.
   * Returns an array of `DeRecEvent` objects the application should react to.
   */
  process(message: Uint8Array): Promise<DeRecEvent[]>;
}

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
      produce(kind: SenderKind, transport_protocol: any, contact_message: any): any;
    };
    response: {
      /** Produces a pairing response envelope and derives the initiator-side shared key. */
      produce(kind: SenderKind, pair_request: any, pairing_secret_key_material: Uint8Array): any;
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
  discovery: {
    request: {
      /** Produces a discovery request envelope (Owner side). */
      produce(channel_id: bigint, shared_key: Uint8Array): any;
      /** Decodes and decrypts a discovery request envelope (Helper side). */
      extract(request: any, shared_key: Uint8Array): any;
    };
    response: {
      /**
       * Produces a discovery response envelope (Helper side).
       * `secret_list` is an array of `{ secret_id: Uint8Array, versions: [{ version: number, description: string }] }`.
       */
      produce(channel_id: bigint, secret_list: Array<{ secret_id: Uint8Array; versions: Array<{ version: number; description: string }> }>, shared_key: Uint8Array): any;
      /**
       * Decodes, decrypts, and processes a discovery response (Owner side).
       * Returns an array of `{ secret_id: Uint8Array, versions: [{ version: number, description: string }] }`.
       */
      process(response: any, shared_key: Uint8Array): Array<{ secret_id: Uint8Array; versions: Array<{ version: number; description: string }> }>;
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
