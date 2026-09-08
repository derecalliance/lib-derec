// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

import { jsonFromBytes, jsonToBytes } from './codec';
import { getNative } from './native';
import { primitives } from './primitives';
import { FlowKind } from './types';
import type {
  AutoAcceptPolicy,
  ChannelStore,
  ContactMessage,
  ContactMode,
  DeRecEvent,
  DiscoveryParams,
  PairingParams,
  ParameterRange,
  ProtectSecretParams,
  RecoverSecretParams,
  UnpairReplicaParams,
  SecretStore,
  ShareStore,
  StateStore,
  ReplicaDiscoveryParams,
  Target,
  Timeouts,
  Transport,
  UnpairAck,
  UnpairParams,
  UpdateChannelInfoParams,
  UserSecretStore,
  VerifySharesParams,
} from './types';

/** Shape of the `__DeRec` host object as seen from this file: every member is
 *  a plain callable, since the JSI layer exposes host functions this way and
 *  TypeScript has no static knowledge of them (see `primitives.ts`'s `call`
 *  helper, which uses the same escape hatch). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type NativeHost = Record<string, (...args: any[]) => any>;

/**
 * Event fields carrying `Vec<u8>`.
 *
 * `serde_json` writes them as arrays of decimal byte values, while
 * {@link DeRecEvent} declares them `Uint8Array` — the shape
 * `@derec-alliance/nodejs` produces, where `serde-wasm-bindgen` makes the
 * conversion natively. Without the conversion below the declared type is a
 * lie, and the first thing an application does with `ActionRequired.action` is
 * hand it back to `accept()`, where the native layer reads `.buffer` off it
 * and finds nothing.
 *
 * Unlike the message codec in `./messages`, ids are deliberately left alone:
 * every id on an event is declared as a decimal `string`, not a `bigint`.
 */
const EVENT_BYTE_FIELDS = new Set([
  'action',
  'shared_key',
  'committed_share',
  'id',
  'data',
]);

function reviveEventBytes(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(reviveEventBytes);
  }
  if (value === null || typeof value !== 'object') {
    return value;
  }
  const out: Record<string, unknown> = {};
  for (const [key, field] of Object.entries(value as Record<string, unknown>)) {
    out[key] =
      EVENT_BYTE_FIELDS.has(key) && Array.isArray(field)
        ? Uint8Array.from(field as number[])
        : reviveEventBytes(field);
  }
  return out;
}

function decodeEvents(buffer: ArrayBuffer): DeRecEvent[] {
  return reviveEventBytes(jsonFromBytes(buffer)) as DeRecEvent[];
}

/**
 * Maps a transport protocol name to the `derec_proto::Protocol` discriminant.
 * The shared enum fixture every other numeric mapping in this SDK is checked
 * against does not carry this enum (it
 * only covers the Rust-internal serde enums listed under its `"enums"` key);
 * the transport `Protocol` enum lives in `protobufs/transportprotocol.proto`
 * instead, where `HTTPS = 0` and `GRPC = 1` are defined.
 */
export function protocolDiscriminant(protocol: string): number {
  switch (protocol.toLowerCase()) {
    case 'https':
      return 0;
    case 'grpc':
      return 1;
    default:
      throw new Error(`DeRec: unknown transport protocol "${protocol}"`);
  }
}

function encodeTarget(target: Target): unknown {
  if (target === null) {
    return null;
  }
  if (Array.isArray(target)) {
    return target.map((id) => id.toString());
  }
  return target.toString();
}

/**
 * `ProtectSecretParamsJson` (`library/src/interop/ffi/protocol/flow.rs`): every
 * `UserSecret.id`/`.data` byte array travels as a bare JSON array of decimal
 * byte values, matching `UserSecretJson`'s plain `Vec<u8>` fields — no
 * base64, no wrapping.
 *
 * Exported so it can be golden-tested against the shared wire fixture
 * without a native module.
 */
export function buildProtectSecretParams(params: ProtectSecretParams): Record<string, unknown> {
  const out: Record<string, unknown> = {
    secrets: params.secrets.map((secret) => ({
      id: Array.from(secret.id),
      name: secret.name,
      data: Array.from(secret.data),
    })),
  };
  if (params.description !== undefined) {
    out.description = params.description;
  }
  return out;
}

function communicationInfoOrOmit(
  info: Record<string, string> | undefined,
): Record<string, string> | undefined {
  return info !== undefined && Object.keys(info).length > 0 ? info : undefined;
}

/**
 * `RestoreParamsJson` (`library/src/interop/ffi/protocol/handle/flow.rs`). Mirrors
 * `SecretWire`'s own shape: `channel_id`/`replica_id` are the decimal `u64`
 * strings the `SecretRecovered` event already carries, forwarded verbatim;
 * `communication_info` is omitted per-entry (not sent as `{}`) whenever a
 * helper or replica member has none, matching the Go SDK's `omitempty` and
 * the shared golden fixture byte-for-byte; `replicas` is omitted entirely
 * when the recovered secret has no replica group.
 *
 * Exported so it can be golden-tested against the shared wire fixture
 * without a native module.
 */
export function buildRestoreParams(
  recoveredSecret: Extract<DeRecEvent, { type: 'SecretRecovered' }>['secret'],
  version: number,
): Record<string, unknown> {
  const recovered: Record<string, unknown> = {
    helpers: recoveredSecret.helpers.map((helper) => {
      const out: Record<string, unknown> = {
        channel_id: helper.channel_id,
        transports: helper.transports,
        shared_key: Array.from(helper.shared_key),
      };
      const info = communicationInfoOrOmit(helper.communication_info);
      if (info !== undefined) {
        out.communication_info = info;
      }
      return out;
    }),
    secrets: recoveredSecret.secrets.map((secret) => ({
      id: Array.from(secret.id),
      name: secret.name,
      data: Array.from(secret.data),
    })),
  };
  if (recoveredSecret.replicas !== undefined) {
    recovered.replicas = {
      channel_id: recoveredSecret.replicas.channel_id,
      members: recoveredSecret.replicas.members.map((member) => {
        const out: Record<string, unknown> = {
          replica_id: member.replica_id,
          transports: member.transports,
          role: member.role,
        };
        const info = communicationInfoOrOmit(member.communication_info);
        if (info !== undefined) {
          out.communication_info = info;
        }
        return out;
      }),
      shared_key: Array.from(recoveredSecret.replicas.shared_key),
    };
  }
  return { version, recovered_secret: recovered };
}

/**
 * `PairingParamsJson.contact` (`library/src/interop/ffi/protocol/flow.rs`) is a
 * `Vec<u8>` of proto-encoded `ContactMessage` bytes, so the typed contact the
 * caller holds is re-encoded through the library's own codec on the way in.
 * Encoding in Rust also means the contact is structurally validated before
 * the pairing flow ever sees it.
 */
function contactToByteArray(contact: ContactMessage): number[] {
  return Array.from(primitives.pairing.request.encode_contact(contact));
}

function buildStartParams(flowKind: FlowKind, params: unknown): Uint8Array {
  switch (flowKind) {
    case FlowKind.Pairing: {
      const p = params as PairingParams;
      const out: Record<string, unknown> = {
        kind: p.kind,
        contact: contactToByteArray(p.contact),
      };
      if (p.peerCommunicationInfo !== undefined) {
        out.peer_communication_info = p.peerCommunicationInfo;
      }
      return jsonToBytes(out);
    }
    case FlowKind.Discovery: {
      const p = (params ?? {}) as DiscoveryParams;
      const out: Record<string, unknown> = {};
      if (p.target !== undefined) {
        out.target = encodeTarget(p.target);
      }
      return jsonToBytes(out);
    }
    case FlowKind.ProtectSecret:
      return jsonToBytes(buildProtectSecretParams(params as ProtectSecretParams));
    case FlowKind.VerifyShares: {
      const p = params as VerifySharesParams;
      const out: Record<string, unknown> = {
        secret_id: p.secretId.toString(),
        version: p.version,
      };
      if (p.target !== undefined) {
        out.target = encodeTarget(p.target);
      }
      return jsonToBytes(out);
    }
    case FlowKind.RecoverSecret: {
      const p = params as RecoverSecretParams;
      return jsonToBytes({ secret_id: p.secretId.toString(), version: p.version });
    }
    case FlowKind.Unpair: {
      const p = params as UnpairParams;
      const out: Record<string, unknown> = { channel_id: p.channel_id };
      if (p.memo !== undefined) {
        out.memo = p.memo;
      }
      return jsonToBytes(out);
    }
    case FlowKind.UpdateChannelInfo: {
      const p = (params ?? {}) as UpdateChannelInfoParams;
      const out: Record<string, unknown> = {};
      if (p.target !== undefined) {
        out.target = encodeTarget(p.target);
      }
      if (p.communication_info !== undefined) {
        out.communication_info = p.communication_info;
      }
      if (p.own_transports !== undefined && p.own_transports.length > 0) {
        out.own_transports = p.own_transports;
        // The first entry also fills the deprecated singular field so a peer
        // predating `supported_transports` still learns the new address.
        out.transport_protocol = p.own_transports[0];
      } else if (p.transport_protocol !== undefined) {
        out.transport_protocol = p.transport_protocol;
      }
      return jsonToBytes(out);
    }
    case FlowKind.ReplicaDiscovery:
      // No parameters: the group and this device's own version both come
      // from the stores.
      return jsonToBytes({});
    case FlowKind.UnpairReplica: {
      const p = params as UnpairReplicaParams;
      const out: Record<string, unknown> = { replica_id: p.replica_id };
      if (p.memo !== undefined) {
        out.memo = p.memo;
      }
      return jsonToBytes(out);
    }
    default: {
      const exhaustive: never = flowKind;
      throw new Error(`DeRec: unknown FlowKind ${exhaustive as number}`);
    }
  }
}

function toBigInt(id: bigint | number): bigint {
  return typeof id === 'bigint' ? id : BigInt(id);
}

/**
 * Builder for {@link DeRecProtocol}, mirroring `@derec-alliance/nodejs`'s
 * `DeRecProtocolBuilder` method-for-method. The config JSON shape is dictated
 * by the Rust `ProtocolConfig` struct (`library/src/interop/ffi/protocol/handle/mod.rs`);
 * every field here writes exactly the `snake_case` key that struct expects.
 *
 * Every value the caller supplies is forwarded verbatim — defaults, clamping
 * and the meaning of a disabled cleanup policy are library decisions.
 * `threshold`, `keep_versions_count`, `auto_respond_on_failure`,
 * `unpair_ack`, `auto_reply_to` and `auto_accept` are omitted entirely from
 * the emitted config unless their setter was called: `ProtocolConfig` has a
 * `#[serde(default = "...")]` on each of them, reading the same constants
 * `DeRecProtocolBuilder::new` uses, so an absent key resolves to the
 * library's own default rather than one frozen into this shim.
 */
export class DeRecProtocolBuilder {
  private readonly secretIdValue: bigint;
  private config: Record<string, unknown> = {};
  private stores: Record<string, unknown> = {};
  private communicationInfo: Record<string, string> | undefined;

  constructor(secretId: bigint | number) {
    this.secretIdValue = BigInt(secretId);
  }

  withChannelStore(store: ChannelStore): this {
    this.stores.channelStore = store;
    return this;
  }

  withShareStore(store: ShareStore): this {
    this.stores.shareStore = store;
    return this;
  }

  withSecretStore(store: SecretStore): this {
    this.stores.secretStore = store;
    return this;
  }

  withUserSecretStore(store: UserSecretStore): this {
    this.stores.userSecretStore = store;
    return this;
  }

  withStateStore(store: StateStore): this {
    this.stores.stateStore = store;
    return this;
  }

  withTransport(transport: Transport): this {
    this.stores.transport = transport;
    return this;
  }

  /**
   * @deprecated Use {@link withOwnTransports}, which takes the whole
   * preference list — `withOwnTransports([endpoint])` is the direct
   * replacement. Removed at 0.0.5.
   */
  withOwnTransport(endpoint: { uri: string; protocol: string }): this {
    this.config.own_transport_uri = endpoint.uri;
    this.config.own_transport_protocol = protocolDiscriminant(endpoint.protocol);
    return this;
  }

  /**
   * Set every transport endpoint this application serves, in preference
   * order. Written to the config's `own_transports` array, which takes
   * precedence over `own_transport_uri` / `own_transport_protocol` on the
   * Rust side when non-empty — see `ProtocolConfig` in
   * `library/src/interop/ffi/protocol/handle/mod.rs`.
   *
   * The order given is forwarded verbatim: it is not sorted, deduplicated,
   * or reordered here. It is this application's own preference and
   * decides which of a peer's offered endpoints is used. Every listed
   * transport must actually be served, because delivery is push-only —
   * listing an endpoint this application does not serve makes pairing
   * succeed and replies vanish.
   *
   * Supersedes {@link withOwnTransport} for applications serving more
   * than one transport; the single-endpoint setter remains fully
   * supported.
   */
  withOwnTransports(transports: { uri: string; protocol: string }[]): this {
    this.config.own_transports = transports.map((t) => ({
      uri: t.uri,
      protocol: protocolDiscriminant(t.protocol),
    }));
    return this;
  }

  /** Default: 3. */
  withThreshold(threshold: number): this {
    this.config.threshold = threshold;
    return this;
  }

  /** Default: 3. */
  withKeepVersionsCount(count: number): this {
    this.config.keep_versions_count = count;
    return this;
  }

  /**
   * Every field is optional; not calling this at all leaves all four at the
   * library's defaults — `timeouts` is genuinely absent from the JSON in
   * that case, not filled in with a synthesized object. Values are forwarded
   * verbatim; `Timeouts`'s field names already match `TimeoutsConfig`'s
   * `snake_case` keys one for one.
   */
  withTimeouts(timeouts: Timeouts): this {
    this.config.timeouts = { ...timeouts };
    return this;
  }

  /**
   * @deprecated Use {@link withUnsafeConnection}, which names both gated
   * schemes. Removed at 0.1.0. Default: false.
   */
  withUnsafeHttp(allow: boolean): this {
    this.config.unsafe_http = allow;
    return this;
  }

  /**
   * Accept plaintext `http://` and `grpc://` transport endpoints.
   * **Development only.** Default: false. Supersedes
   * {@link withUnsafeHttp}, which names only the HTTP scheme.
   */
  withUnsafeConnection(allow: boolean): this {
    this.config.unsafe_connection = allow;
    return this;
  }

  /**
   * Default: empty. `derec_protocol_new`'s own `communication_info` argument
   * is a pre-encoded `CommunicationInfo` protobuf message, and this SDK has
   * no encoder for that message — the C ABI exposes one only for
   * `ContactMessage`. Hand-rolling one here would be SDK-side protocol logic
   * with no test coverage — exactly what this codebase's "Rust decides, the
   * SDK only marshals" rule forbids. Instead,
   * `build()` constructs the protocol with an empty `communication_info`
   * (a legitimate, always-accepted value — see `decode_communication_info`
   * in `library/src/interop/ffi/protocol/handle/mod.rs`, which treats a zero-length
   * buffer as "no entries") and then calls the already-bound
   * {@link DeRecProtocol.setCommunicationInfo}, which takes the same map as
   * plain JSON (`derec_protocol_set_communication_info` in
   * `library/src/interop/ffi/protocol/handle/config.rs`). That setter is queued on
   * the protocol's serial worker before `build()` returns, so it is ordered
   * ahead of every call the caller can subsequently make.
   */
  withCommunicationInfo(info: Record<string, string>): this {
    this.communicationInfo = info;
    return this;
  }

  /** Default: false. */
  withAutoRespondOnFailure(enabled: boolean): this {
    this.config.auto_respond_on_failure = enabled;
    return this;
  }

  /** Default: "required". */
  withUnpairAck(ack: UnpairAck): this {
    if (ack === 'required') {
      this.config.unpair_ack = 0;
    } else if (ack === 'not_required') {
      this.config.unpair_ack = 1;
    } else {
      throw new Error(`DeRec: unknown unpair ack "${ack as string}"`);
    }
    return this;
  }

  /** Default: false. */
  withAutoReplyTo(enabled: boolean): this {
    this.config.auto_reply_to = enabled;
    return this;
  }

  /** Default: empty policy (every flow off). */
  withAutoAccept(policy: AutoAcceptPolicy): this {
    this.config.auto_accept = {
      pairing: policy.pairing ?? false,
      pre_pair: policy.prePair ?? false,
      store_share: policy.storeShare ?? false,
      verify_share: policy.verifyShare ?? false,
      discovery: policy.discovery ?? false,
      get_share: policy.getShare ?? false,
      unpair: policy.unpair ?? false,
      update_channel_info: policy.updateChannelInfo ?? false,
    };
    return this;
  }

  /** Default: unset. */
  withReplicaId(replicaId: bigint | number): this {
    this.config.replica_id = BigInt(replicaId).toString();
    return this;
  }

  /**
   * Declare the bounds this node advertises during pair negotiation.
   *
   * Embedded in outbound `PairRequest`/`PairResponse` envelopes and checked
   * against the peer's range on inbound ones: a range that fails to
   * intersect rejects the pairing. Every bound is optional and defaults to
   * `0`, which the protocol reads as "no constraint on this dimension".
   *
   * Default: unset — no constraints advertised, every peer range accepted.
   */
  withParameterRange(range: Partial<ParameterRange>): this {
    const n = (v: bigint | undefined) => Number(v ?? 0n);
    this.config.parameter_range = {
      min_share_size: n(range.min_share_size),
      max_share_size: n(range.max_share_size),
      min_time_between_verifications: n(range.min_time_between_verifications),
      max_time_between_verifications: n(range.max_time_between_verifications),
      min_time_between_share_updates: n(range.min_time_between_share_updates),
      max_time_between_share_updates: n(range.max_time_between_share_updates),
      min_unresponsive_deletion_timeout: n(
        range.min_unresponsive_deletion_timeout,
      ),
      max_unresponsive_deletion_timeout: n(
        range.max_unresponsive_deletion_timeout,
      ),
      min_unresponsive_deactivation_timeout: n(
        range.min_unresponsive_deactivation_timeout,
      ),
      max_unresponsive_deactivation_timeout: n(
        range.max_unresponsive_deactivation_timeout,
      ),
    };
    return this;
  }

  build(): DeRecProtocol {
    const config = {
      secret_id: this.secretIdValue.toString(),
      replica_id: null,
      own_transport_uri: '',
      own_transport_protocol: 0,
      ...this.config,
    };
    const host = (getNative() as unknown as NativeHost).protocol_new(
      JSON.stringify(config),
      new Uint8Array(0),
      this.stores,
    ) as NativeHost;
    const protocol = DeRecProtocol.fromHost(host);
    if (this.communicationInfo !== undefined) {
      // `setCommunicationInfo` is asynchronous, but `build()` stays
      // synchronous: the guarantee callers need is not that the map has been
      // applied by the time `build()` returns, it is that no flow can run
      // before it. Posting it here puts it on the protocol's serial worker
      // queue ahead of anything the caller has had the chance to start, so
      // every subsequent call observes it. Left unhandled deliberately — a
      // failure reaches the runtime's unhandled-rejection reporting rather
      // than being silently discarded, and `build()` has no synchronous
      // channel to raise it on.
      void protocol.setCommunicationInfo(this.communicationInfo);
    }
    return protocol;
  }
}

/**
 * Thin wrapper around the `ProtocolHost` JSI host object, mirroring
 * `@derec-alliance/nodejs`'s `DeRecProtocol` — same methods, and the same
 * sync/async split except for `setCommunicationInfo` and `setOwnTransport`,
 * which return a `Promise` here (see their own doc comments for why);
 * `secretId` is synchronous and everything else returns a `Promise`. Every method encodes its
 * arguments into the wire shape the host function expects and decodes its
 * result back into the typed value declared here; no protocol decision is
 * made in this class.
 */
export class DeRecProtocol {
  private readonly host: NativeHost;

  /** Use {@link DeRecProtocolBuilder} to construct instances. */
  private constructor(host: NativeHost) {
    this.host = host;
  }

  /**
   * @internal Constructs an instance from a native `ProtocolHost`. Not part
   * of the public surface — {@link DeRecProtocolBuilder.build} is the only
   * caller. Exists because the constructor is `private` (matching
   * `@derec-alliance/nodejs`'s `index.d.ts`), and a private constructor is
   * only callable from within this class's own body, not from
   * `DeRecProtocolBuilder`.
   */
  static fromHost(host: NativeHost): DeRecProtocol {
    return new DeRecProtocol(host);
  }

  secretId(): bigint {
    return this.host.secretId() as bigint;
  }

  /**
   * Returns a `Promise`, where `@derec-alliance/nodejs` declares this
   * `void`. The native setter takes the same handle mutex a running flow
   * holds across its store callbacks, so calling it on the JavaScript thread
   * would block that thread until the flow released the mutex — which it
   * cannot do while it is waiting on the JavaScript thread. The binding
   * therefore queues the setter onto the same serial worker every flow runs
   * on, which orders it after any call already in flight. The nodejs SDK is
   * WASM and single-threaded, so it has no such hazard.
   *
   * Callers that ignore the result behave exactly as before, so this stays
   * source-compatible with nodejs-shaped code; awaiting it additionally
   * surfaces a failure that would otherwise be swallowed.
   */
  setCommunicationInfo(info: Record<string, string>): Promise<void> {
    return this.host.setCommunicationInfo(jsonToBytes(info)) as Promise<void>;
  }

  /**
   * Replace this node's endpoint for one protocol, leaving the others
   * alone. A node serves at most one endpoint per protocol, so the
   * `(uri, protocol)` pair identifies the entry it replaces; an entry for a
   * protocol not yet served is appended, and a replaced one keeps its
   * position in the preference order.
   *
   * Returns a `Promise` for the same reason {@link setCommunicationInfo} does.
   *
   * @deprecated Use {@link setOwnTransports}, which takes the whole
   * preference list and is the only way to change which protocols this node
   * serves, or their order. Removed at 0.0.5.
   */
  setOwnTransport(uri: string, protocol: string): Promise<void> {
    return this.host.setOwnTransport(
      uri,
      protocolDiscriminant(protocol),
    ) as Promise<void>;
  }

  /**
   * Replaces every endpoint this node advertises, in preference order —
   * the runtime counterpart to `withOwnTransports`, and the only way to
   * change a multi-endpoint node's set ({@link setOwnTransport} collapses
   * it to the one endpoint it is given).
   *
   * Every entry is validated before any is stored, so a malformed URI
   * leaves the previous set intact. An empty array is rejected.
   *
   * Returns a `Promise` for the same reason {@link setCommunicationInfo} does.
   */
  setOwnTransports(
    transports: { uri: string; protocol: string }[],
  ): Promise<void> {
    const wire = transports.map(({ uri, protocol }) => ({
      uri,
      protocol: protocolDiscriminant(protocol),
    }));
    return this.host.setOwnTransports(jsonToBytes(wire)) as Promise<void>;
  }

  /**
   * Decodes the `contact_wire_bytes` `derec_protocol_create_contact`
   * produces into a typed `ContactMessage`, so an application can read the
   * contact's `nonce`, `transport_protocol` and mode without a protobuf
   * codec of its own. Feed the returned object straight back into
   * `start(FlowKind.Pairing, { contact })`, which re-encodes it.
   */
  async createContact(
    channelId: bigint | number | null | undefined,
    contactMode: ContactMode,
    nonce?: bigint | number | null,
  ): Promise<ContactMessage> {
    const hasChannelId = channelId !== null && channelId !== undefined ? 1 : 0;
    const hasNonce = nonce !== null && nonce !== undefined ? 1 : 0;
    const buffer = (await this.host.createContact(
      hasChannelId,
      toBigInt(channelId ?? 0),
      contactMode,
      hasNonce,
      toBigInt(nonce ?? 0),
    )) as ArrayBuffer;
    return primitives.pairing.request.decode_contact(new Uint8Array(buffer));
  }

  start(flowKind: FlowKind.Pairing, params: PairingParams): Promise<DeRecEvent[]>;
  start(flowKind: FlowKind.Discovery, params?: DiscoveryParams): Promise<DeRecEvent[]>;
  start(flowKind: FlowKind.ProtectSecret, params: ProtectSecretParams): Promise<DeRecEvent[]>;
  start(flowKind: FlowKind.VerifyShares, params: VerifySharesParams): Promise<DeRecEvent[]>;
  start(flowKind: FlowKind.RecoverSecret, params: RecoverSecretParams): Promise<DeRecEvent[]>;
  start(flowKind: FlowKind.Unpair, params: UnpairParams): Promise<DeRecEvent[]>;
  start(flowKind: FlowKind.UpdateChannelInfo, params: UpdateChannelInfoParams): Promise<DeRecEvent[]>;
  start(flowKind: FlowKind.ReplicaDiscovery, params?: ReplicaDiscoveryParams): Promise<DeRecEvent[]>;
  start(flowKind: FlowKind.UnpairReplica, params: UnpairReplicaParams): Promise<DeRecEvent[]>;
  async start(flowKind: FlowKind, params?: unknown): Promise<DeRecEvent[]> {
    const paramsBytes = buildStartParams(flowKind, params);
    const buffer = (await this.host.start(flowKind, paramsBytes)) as ArrayBuffer;
    return decodeEvents(buffer);
  }

  async process(message: Uint8Array): Promise<DeRecEvent[]> {
    const buffer = (await this.host.process(message)) as ArrayBuffer;
    return decodeEvents(buffer);
  }

  async tick(): Promise<DeRecEvent[]> {
    const buffer = (await this.host.tick()) as ArrayBuffer;
    return decodeEvents(buffer);
  }

  async accept(actionBytes: Uint8Array): Promise<DeRecEvent[]> {
    const buffer = (await this.host.accept(actionBytes)) as ArrayBuffer;
    return decodeEvents(buffer);
  }

  async reject(actionBytes: Uint8Array, status: number, memo: string): Promise<void> {
    await this.host.reject(actionBytes, status, memo);
  }

  async getFingerprint(channelId: bigint | number): Promise<string> {
    return (await this.host.getFingerprint(toBigInt(channelId))) as string;
  }

  async verifyFingerprint(channelId: bigint | number, fingerprint: string): Promise<boolean> {
    return (await this.host.verifyFingerprint(toBigInt(channelId), fingerprint)) as boolean;
  }

  async removeExpiredChannels(olderThanSecs: number): Promise<string[]> {
    const buffer = (await this.host.removeExpiredChannels(olderThanSecs)) as ArrayBuffer;
    return jsonFromBytes(buffer) as string[];
  }

  async restore(
    recoveredSecret: Extract<DeRecEvent, { type: 'SecretRecovered' }>['secret'],
    version: number,
  ): Promise<DeRecEvent[]> {
    const params = buildRestoreParams(recoveredSecret, version);
    const buffer = (await this.host.restore(jsonToBytes(params))) as ArrayBuffer;
    return decodeEvents(buffer);
  }

  /** Release the native handle. Safe to call more than once. */
  free(): void {
    this.host.free();
  }
}
