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
  DeRecProtocolConfig,
  Endpoint,
  DiscoveryParams,
  PairingParams,
  ParameterRange,
  ProtectSecretParams,
  RecoverSecretParams,
  UnpairReplicaParams,
  SecretStore,
  ShareStore,
  StateStore,
  StatusEnum,
  ReplicaDiscoveryParams,
  Target,
  Timeouts,
  Transport,
  UnpairAck,
  UnpairParams,
  UpdateChannelInfoParams,
  UserSecretStore,
  VerifySharesParams,
  StoresInit,
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
  if (params.weights != null && params.weights.size > 0) {
    const weights: Record<string, number> = {};
    for (const [id, weight] of params.weights) {
      weights[id.toString()] = weight;
    }
    out.weights = weights;
  }
  if (params.threshold != null) {
    out.threshold = params.threshold;
  }
  return out;
}

function communicationInfoOrOmit(
  info: Record<string, string> | null | undefined,
): Record<string, string> | undefined {
  return info != null && Object.keys(info).length > 0 ? info : undefined;
}

/**
 * `RestoreParamsJson` (`library/src/interop/ffi/protocol/handle/flow.rs`). Mirrors
 * `SecretWire`'s own shape: `channel_id`/`replica_id` are the decimal `u64`
 * strings the `SecretRecovered` event already carries, forwarded verbatim;
 * `communication_info` is omitted per-entry (not sent as `{}`) whenever a
 * helper or replica member has none — `undefined`, `null`, or an empty map
 * are all treated the same — matching the Go SDK's `omitempty` and the
 * shared golden fixture byte-for-byte; `weight` is forwarded as given
 * whenever a helper carries one; `replicas` is omitted entirely when the
 * recovered secret has no replica group, and `threshold` when the roster
 * records none.
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
      if (helper.weight !== undefined) {
        out.weight = helper.weight;
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
  if (recoveredSecret.threshold != null) {
    recovered.threshold = recoveredSecret.threshold;
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
      if (p.own_transports !== undefined) {
        out.own_transports = p.own_transports;
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
 * `threshold`, `auto_respond_on_failure`, `unpair_ack`, `auto_reply_to`
 * and `auto_accept` are omitted entirely from the emitted config unless
 * their setter was called: `ProtocolConfig` has a
 * `#[serde(default = "...")]` on each of them, reading the same constants
 * `DeRecProtocolBuilder::new` uses, so an absent key resolves to the
 * library's own default rather than one frozen into this shim.
 */
export class DeRecProtocolBuilder {
  private readonly secretIdValue: bigint;
  private config: Record<string, unknown> = {};
  private stores: Record<string, unknown> = {};

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

  /**
   * Set every store in one call. Forwards to {@link withChannelStore},
   * {@link withShareStore}, {@link withSecretStore},
   * {@link withUserSecretStore} and {@link withStateStore} in turn, so
   * calling one of them again afterwards replaces just that store.
   */
  withStores(stores: StoresInit): this {
    return this.withChannelStore(stores.channelStore)
      .withShareStore(stores.shareStore)
      .withSecretStore(stores.secretStore)
      .withUserSecretStore(stores.userSecretStore)
      .withStateStore(stores.stateStore);
  }

  withTransport(transport: Transport): this {
    this.stores.transport = transport;
    return this;
  }

  /**
   * Set every transport endpoint this application serves, in preference
   * order. Written to the config's `own_transports` array — see
   * `ProtocolConfig` in `library/src/interop/ffi/protocol/handle/mod.rs`.
   *
   * The order given is forwarded verbatim: it is not sorted, deduplicated,
   * or reordered here. It is this application's own preference and
   * decides which of a peer's offered endpoints is used. Every listed
   * transport must actually be served, because delivery is push-only —
   * listing an endpoint this application does not serve makes pairing
   * succeed and replies vanish.
   *
   * Required: `build()` with no own transport is refused by the library,
   * since a node with no endpoint cannot be reached by any peer.
   */
  withOwnTransports(transports: Endpoint[]): this {
    this.config.own_transports = transports.map(({ uri, protocol }) => ({ uri, protocol }));
    return this;
  }

  /**
   * The starting threshold: the minimum number of subshares required to
   * reconstruct the secret, for a secret with no threshold stored. Every
   * publish stores the threshold it used (`UserSecrets.threshold`), the
   * roster carries it, and `restore` and replica hydration put it back. A
   * round splits at `ProtectSecretParams.threshold`, otherwise at the stored
   * threshold, and only otherwise at this value, so changing it later does
   * not change a stored threshold.
   *
   * A Helper holds one subshare unless `ProtectSecretParams.weights` has
   * given it a weight, so with no weights the threshold is a number of
   * Helpers, as before. Every weight must be below the round's threshold, so
   * no single Helper can recover alone. When this value applies and is
   * lowered to or below a stored weight, every publish fails with
   * `invalid_weight` until `ProtectSecret` assigns valid weights. Default: 3.
   */
  withThreshold(threshold: number): this {
    this.config.threshold = threshold;
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
   * Accept plaintext `http://` and `grpc://` transport endpoints.
   * **Development only.** Default: false.
   */
  withUnsafeConnection(allow: boolean): this {
    this.config.unsafe_connection = allow;
    return this;
  }

  /**
   * Default: empty. Written to the config's `communication_info` key, so the
   * map is part of the protocol from construction.
   */
  withCommunicationInfo(info: Record<string, string>): this {
    this.config.communication_info = info;
    return this;
  }

  /**
   * Who answers an inbound request whose handling failed. `true`: the
   * library sends the response itself. `false`: nothing is sent, and the
   * `RequestFailed` event carries a token to pass to `reject`. Default:
   * false.
   */
  withAutoRespondOnFailure(enabled: boolean): this {
    this.config.auto_respond_on_failure = enabled;
    return this;
  }

  /** Default: "required". */
  withUnpairAck(ack: UnpairAck): this {
    this.config.unpair_ack = ack;
    return this;
  }

  /** Default: false. */
  withAutoReplyTo(enabled: boolean): this {
    this.config.auto_reply_to = enabled;
    return this;
  }

  /**
   * Default: empty policy (every flow off). A flow left out of `policy` is
   * left out of the config, and the library applies its own default to it.
   */
  withAutoAccept(policy: AutoAcceptPolicy): this {
    this.config.auto_accept = {
      pairing: policy.pairing,
      pre_pair: policy.prePair,
      store_share: policy.storeShare,
      verify_share: policy.verifyShare,
      discovery: policy.discovery,
      get_share: policy.getShare,
      unpair: policy.unpair,
      update_channel_info: policy.updateChannelInfo,
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
   * Bounds cross to the library as decimal strings, so the full `i64` range
   * survives; a bound left out is left out of the config, and the library
   * applies its default.
   *
   * Default: unset — no constraints advertised, every peer range accepted.
   *
   * Share size is enforced by the helper; frequency limits are enforced by
   * the app's share store (refuse from `save`/`recordVerification`); the
   * deletion and deactivation timeouts are checked at pairing only.
   */
  withParameterRange(range: Partial<ParameterRange>): this {
    this.config.parameter_range = {
      min_share_size: range.min_share_size?.toString(),
      max_share_size: range.max_share_size?.toString(),
      min_time_between_verifications: range.min_time_between_verifications?.toString(),
      max_time_between_verifications: range.max_time_between_verifications?.toString(),
      min_time_between_share_updates: range.min_time_between_share_updates?.toString(),
      max_time_between_share_updates: range.max_time_between_share_updates?.toString(),
      min_unresponsive_deletion_timeout: range.min_unresponsive_deletion_timeout?.toString(),
      max_unresponsive_deletion_timeout: range.max_unresponsive_deletion_timeout?.toString(),
      min_unresponsive_deactivation_timeout:
        range.min_unresponsive_deactivation_timeout?.toString(),
      max_unresponsive_deactivation_timeout:
        range.max_unresponsive_deactivation_timeout?.toString(),
    };
    return this;
  }

  /**
   * Cap the total number of subshares one sharing round may split the
   * secret into — the sum of every helper's weight. Crosses to the library
   * as a decimal string. Default: unset, no cap.
   *
   * Checked only by `start(ProtectSecret)`, including the publishes the
   * library starts itself: a round over the cap fails with
   * `too_many_subshares` before anything is sent. Recovery applies no cap.
   * Recovering costs time that grows quadratically with the total number of
   * subshares, so the cap bounds what a later recovery must do. A cap below
   * the threshold makes `build()` throw.
   */
  withMaxSubshares(max: bigint | number): this {
    this.config.max_subshares = BigInt(max).toString();
    return this;
  }

  /**
   * Layer a {@link DeRecProtocolConfig} onto the builder: a field the config
   * sets (present and not `null`) replaces what the builder currently
   * holds, a field it leaves unset is untouched, and `timeouts` merges per
   * field against the builder's current timeouts rather than resetting the
   * other three. Every other nested object replaces as a whole. Apply a
   * general config, then a per-user one, then any individual `with*` call —
   * the last write wins per field, same as two `withConfig` calls in a row.
   *
   * Every key is assigned verbatim into the same `snake_case` config JSON
   * `build()` sends to `protocol_new`, whatever it is spelled as: nothing
   * here validates, defaults, or recognizes field names. Rust does both —
   * `deny_unknown_fields` is what turns a misspelled key into an error.
   *
   * `secret_id` is not a config field — it is the constructor argument —
   * and `build()` always sends the constructor's value last, so a config
   * (e.g. loaded from a per-user record) can never redirect which secret
   * this instance manages even if it carries a `secret_id` key.
   *
   * A config parsed from JSON can carry an own `__proto__` key. Assigning
   * it through plain bracket notation would hit the accessor
   * `Object.prototype` defines for that name and replace this builder's
   * config object's prototype instead of setting a field on it — the value
   * would then vanish from the JSON payload instead of reaching Rust to be
   * rejected as an unknown key. `Object.defineProperty` makes it a genuine
   * own property, the same as every other key here.
   */
  withConfig(config: DeRecProtocolConfig): this {
    for (const [key, value] of Object.entries(config as Record<string, unknown>)) {
      if (value === undefined || value === null) {
        continue;
      }
      if (key === 'timeouts') {
        const held = (this.config.timeouts as Record<string, unknown> | undefined) ?? {};
        const merged: Record<string, unknown> = { ...held };
        for (const [timeoutKey, timeoutValue] of Object.entries(
          value as Record<string, unknown>,
        )) {
          if (timeoutValue !== undefined && timeoutValue !== null) {
            merged[timeoutKey] = timeoutValue;
          }
        }
        this.config.timeouts = merged;
        continue;
      }
      if (key === '__proto__') {
        Object.defineProperty(this.config, key, {
          value,
          writable: true,
          enumerable: true,
          configurable: true,
        });
        continue;
      }
      this.config[key] = value;
    }
    return this;
  }

  build(): DeRecProtocol {
    const config = {
      replica_id: null,
      ...this.config,
      // Last, so a config's own `secret_id` key (it is not a config field;
      // see `withConfig`) can never override the constructor's.
      secret_id: this.secretIdValue.toString(),
    };
    const host = (getNative() as unknown as NativeHost).protocol_new(
      JSON.stringify(config),
      new Uint8Array(0),
      this.stores,
    ) as NativeHost;
    return DeRecProtocol.fromHost(host);
  }
}

/**
 * Thin wrapper around the `ProtocolHost` JSI host object, mirroring
 * `@derec-alliance/nodejs`'s `DeRecProtocol` — same methods, and the same
 * sync/async split: `secretId` is synchronous and everything else returns a
 * `Promise`. Every method encodes its
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
   * Replaces this node's local communication info.
   *
   * The native setter takes the same handle mutex a running flow holds
   * across its store callbacks, so calling it on the JavaScript thread would
   * block that thread until the flow released the mutex — which it cannot do
   * while it is waiting on the JavaScript thread. The binding therefore
   * queues the setter onto the same serial worker every flow runs on, which
   * orders it after any call already in flight. Awaiting the returned
   * `Promise` surfaces a failure that would otherwise be swallowed.
   */
  setCommunicationInfo(info: Record<string, string>): Promise<void> {
    return this.host.setCommunicationInfo(jsonToBytes(info)) as Promise<void>;
  }

  /**
   * Replaces every endpoint this node advertises, in preference order —
   * the runtime counterpart to `withOwnTransports`.
   *
   * Every entry is validated before any is stored, so a malformed URI
   * leaves the previous set intact. An empty array is rejected.
   *
   * Queued onto the serial worker for the same reason as
   * {@link setCommunicationInfo}.
   */
  setOwnTransports(transports: Endpoint[]): Promise<void> {
    const wire = transports.map(({ uri, protocol }) => ({ uri, protocol }));
    return this.host.setOwnTransports(jsonToBytes(wire)) as Promise<void>;
  }

  /**
   * Decodes the `contact_wire_bytes` `derec_protocol_create_contact`
   * produces into a typed `ContactMessage`, so an application can read the
   * contact's `nonce`, `supported_transports` and mode without a protobuf
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
    let buffer: ArrayBuffer;
    try {
      buffer = (await this.host.process(message)) as ArrayBuffer;
    } catch (error) {
      const failure = error as { events?: unknown };
      if (Array.isArray(failure.events)) {
        failure.events = reviveEventBytes(failure.events);
      }
      throw error;
    }
    return decodeEvents(buffer);
  }

  async tick(): Promise<DeRecEvent[]> {
    const buffer = (await this.host.tick()) as ArrayBuffer;
    return decodeEvents(buffer);
  }

  /**
   * Accept a pending action from an `ActionRequired` event, returning the
   * events it produces.
   *
   * When the action completes a pairing, the publish that follows reuses the
   * stored helper weights. If one is no longer valid under the round's
   * threshold, that publish fails with `invalid_weight` before anything is
   * sent and this throws: the pairing has completed and its response was
   * sent, but the `PairingCompleted` event is not returned. Call `start`
   * with `ProtectSecret` and valid weights to publish.
   */
  async accept(actionBytes: Uint8Array): Promise<DeRecEvent[]> {
    const buffer = (await this.host.accept(actionBytes)) as ArrayBuffer;
    return decodeEvents(buffer);
  }

  async reject(actionBytes: Uint8Array, status: StatusEnum, memo: string): Promise<void> {
    await this.host.reject(actionBytes, status, memo);
  }

  async getFingerprint(channelId: bigint | number): Promise<string> {
    return (await this.host.getFingerprint(toBigInt(channelId))) as string;
  }

  /**
   * Verify `fingerprint` against the channel's locally-derived one. On
   * match, the channel transitions from `Pending` to `Paired`.
   *
   * A mismatch rejects with code `fingerprint_mismatch` — a possible
   * man-in-the-middle. A `Pending` pairing is revoked: its records, channel
   * key and pairing material are deleted, so pair again. A channel already
   * `Paired` is left as it is.
   *
   * On a replica destination, confirming is also the decision to adopt the
   * group's vault: the source's publish is then installed as it arrives,
   * with no further prompt. Ask the user before calling this; to decline,
   * never confirm: expired-channel cleanup removes the channel and its key.
   *
   * On a promotion the current snapshot is published to the promoted peer,
   * reusing the stored helper weights. If one is no longer valid under the
   * current threshold, that publish fails with `invalid_weight` before
   * anything is sent and this throws. The promotion stands: calling this
   * again resolves and publishes nothing, so call `start` with
   * `ProtectSecret` and valid weights to reach the promoted peer.
   */
  async verifyFingerprint(channelId: bigint | number, fingerprint: string): Promise<void> {
    await this.host.verifyFingerprint(toBigInt(channelId), fingerprint);
  }

  async removeExpiredChannels(olderThanSecs: number): Promise<string[]> {
    const buffer = (await this.host.removeExpiredChannels(olderThanSecs)) as ArrayBuffer;
    return jsonFromBytes(buffer) as string[];
  }

  /**
   * Rebuild this protocol's `secret_id` namespace from a recovered `Secret`.
   * Pass the `secret` carried by the `SecretRecovered` event verbatim.
   * Recovery and restore are separate steps on purpose: `SecretRecovered`
   * writes nothing. Show the user what was recovered, or ask them, before
   * calling `restore`, which commits it to this device.
   * A helper or member whose `transports` is empty gets no channel: it is
   * reported as a `PeerNotRestored` event in the returned array and the rest
   * of the roster is restored.
   *
   * A helper's or member's `communication_info` may be absent or `null`;
   * both mean the same thing — no entries.
   *
   * Rejects with a `DeRecError`; among its codes:
   *
   * | code               | meaning                                                     |
   * |--------------------|-------------------------------------------------------------|
   * | `already_restored` | A user-secret snapshot already exists for this `secret_id`. |
   * | `restore_conflict` | Channels live at ids restore is about to write. The error   |
   * |                    | carries `channel_ids: string[]` listing the collisions.     |
   */
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

  /** Same as {@link DeRecProtocol.free}, for `using`. */
  [Symbol.dispose](): void {
    this.free();
  }
}
