import { readFileSync } from "node:fs";
import { join } from "node:path";

import type { DeRecEvent } from "@derec-alliance/nodejs";

/**
 * How a declared event field appears on the wire: always present, possibly
 * absent (`field?: T`, a Rust `skip_serializing_if`), or always present and
 * possibly `null` (`field: T | null`, a Rust `Option` that is not skipped).
 */
type Presence = "required" | "optional" | "nullable";

type EventType = DeRecEvent["type"];
type Variant<T extends EventType> = Extract<DeRecEvent, { type: T }>;
type PresenceOf<V, F extends keyof V> = {} extends Pick<V, F>
  ? "optional"
  : null extends V[F]
    ? "nullable"
    : "required";

/**
 * Every `DeRecEvent` variant with every declared field and its presence,
 * computed from `index.d.ts`. A variant or field added to or removed from the
 * declarations, or a field whose optionality changes, makes the table below
 * fail to compile until it is updated; the run-time check then holds the
 * updated table to what Rust emits.
 */
type EventFieldTable = {
  [T in EventType]: { [F in Exclude<keyof Variant<T>, "type">]-?: PresenceOf<Variant<T>, F> };
};

const R = "required";
const O = "optional";
const N = "nullable";

const DECLARED: EventFieldTable = {
  PairingCompleted: { channel_id: R, pairing_channel_id: R, kind: R, peer_communication_info: O },
  ActionRequired: {
    channel_id: R,
    action: R,
    action_kind: R,
    trace_id: R,
    peer_communication_info: O,
    sender_kind: O,
    version: O,
    share_description: O,
    share_secret_id: O,
    share_size: O,
    unpair_memo: O,
    updated_communication_info: O,
    updated_transports: O,
  },
  ShareStored: { channel_id: R, version: R },
  ShareRefused: { channel_id: R, version: R, status: R, memo: R },
  ShareConfirmed: { channel_id: R, version: R },
  ShareRejected: { channel_id: R, version: R, status: R, memo: R },
  SharingComplete: { version: R, confirmed_count: R, failed_count: R, threshold_met: R },
  ReplicaSyncRejected: { replica_id: R, secret_id: R, version: R, status: R, memo: R },
  ReplicaSyncFailed: { replica_id: R, version: R, reason: R },
  ReplicaRemoved: { replica_id: R },
  ReplicaSourceChanged: { replica_id: R },
  SelfRemovedFromGroup: { version: R },
  ReplicaDiscoveryComplete: { local_version: R, group_version: R, fetched_from: O },
  ReplicaSyncComplete: { version: R, synced: R, behind: R },
  ShareVerified: { channel_id: R, version: R, subshares: O, threshold: O },
  ShareVerifyInvalid: { channel_id: R, version: R },
  ShareVerifyRejected: { channel_id: R, version: R, status: R, memo: R },
  SecretsDiscovered: { channel_id: R, secrets: R },
  RecoveryShareReceived: { channel_id: R, shares_received: R },
  RecoveryShareError: { channel_id: R, shares_received: R, error: R },
  RecoveryShareRefused: { channel_id: R, version: R, status: R, memo: R },
  RecoveryShareCorrupted: { channel_id: R, version: R, reason: R },
  SecretRecovered: { secret: R },
  Unpaired: { channel_id: R },
  UnpairRejected: { channel_id: R, status: R, memo: R },
  PrePairRejected: { channel_id: R, status: R, memo: R },
  ErrorResponseReceived: { channel_id: R, status: R, memo: R },
  PairingRefused: { channel_id: R, status: R, memo: R, error_code: R, message: R },
  ReplicaPaired: { channel_id: R, peer_replica_id: R },
  ReplicaSecretReceived: {
    channel_id: R,
    from_replica_id: R,
    author_replica_id: N,
    secret_id: R,
    version: R,
    secret: R,
    shares: R,
  },
  ReplicaSecretInstalled: {
    channel_id: R,
    from_replica_id: R,
    author_replica_id: N,
    secret_id: R,
    version: R,
    secret: R,
    shares: R,
  },
  ReplicaVersionConflict: {
    channel_id: R,
    from_replica_id: R,
    secret_id: R,
    version: R,
    held_author_replica_id: N,
    incoming_author_replica_id: N,
    secret: R,
  },
  ReplicaSecretRefused: { channel_id: R, from_replica_id: R, secret_id: R, version: R, status: R, memo: R },
  ReplicaSecretAcked: { channel_id: R, from_replica_id: R, secret_id: R, version: R, status: R, memo: R },
  ChannelInfoUpdated: { channel_id: R },
  ChannelInfoUpdateRejected: { channel_id: R, status: R, memo: R },
  AutoAccepted: { channel_id: R, action_kind: R },
  RequestFailed: {
    channel_id: R,
    action_kind: R,
    responded: R,
    status: R,
    memo: R,
    error_code: R,
    message: R,
    action: O,
  },
  NoOp: {},
  MessageIgnored: { channel_id: R, reason: R, trace_id: R },
  PeerNotRestored: { channel_id: R, replica_id: O, reason: R },
  PairingStarted: { channel_id: R, kind: R, trace_id: R },
  DiscoveryStarted: { channel_id: R, trace_id: R },
  DiscoveryFailed: { channel_id: R, error: R },
  ProtectSecretStarted: { channel_id: R, version: R, trace_id: R, weight: R },
  ProtectSecretFailed: { channel_id: R, version: R, error: R, weight: R },
  VerifySharesStarted: { channel_id: R, version: R, trace_id: R },
  VerifySharesFailed: { channel_id: R, version: R, reason: R, error: R },
  RecoverSecretStarted: { channel_id: R, version: R, trace_id: R },
  RecoverSecretFailed: { channel_id: R, version: R, error: R },
  UnpairFailed: { channel_id: R, error: R },
  UnpairStarted: { channel_id: R, trace_id: R },
  UpdateChannelInfoStarted: { channel_id: R, trace_id: R },
  UpdateChannelInfoFailed: { channel_id: R, error: R },
};

/**
 * Field presence per variant as Rust's wire mirror defines it, read from the
 * `Event` enum in `wire.rs`: a field under `skip_serializing_if` may be
 * absent, an `Option` that is not skipped is serialized as `null`, and every
 * other field is always present. The fixture cannot carry this — it shows
 * every optional field present.
 */
function rustPresence(source: string): Map<string, Map<string, Presence>> {
  const start = source.indexOf("pub(crate) enum Event {");
  if (start < 0) throw new Error("wire.rs: `pub(crate) enum Event {` not found");
  const variants = new Map<string, Map<string, Presence>>();
  let fields: Map<string, Presence> | undefined;
  let skipped = false;
  for (const line of source.slice(start).split("\n").slice(1)) {
    if (line === "}") break;
    const variant = /^ {4}([A-Z]\w*)(?: \{|,)$/.exec(line);
    if (variant) {
      fields = new Map();
      variants.set(variant[1]!, fields);
      skipped = false;
      continue;
    }
    if (/^ {8}#\[serde\(.*skip_serializing_if/.test(line)) {
      skipped = true;
      continue;
    }
    const field = /^ {8}(\w+): (.+),$/.exec(line);
    if (field && fields) {
      fields.set(
        field[1]!,
        skipped ? "optional" : field[2]!.startsWith("Option<") ? "nullable" : "required",
      );
      skipped = false;
    }
  }
  if (variants.size === 0) throw new Error("wire.rs: no `Event` variant parsed");
  return variants;
}

function sameKeys(a: Iterable<string>, b: Iterable<string>): boolean {
  const left = [...a].sort();
  const right = [...b].sort();
  return left.length === right.length && left.every((k, i) => k === right[i]);
}

/**
 * Holds the `DeRecEvent` declarations to the shared golden fixture and to the
 * Rust wire mirror it was generated from: the same variants, the same fields
 * per variant, and the same presence for each field. Fails both ways — a
 * declared field the fixture lacks, and a fixture field nothing declares.
 */
export function checkEventDeclarations(
  fixture: { events: Array<Record<string, unknown>> },
  wireSource: string,
): void {
  const declared = DECLARED as Record<string, Record<string, Presence>>;
  const rust = rustPresence(wireSource);
  const samples = new Map<string, Record<string, unknown>>();
  for (const event of fixture.events) {
    const type = String(event.type);
    if (samples.has(type)) throw new Error(`fixture: duplicate sample for ${type}`);
    samples.set(type, event);
  }

  if (!sameKeys(Object.keys(declared), samples.keys())) {
    throw new Error(
      `declared variants [${Object.keys(declared).sort().join(", ")}] ≠ fixture variants [${[...samples.keys()].sort().join(", ")}]`,
    );
  }
  if (!sameKeys(Object.keys(declared), rust.keys())) {
    throw new Error(
      `declared variants [${Object.keys(declared).sort().join(", ")}] ≠ wire.rs variants [${[...rust.keys()].sort().join(", ")}]`,
    );
  }

  for (const [type, fields] of Object.entries(declared)) {
    const sample = samples.get(type)!;
    const sampleFields = Object.keys(sample).filter((k) => k !== "type");
    const missing = Object.keys(fields).filter((f) => !sampleFields.includes(f));
    const undeclared = sampleFields.filter((f) => !(f in fields));
    if (missing.length > 0 || undeclared.length > 0) {
      throw new Error(
        `${type}: declared but absent from the fixture [${missing.join(", ")}]; in the fixture but not declared [${undeclared.join(", ")}]`,
      );
    }

    const wire = rust.get(type)!;
    if (!sameKeys(Object.keys(fields), wire.keys())) {
      throw new Error(
        `${type}: declared fields [${Object.keys(fields).sort().join(", ")}] ≠ wire.rs fields [${[...wire.keys()].sort().join(", ")}]`,
      );
    }
    for (const [field, presence] of Object.entries(fields)) {
      if (wire.get(field) !== presence) {
        throw new Error(`${type}.${field}: declared ${presence}, wire.rs emits it ${wire.get(field)}`);
      }
      if (sample[field] === null && presence !== "nullable") {
        throw new Error(`${type}.${field}: the fixture carries null, the declaration does not admit it`);
      }
    }
  }
}

export function runEventFixtureConformance(): void {
  console.log("=== Event declarations vs golden fixture ===");

  const repo = join(import.meta.dirname, "..", "..");
  const fixture = JSON.parse(
    readFileSync(join(repo, "library", "tests", "fixtures", "events_golden.json"), "utf8"),
  ) as { events: Array<Record<string, unknown>> };
  const wireSource = readFileSync(
    join(repo, "library", "src", "protocol", "events", "wire.rs"),
    "utf8",
  );
  checkEventDeclarations(fixture, wireSource);

  console.log(`All ${fixture.events.length} event variants match the fixture and wire.rs.\n`);
}
