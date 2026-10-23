// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

import * as fs from 'node:fs';
import * as path from 'node:path';

import type { DeRecEvent } from '../src/types';

const golden = JSON.parse(
  fs.readFileSync(path.join(__dirname, '../../../library/tests/fixtures/events_golden.json'), 'utf8'),
) as { events: Array<Record<string, unknown> & { type: string }> };

// How each declared field is typed: a byte field is one `DeRecEvent` declares
// `Uint8Array`, and `?` marks a field that may be absent.
type Kind = 'required' | 'optional' | 'bytes' | 'bytes?';

type FieldKind<V, P extends keyof V> =
  NonNullable<V[P]> extends Uint8Array
    ? {} extends Pick<V, P>
      ? 'bytes?'
      : 'bytes'
    : {} extends Pick<V, P>
      ? 'optional'
      : 'required';

type Fields<V> = { [P in keyof V]-?: FieldKind<V, P> };

interface Desc {
  fields: Record<string, Kind>;
  nested?: Record<string, Desc>;
}

type Variant<T extends DeRecEvent['type']> = Extract<DeRecEvent, { type: T }>;
type SecretEvent = 'SecretRecovered' | 'ReplicaSecretReceived' | 'ReplicaSecretInstalled' | 'ReplicaVersionConflict';
type SecretOf<T extends SecretEvent> = Variant<T>['secret'];
type Replicas<T extends SecretEvent> = NonNullable<SecretOf<T>['replicas']>;

// Mutual assignability: the same keys, each with the same `Kind`.
type Same<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false;
type Assert<T extends true> = T;

const ENDPOINT = { fields: { uri: 'required', protocol: 'required' } } as const;

const USER_SECRET = { fields: { id: 'bytes', name: 'required', data: 'bytes' } } as const;

// `weight` is always on the wire, but the same shape is `restore`'s input,
// which accepts a roster written before the field existed.
const HELPER = {
  fields: {
    channel_id: 'required',
    transports: 'required',
    shared_key: 'bytes',
    communication_info: 'optional',
    weight: 'optional',
  },
  nested: { transports: ENDPOINT },
} as const;

const MEMBER = {
  fields: { replica_id: 'required', transports: 'required', role: 'required', communication_info: 'optional' },
  nested: { transports: ENDPOINT },
} as const;

const REPLICAS = {
  fields: { channel_id: 'required', members: 'required', shared_key: 'bytes' },
  nested: { members: MEMBER },
} as const;

const SECRET = {
  fields: { helpers: 'required', secrets: 'required', replicas: 'optional', threshold: 'optional' },
  nested: { helpers: HELPER, secrets: USER_SECRET, replicas: REPLICAS },
} as const;

const SHARE = { fields: { channel_id: 'required', committed_share: 'bytes' } } as const;

const DISCOVERED_SECRET = {
  fields: { secret_id: 'required', versions: 'required' },
  nested: { versions: { fields: { version: 'required', description: 'required' } } },
} as const;

const REPLICA_COPY = {
  fields: {
    type: 'required',
    channel_id: 'required',
    from_replica_id: 'required',
    author_replica_id: 'required',
    secret_id: 'required',
    version: 'required',
    secret: 'required',
    shares: 'required',
  },
  nested: { secret: SECRET, shares: SHARE },
} as const;

const STATUS_MEMO = { status: 'required', memo: 'required' } as const;

const EVENTS = {
  PairingCompleted: {
    fields: {
      type: 'required',
      channel_id: 'required',
      pairing_channel_id: 'required',
      kind: 'required',
      peer_communication_info: 'optional',
    },
  },
  ReplicaPaired: { fields: { type: 'required', channel_id: 'required', peer_replica_id: 'required' } },
  ReplicaSecretReceived: REPLICA_COPY,
  ReplicaSecretInstalled: REPLICA_COPY,
  ReplicaVersionConflict: {
    fields: {
      type: 'required',
      channel_id: 'required',
      from_replica_id: 'required',
      secret_id: 'required',
      version: 'required',
      held_author_replica_id: 'required',
      incoming_author_replica_id: 'required',
      secret: 'required',
    },
    nested: { secret: SECRET },
  },
  ReplicaSecretRefused: {
    fields: {
      type: 'required',
      channel_id: 'required',
      from_replica_id: 'required',
      secret_id: 'required',
      version: 'required',
      ...STATUS_MEMO,
    },
  },
  ReplicaSecretAcked: {
    fields: {
      type: 'required',
      channel_id: 'required',
      from_replica_id: 'required',
      secret_id: 'required',
      version: 'required',
      ...STATUS_MEMO,
    },
  },
  ReplicaSyncRejected: {
    fields: { type: 'required', replica_id: 'required', secret_id: 'required', version: 'required', ...STATUS_MEMO },
  },
  ReplicaSyncFailed: { fields: { type: 'required', replica_id: 'required', version: 'required', reason: 'required' } },
  ReplicaRemoved: { fields: { type: 'required', replica_id: 'required' } },
  ReplicaSourceChanged: { fields: { type: 'required', replica_id: 'required' } },
  SelfRemovedFromGroup: { fields: { type: 'required', version: 'required' } },
  ReplicaDiscoveryComplete: {
    fields: { type: 'required', local_version: 'required', group_version: 'required', fetched_from: 'optional' },
  },
  ReplicaSyncComplete: { fields: { type: 'required', version: 'required', synced: 'required', behind: 'required' } },
  ShareStored: { fields: { type: 'required', channel_id: 'required', version: 'required' } },
  ShareRefused: { fields: { type: 'required', channel_id: 'required', version: 'required', ...STATUS_MEMO } },
  ShareConfirmed: { fields: { type: 'required', channel_id: 'required', version: 'required' } },
  ShareRejected: { fields: { type: 'required', channel_id: 'required', version: 'required', ...STATUS_MEMO } },
  SharingComplete: {
    fields: {
      type: 'required',
      version: 'required',
      confirmed_count: 'required',
      failed_count: 'required',
      threshold_met: 'required',
    },
  },
  ShareVerified: {
    fields: {
      type: 'required',
      channel_id: 'required',
      version: 'required',
      subshares: 'optional',
      threshold: 'optional',
    },
  },
  ShareVerifyInvalid: { fields: { type: 'required', channel_id: 'required', version: 'required' } },
  ShareVerifyRejected: { fields: { type: 'required', channel_id: 'required', version: 'required', ...STATUS_MEMO } },
  SecretsDiscovered: {
    fields: { type: 'required', channel_id: 'required', secrets: 'required' },
    nested: { secrets: DISCOVERED_SECRET },
  },
  RecoveryShareReceived: { fields: { type: 'required', channel_id: 'required', shares_received: 'required' } },
  RecoveryShareError: {
    fields: { type: 'required', channel_id: 'required', shares_received: 'required', error: 'required' },
  },
  RecoveryShareRefused: { fields: { type: 'required', channel_id: 'required', version: 'required', ...STATUS_MEMO } },
  RecoveryShareCorrupted: {
    fields: { type: 'required', channel_id: 'required', version: 'required', reason: 'required' },
  },
  SecretRecovered: { fields: { type: 'required', secret: 'required' }, nested: { secret: SECRET } },
  Unpaired: { fields: { type: 'required', channel_id: 'required' } },
  UnpairRejected: { fields: { type: 'required', channel_id: 'required', ...STATUS_MEMO } },
  PrePairRejected: { fields: { type: 'required', channel_id: 'required', ...STATUS_MEMO } },
  ErrorResponseReceived: { fields: { type: 'required', channel_id: 'required', ...STATUS_MEMO } },
  PairingRefused: {
    fields: {
      type: 'required',
      channel_id: 'required',
      ...STATUS_MEMO,
      error_code: 'required',
      message: 'required',
    },
  },
  ChannelInfoUpdated: { fields: { type: 'required', channel_id: 'required' } },
  ChannelInfoUpdateRejected: { fields: { type: 'required', channel_id: 'required', ...STATUS_MEMO } },
  ActionRequired: {
    fields: {
      type: 'required',
      channel_id: 'required',
      action: 'bytes',
      action_kind: 'required',
      trace_id: 'required',
      peer_communication_info: 'optional',
      sender_kind: 'optional',
      version: 'optional',
      share_description: 'optional',
      share_secret_id: 'optional',
      share_size: 'optional',
      unpair_memo: 'optional',
      updated_communication_info: 'optional',
      updated_transports: 'optional',
    },
    nested: { updated_transports: ENDPOINT },
  },
  AutoAccepted: { fields: { type: 'required', channel_id: 'required', action_kind: 'required' } },
  RequestFailed: {
    fields: {
      type: 'required',
      channel_id: 'required',
      action_kind: 'required',
      responded: 'required',
      ...STATUS_MEMO,
      error_code: 'required',
      message: 'required',
      action: 'bytes?',
    },
  },
  NoOp: { fields: { type: 'required' } },
  MessageIgnored: {
    fields: { type: 'required', channel_id: 'required', reason: 'required', trace_id: 'required' },
  },
  PeerNotRestored: {
    fields: { type: 'required', channel_id: 'required', replica_id: 'optional', reason: 'required' },
  },
  PairingStarted: { fields: { type: 'required', channel_id: 'required', kind: 'required', trace_id: 'required' } },
  DiscoveryStarted: { fields: { type: 'required', channel_id: 'required', trace_id: 'required' } },
  DiscoveryFailed: { fields: { type: 'required', channel_id: 'required', error: 'required' } },
  ProtectSecretStarted: {
    fields: {
      type: 'required',
      channel_id: 'required',
      version: 'required',
      trace_id: 'required',
      weight: 'required',
    },
  },
  ProtectSecretFailed: {
    fields: { type: 'required', channel_id: 'required', version: 'required', error: 'required', weight: 'required' },
  },
  VerifySharesStarted: {
    fields: { type: 'required', channel_id: 'required', version: 'required', trace_id: 'required' },
  },
  VerifySharesFailed: {
    fields: { type: 'required', channel_id: 'required', version: 'required', reason: 'required', error: 'required' },
  },
  RecoverSecretStarted: {
    fields: { type: 'required', channel_id: 'required', version: 'required', trace_id: 'required' },
  },
  RecoverSecretFailed: {
    fields: { type: 'required', channel_id: 'required', version: 'required', error: 'required' },
  },
  UnpairFailed: { fields: { type: 'required', channel_id: 'required', error: 'required' } },
  UnpairStarted: { fields: { type: 'required', channel_id: 'required', trace_id: 'required' } },
  UpdateChannelInfoStarted: { fields: { type: 'required', channel_id: 'required', trace_id: 'required' } },
  UpdateChannelInfoFailed: { fields: { type: 'required', channel_id: 'required', error: 'required' } },
} as const;

// Compile-time half: the tables above describe exactly what `DeRecEvent`
// declares — every variant, every field, its optionality and whether it is a
// byte field. A field added to or dropped from a declaration, or a changed
// optionality, fails `tsc --noEmit` here; the runtime half below then holds
// the tables to the fixture.
export type DeclarationChecks = [
  Assert<Same<{ [T in DeRecEvent['type']]: Fields<Variant<T>> }, { -readonly [T in keyof typeof EVENTS]: (typeof EVENTS)[T]['fields'] }>>,
  Assert<Same<Fields<SecretOf<'SecretRecovered'>>, typeof SECRET.fields>>,
  Assert<Same<Fields<SecretOf<'ReplicaSecretReceived'>>, typeof SECRET.fields>>,
  Assert<Same<Fields<SecretOf<'ReplicaSecretInstalled'>>, typeof SECRET.fields>>,
  Assert<Same<Fields<SecretOf<'ReplicaVersionConflict'>>, typeof SECRET.fields>>,
  Assert<Same<Fields<SecretOf<'SecretRecovered'>['helpers'][number]>, typeof HELPER.fields>>,
  Assert<Same<Fields<SecretOf<'ReplicaSecretReceived'>['helpers'][number]>, typeof HELPER.fields>>,
  Assert<Same<Fields<SecretOf<'ReplicaSecretInstalled'>['helpers'][number]>, typeof HELPER.fields>>,
  Assert<Same<Fields<SecretOf<'ReplicaVersionConflict'>['helpers'][number]>, typeof HELPER.fields>>,
  Assert<Same<Fields<SecretOf<'SecretRecovered'>['secrets'][number]>, typeof USER_SECRET.fields>>,
  Assert<Same<Fields<SecretOf<'ReplicaSecretReceived'>['secrets'][number]>, typeof USER_SECRET.fields>>,
  Assert<Same<Fields<SecretOf<'ReplicaSecretInstalled'>['secrets'][number]>, typeof USER_SECRET.fields>>,
  Assert<Same<Fields<SecretOf<'ReplicaVersionConflict'>['secrets'][number]>, typeof USER_SECRET.fields>>,
  Assert<Same<Fields<Replicas<'SecretRecovered'>>, typeof REPLICAS.fields>>,
  Assert<Same<Fields<Replicas<'ReplicaSecretReceived'>>, typeof REPLICAS.fields>>,
  Assert<Same<Fields<Replicas<'ReplicaSecretInstalled'>>, typeof REPLICAS.fields>>,
  Assert<Same<Fields<Replicas<'ReplicaVersionConflict'>>, typeof REPLICAS.fields>>,
  Assert<Same<Fields<Replicas<'SecretRecovered'>['members'][number]>, typeof MEMBER.fields>>,
  Assert<Same<Fields<Replicas<'ReplicaSecretReceived'>['members'][number]>, typeof MEMBER.fields>>,
  Assert<Same<Fields<Replicas<'ReplicaSecretInstalled'>['members'][number]>, typeof MEMBER.fields>>,
  Assert<Same<Fields<Replicas<'ReplicaVersionConflict'>['members'][number]>, typeof MEMBER.fields>>,
  Assert<Same<Fields<SecretOf<'SecretRecovered'>['helpers'][number]['transports'][number]>, typeof ENDPOINT.fields>>,
  Assert<Same<Fields<NonNullable<Variant<'ActionRequired'>['updated_transports']>[number]>, typeof ENDPOINT.fields>>,
  Assert<Same<Fields<Variant<'ReplicaSecretReceived'>['shares'][number]>, typeof SHARE.fields>>,
  Assert<Same<Fields<Variant<'ReplicaSecretInstalled'>['shares'][number]>, typeof SHARE.fields>>,
  Assert<Same<Fields<Variant<'SecretsDiscovered'>['secrets'][number]>, typeof DISCOVERED_SECRET.fields>>,
  Assert<
    Same<
      Fields<Variant<'SecretsDiscovered'>['secrets'][number]['versions'][number]>,
      typeof DISCOVERED_SECRET.nested.versions.fields
    >
  >,
];

function sortedKeys(value: unknown): string[] {
  return Object.keys(value as object).sort();
}

/**
 * Holds one decoded value to its fixture sample: the fixture carries exactly
 * the fields `desc` declares, decoding kept exactly those, a byte field became
 * a `Uint8Array` with the same bytes, and every other field is unchanged.
 */
function expectShape(decoded: unknown, sample: unknown, desc: Desc, where: string): void {
  expect({ where, keys: sortedKeys(sample) }).toEqual({ where, keys: sortedKeys(desc.fields) });
  expect({ where, keys: sortedKeys(decoded) }).toEqual({ where, keys: sortedKeys(sample) });
  const got = decoded as Record<string, unknown>;
  const want = sample as Record<string, unknown>;
  for (const [key, kind] of Object.entries(desc.fields)) {
    const at = `${where}.${key}`;
    if (kind === 'bytes' || kind === 'bytes?') {
      expect({ at, bytes: got[key] instanceof Uint8Array }).toEqual({ at, bytes: true });
      expect({ at, value: Array.from(got[key] as Uint8Array) }).toEqual({ at, value: want[key] });
      continue;
    }
    const child = desc.nested?.[key];
    if (child === undefined) {
      expect({ at, value: got[key] }).toEqual({ at, value: want[key] });
    } else if (Array.isArray(want[key])) {
      const items = want[key] as unknown[];
      expect({ at, length: (got[key] as unknown[]).length }).toEqual({ at, length: items.length });
      items.forEach((item, i) => expectShape((got[key] as unknown[])[i], item, child, `${at}[${i}]`));
    } else {
      expectShape(got[key], want[key], child, at);
    }
  }
}

describe('event golden vectors', () => {
  let decoded: DeRecEvent[];

  beforeAll(async () => {
    const bytes = new TextEncoder().encode(JSON.stringify(golden.events));
    // @ts-expect-error test-only global
    globalThis.__DeRec = { tick: () => Promise.resolve(bytes.buffer) };
    const { DeRecProtocol } = await import('../src/protocol');
    // @ts-expect-error test-only global
    decoded = await DeRecProtocol.fromHost(globalThis.__DeRec).tick();
  });

  afterAll(() => {
    // @ts-expect-error test-only global
    delete globalThis.__DeRec;
  });

  it('declares exactly the event types the fixture samples', () => {
    expect(Object.keys(EVENTS).sort()).toEqual([...new Set(golden.events.map((e) => e.type))].sort());
  });

  it('decodes every sample in order', () => {
    expect(decoded.map((e) => e.type)).toEqual(golden.events.map((e) => e.type));
  });

  it.each(golden.events.map((sample, i) => [sample.type, i] as const))(
    '%s survives decoding with every field',
    (type, i) => {
      const desc = (EVENTS as Record<string, Desc>)[type];
      expect(desc).toBeDefined();
      expectShape(decoded[i], golden.events[i], desc, type);
    },
  );

  it('keeps the null author ids null', () => {
    const nulls = golden.events.flatMap((sample, i) =>
      ['author_replica_id', 'held_author_replica_id', 'incoming_author_replica_id']
        .filter((key) => key in sample && sample[key] === null)
        .map((key) => (decoded[i] as Record<string, unknown>)[key]),
    );
    expect(nulls.length).toBeGreaterThan(0);
    nulls.forEach((value) => expect(value).toBeNull());
  });
});
