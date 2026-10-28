// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

import * as fs from 'node:fs';
import * as path from 'node:path';

import { buildProtectSecretParams, buildRestoreParams } from '../src/protocol';
import type { DeRecEvent, ProtectSecretParams } from '../src/types';

const golden = JSON.parse(
  fs.readFileSync(path.join(__dirname, '../../../library/tests/fixtures/wire_golden.json'), 'utf8'),
) as Record<string, unknown>;

function asciiBytes(text: string): Uint8Array {
  return Uint8Array.from(Array.from(text, (c) => c.charCodeAt(0)));
}

// Mirrors goldenRestoreSecret() at packages/go/protocol/wire_golden_test.go:59:
// two UserSecrets shared by both the restore and protect_secret fixtures.
function goldenUserSecrets(): ProtectSecretParams['secrets'] {
  return [
    { id: Uint8Array.from([0x01]), name: 'wallet', data: asciiBytes('correct horse battery staple') },
    { id: Uint8Array.from([0x02, 0x03]), name: 'seed', data: Uint8Array.from([0xde, 0xad, 0xbe, 0xef]) },
  ];
}

function goldenProtectSecretInput(): ProtectSecretParams {
  return {
    secrets: goldenUserSecrets(),
    description: 'capture description',
  };
}

function goldenProtectSecretWeightedInput(): ProtectSecretParams {
  return {
    secrets: goldenUserSecrets(),
    description: 'capture description',
    weights: new Map([
      [7n, 2],
      [12n, 3],
    ]),
  };
}

// The two 32-byte shared keys are filled with `i` and `31 - i` respectively,
// matching goldenRestoreSecret()'s sharedKey1/sharedKey2. helpers[1] and
// replicas.members[1] carry an empty communication_info map (the field is
// required on this event shape) to exercise the same omit-when-empty branch
// Go's `omitempty` exercises on its CommunicationInfo-absent entries.
function goldenRestoreInput(): Extract<DeRecEvent, { type: 'SecretRecovered' }>['secret'] {
  const sharedKey1 = Uint8Array.from({ length: 32 }, (_, i) => i);
  const sharedKey2 = Uint8Array.from({ length: 32 }, (_, i) => 31 - i);
  const replicaGroupKey = Uint8Array.from([9, 8, 7, 6, 5, 4, 3, 2, 1, 0]);

  return {
    helpers: [
      {
        channel_id: '11',
        transports: [{ uri: 'https://helper-a.example.com', protocol: 'https' }],
        shared_key: sharedKey1,
        communication_info: { foo: 'bar' },
        weight: 1,
      },
      {
        channel_id: '22',
        transports: [{ uri: 'https://helper-b.example.com', protocol: 'https' }],
        shared_key: sharedKey2,
        communication_info: {},
        weight: 2,
      },
    ],
    secrets: goldenUserSecrets(),
    replicas: {
      channel_id: '33',
      members: [
        {
          replica_id: '44',
          transports: [{ uri: 'https://replica-a.example.com', protocol: 'https' }],
          role: 'Source',
          communication_info: { baz: 'qux' },
        },
        {
          replica_id: '66',
          transports: [{ uri: 'https://replica-b.example.com', protocol: 'https' }],
          role: 'Destination',
          communication_info: {},
        },
      ],
      shared_key: replicaGroupKey,
    },
    threshold: 3,
  };
}

describe('wire golden vectors', () => {
  it('protect_secret params match the shared fixture', () => {
    expect(buildProtectSecretParams(goldenProtectSecretInput())).toEqual(golden.protect_secret);
  });

  it('protect_secret_weighted params match the shared fixture', () => {
    expect(buildProtectSecretParams(goldenProtectSecretWeightedInput())).toEqual(
      golden.protect_secret_weighted,
    );
  });

  it('protect_secret_weighted params accept decimal-string channel ids identically', () => {
    const input = {
      ...goldenProtectSecretInput(),
      weights: new Map<bigint | string, number>([
        ['7', 2],
        ['12', 3],
      ]),
    };
    expect(buildProtectSecretParams(input)).toEqual(golden.protect_secret_weighted);
  });

  it('protect_secret_threshold params match the shared fixture', () => {
    expect(buildProtectSecretParams({ ...goldenProtectSecretInput(), threshold: 3 })).toEqual(
      golden.protect_secret_threshold,
    );
  });

  it('protect_secret params treat a null threshold as no threshold', () => {
    const input = { ...goldenProtectSecretInput(), threshold: null as unknown as number };
    expect(buildProtectSecretParams(input)).toEqual(golden.protect_secret);
  });

  it('restore params omit the threshold when the roster records none', () => {
    const input = goldenRestoreInput();
    delete input.threshold;
    const params = buildRestoreParams(input, 7) as { recovered_secret: Record<string, unknown> };
    expect(params.recovered_secret).not.toHaveProperty('threshold');
  });

  it('protect_secret params treat null weights as no weights', () => {
    const input = { ...goldenProtectSecretInput(), weights: null as unknown as Map<bigint, number> };
    expect(buildProtectSecretParams(input)).toEqual(golden.protect_secret);
  });

  it('restore params match the shared fixture', () => {
    expect(buildRestoreParams(goldenRestoreInput(), 7)).toEqual(golden.restore);
  });

  it('restore params treat null communication_info as omitted, same as absent or empty', () => {
    const input = goldenRestoreInput();
    input.helpers[0].communication_info = null as unknown as Record<string, string>;
    input.replicas!.members[0].communication_info = null as unknown as Record<string, string>;
    const params = buildRestoreParams(input, 7) as {
      recovered_secret: {
        helpers: Array<Record<string, unknown>>;
        replicas: { members: Array<Record<string, unknown>> };
      };
    };
    expect(params.recovered_secret.helpers[0]).not.toHaveProperty('communication_info');
    expect(params.recovered_secret.replicas.members[0]).not.toHaveProperty('communication_info');
  });

  // A section added to the fixture with no assertion here would leave this
  // SDK's params builder for it unchecked.
  it('covers every fixture section', () => {
    const covered = ['protect_secret', 'protect_secret_threshold', 'protect_secret_weighted', 'restore'];
    const sections = Object.keys(golden).filter((k) => !k.startsWith('$')).sort();
    expect(sections).toEqual(covered);
  });
});
