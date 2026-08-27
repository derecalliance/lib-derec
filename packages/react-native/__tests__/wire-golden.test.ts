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
        transport_uri: 'https://helper-a.example.com',
        shared_key: sharedKey1,
        communication_info: { foo: 'bar' },
      },
      {
        channel_id: '22',
        transport_uri: 'https://helper-b.example.com',
        shared_key: sharedKey2,
        communication_info: {},
      },
    ],
    secrets: goldenUserSecrets(),
    replicas: {
      channel_id: '33',
      members: [
        {
          replica_id: '44',
          transport_uri: 'https://replica-a.example.com',
          role: 'Source',
          communication_info: { baz: 'qux' },
        },
        {
          replica_id: '66',
          transport_uri: 'https://replica-b.example.com',
          role: 'Destination',
          communication_info: {},
        },
      ],
      shared_key: replicaGroupKey,
    },
  };
}

describe('wire golden vectors', () => {
  it('protect_secret params match the shared fixture', () => {
    expect(buildProtectSecretParams(goldenProtectSecretInput())).toEqual(golden.protect_secret);
  });

  it('restore params match the shared fixture', () => {
    expect(buildRestoreParams(goldenRestoreInput(), 7)).toEqual(golden.restore);
  });
});
