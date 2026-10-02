// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

import { DeRecProtocolBuilder } from '../src/protocol';
import { FlowKind } from '../src/types';
import type { DeRecEvent } from '../src/types';

let lastConfig: Record<string, unknown> | undefined;

beforeEach(() => {
  lastConfig = undefined;
  // @ts-expect-error test-only global
  globalThis.__DeRec = {
    transport_protocol_discriminant: () => 0,
    protocol_new: (configJson: string) => {
      lastConfig = JSON.parse(configJson);
      return { secretId: () => 7n };
    },
  };
});

afterEach(() => {
  // @ts-expect-error test-only global
  delete globalThis.__DeRec;
});

const stores = {
  channelStore: {},
  shareStore: {},
  secretStore: {},
  userSecretStore: {},
  stateStore: {},
  transport: {},
};

function baseBuilder() {
  return new DeRecProtocolBuilder(7n)
    .withChannelStore(stores.channelStore as never)
    .withShareStore(stores.shareStore as never)
    .withSecretStore(stores.secretStore as never)
    .withUserSecretStore(stores.userSecretStore as never)
    .withStateStore(stores.stateStore as never)
    .withTransport(stores.transport as never)
    .withOwnTransports([{ uri: 'https://example.com/derec', protocol: 'https' }]);
}

describe('DeRecProtocolBuilder', () => {
  it('sends secret_id as a decimal string', () => {
    baseBuilder().build();
    expect(lastConfig!.secret_id).toBe('7');
  });

  it('omits timeouts entirely when never configured', () => {
    baseBuilder().build();
    // Absent means "use the library default". Emitting an object here would
    // freeze defaults into the binding.
    expect(lastConfig!.timeouts).toBeUndefined();
  });

  it('forwards only the timeout fields that were set', () => {
    baseBuilder().withTimeouts({ sharing_round_secs: 42 }).build();
    expect(lastConfig!.timeouts).toEqual({ sharing_round_secs: 42 });
  });

  it('sends replica_id as null when unset', () => {
    baseBuilder().build();
    expect(lastConfig!.replica_id).toBeNull();
  });

  it('does not clamp threshold', () => {
    baseBuilder().withThreshold(0).build();
    expect(lastConfig!.threshold).toBe(0);
  });

  // F4: `ProtocolConfig` (library/src/interop/ffi/protocol/handle/mod.rs) now has a
  // `#[serde(default = "...")]` on each of these six fields, reading the same
  // constants `DeRecProtocolBuilder::new` does. This SDK must not reintroduce
  // its own copy of those defaults — omitting the key when the caller never
  // called the setter is what lets serde's default (and therefore any future
  // change to it) apply. Pinning the *absence* of the key here means a
  // regression back to hardcoding a value shows up as a failing test.
  it('omits the six Rust-defaulted keys from the config when their setters are never called', () => {
    baseBuilder().build();
    expect(lastConfig).not.toHaveProperty('threshold');
    expect(lastConfig).not.toHaveProperty('keep_versions_count');
    expect(lastConfig).not.toHaveProperty('auto_respond_on_failure');
    expect(lastConfig).not.toHaveProperty('unpair_ack');
    expect(lastConfig).not.toHaveProperty('auto_reply_to');
    expect(lastConfig).not.toHaveProperty('auto_accept');
  });

  // Complements the omission test above: a caller who *does* call the
  // setter must still see its exact value on the wire — omission only
  // applies to the unset case, never to an explicit caller-supplied value.
  it('forwards the six Rust-defaulted keys verbatim when the caller sets them', () => {
    baseBuilder()
      .withThreshold(5)
      .withKeepVersionsCount(7)
      .withAutoRespondOnFailure(true)
      .withUnpairAck('not_required')
      .withAutoReplyTo(true)
      .withAutoAccept({ pairing: true })
      .build();
    expect(lastConfig!.threshold).toBe(5);
    expect(lastConfig!.keep_versions_count).toBe(7);
    expect(lastConfig!.auto_respond_on_failure).toBe(true);
    expect(lastConfig!.unpair_ack).toBe('not_required');
    expect(lastConfig!.auto_reply_to).toBe(true);
    // Only the named flow crosses; the library defaults every other one.
    expect(lastConfig!.auto_accept).toEqual({ pairing: true });
  });

  it('forwards an explicit false auto-accept flow verbatim', () => {
    baseBuilder().withAutoAccept({ unpair: false, discovery: true }).build();
    expect(lastConfig!.auto_accept).toEqual({ unpair: false, discovery: true });
  });

  it('carries communication_info in the construction config', () => {
    let setterCalls = 0;
    // @ts-expect-error test-only global
    globalThis.__DeRec.protocol_new = (configJson: string) => {
      lastConfig = JSON.parse(configJson);
      return {
        secretId: () => 7n,
        setCommunicationInfo: async () => {
          setterCalls += 1;
        },
      };
    };
    baseBuilder().withCommunicationInfo({ name: 'alice' }).build();
    expect(lastConfig!.communication_info).toEqual({ name: 'alice' });
    expect(setterCalls).toBe(0);
  });

  it('omits communication_info when never configured', () => {
    baseBuilder().build();
    expect(lastConfig).not.toHaveProperty('communication_info');
  });

  it('sends parameter-range bounds as exact decimal strings', () => {
    baseBuilder()
      .withParameterRange({
        min_share_size: 9007199254740993n,
        max_unresponsive_deactivation_timeout: -9223372036854775808n,
      })
      .build();
    // Bounds not supplied are absent, so the library's default applies.
    expect(lastConfig!.parameter_range).toEqual({
      min_share_size: '9007199254740993',
      max_unresponsive_deactivation_timeout: '-9223372036854775808',
    });
  });

  // An unrecognized value must reach the library unchanged, so the library
  // refuses it instead of the wrapper reinterpreting it.
  it('withUnpairAck forwards an unrecognized value verbatim', () => {
    baseBuilder().withUnpairAck('bogus' as never).build();
    expect(lastConfig!.unpair_ack).toBe('bogus');
  });
});

// A transport protocol crosses by name, as given. Rust maps the name and
// rejects one it does not recognise; nothing here translates or checks it.
describe('own transports protocol names', () => {
  let setOwnTransportsWire: unknown;

  beforeEach(() => {
    lastConfig = undefined;
    setOwnTransportsWire = undefined;
    // @ts-expect-error test-only global
    globalThis.__DeRec = {
      protocol_new: (configJson: string) => {
        lastConfig = JSON.parse(configJson);
        const protocol = (lastConfig!.own_transports as { protocol: string }[])[0].protocol;
        if (protocol === 'bogus') {
          throw new Error('transport_invalid: unknown transport protocol "bogus"');
        }
        return {
          setOwnTransports: async (bytes: Uint8Array) => {
            setOwnTransportsWire = JSON.parse(String.fromCharCode(...Array.from(bytes)));
            const entries = setOwnTransportsWire as { protocol: string }[];
            if (entries.some((e) => e.protocol === 'bogus')) {
              throw new Error('transport_invalid: unknown transport protocol "bogus"');
            }
          },
        };
      },
    };
  });

  function builderWith(protocol: string) {
    return new DeRecProtocolBuilder(7n)
      .withChannelStore(stores.channelStore as never)
      .withShareStore(stores.shareStore as never)
      .withSecretStore(stores.secretStore as never)
      .withUserSecretStore(stores.userSecretStore as never)
      .withStateStore(stores.stateStore as never)
      .withTransport(stores.transport as never)
      .withOwnTransports([{ uri: 'grpcs://example.com:443', protocol: protocol as never }]);
  }

  it('withOwnTransports forwards the protocol name verbatim', () => {
    builderWith('grpc').build();
    expect(lastConfig!.own_transports).toEqual([
      { uri: 'grpcs://example.com:443', protocol: 'grpc' },
    ]);
  });

  it('withOwnTransports forwards an unknown name to Rust, which rejects it', () => {
    expect(() => builderWith('bogus').build()).toThrow(/transport_invalid/);
    expect(lastConfig!.own_transports).toEqual([
      { uri: 'grpcs://example.com:443', protocol: 'bogus' },
    ]);
  });

  it('setOwnTransports forwards the protocol name verbatim', async () => {
    const protocol = builderWith('grpc').build();
    await protocol.setOwnTransports([{ uri: 'grpcs://example.com:443', protocol: 'grpc' }]);
    expect(setOwnTransportsWire).toEqual([{ uri: 'grpcs://example.com:443', protocol: 'grpc' }]);
  });

  it('setOwnTransports forwards an unknown name to Rust, which rejects it', async () => {
    const protocol = builderWith('grpc').build();
    await expect(
      protocol.setOwnTransports([{ uri: 'grpcs://example.com:443', protocol: 'bogus' as never }]),
    ).rejects.toThrow(/transport_invalid/);
    expect(setOwnTransportsWire).toEqual([{ uri: 'grpcs://example.com:443', protocol: 'bogus' }]);
  });
});

// F1: `PairingParams.contact` is typed `ContactMessage`, and `createContact()`
// resolves to one, so the natural call below type-checks without a cast. It
// could not before `encode_contact_message` / `decode_contact_message` existed
// in the FFI: `createContact()` returned raw wire bytes, and this SDK had no
// codec to turn them into a `ContactMessage`. Reverting either side of that
// pair — `createContact`'s return type or `PairingParams.contact` — makes
// `tsc --noEmit` fail on the `protocol.start(FlowKind.Pairing, ...)` call this
// test makes.
describe('start(FlowKind.Pairing, ...) with createContact() output', () => {
  const CONTACT_WIRE = [9, 8, 7];
  // The JSON shape `decode_contact_message` emits: `channel_id`/`nonce` as
  // decimal strings, byte fields as arrays of byte values.
  const CONTACT_JSON = {
    channel_id: '18446744073709551615',
    contact_mode: 0,
    nonce: '9007199254740993',
    mlkem_encapsulation_key: [1, 2, 3],
    ecies_public_key: [4, 5, 6],
    timestamp: { seconds: 1700000000, nanos: 42 },
    supported_transports: [{ uri: 'https://example.com/derec', protocol: 0 }],
  };

  function asciiToBuffer(text: string): ArrayBuffer {
    return Uint8Array.from(Array.from(text, (c) => c.charCodeAt(0))).buffer;
  }
  function bufferToAscii(buffer: Uint8Array): string {
    return String.fromCharCode(...Array.from(buffer));
  }

  let capturedParams: Record<string, unknown> | undefined;
  let encodedContactJson: Record<string, unknown> | undefined;

  beforeEach(() => {
    capturedParams = undefined;
    encodedContactJson = undefined;
    // @ts-expect-error test-only global
    globalThis.__DeRec = {
      transport_protocol_discriminant: () => 0,
      decode_contact_message: (bytes: Uint8Array) => {
        expect(Array.from(bytes)).toEqual(CONTACT_WIRE);
        return asciiToBuffer(JSON.stringify(CONTACT_JSON));
      },
      encode_contact_message: (jsonBytes: Uint8Array) => {
        encodedContactJson = JSON.parse(bufferToAscii(jsonBytes)) as Record<string, unknown>;
        return Uint8Array.from(CONTACT_WIRE).buffer;
      },
      protocol_new: () => ({
        createContact: async () => Uint8Array.from(CONTACT_WIRE).buffer,
        start: async (_flowKind: number, paramsBytes: Uint8Array) => {
          capturedParams = JSON.parse(bufferToAscii(paramsBytes)) as Record<string, unknown>;
          return asciiToBuffer('[]');
        },
      }),
    };
  });

  it('accepts the exact value createContact() resolves to, with no cast', async () => {
    const protocol = baseBuilder().build();
    const contact = await protocol.createContact(null, 0);
    const events = await protocol.start(FlowKind.Pairing, { kind: 0, contact });

    expect(events).toEqual([]);
    expect(capturedParams).toEqual({ kind: 0, contact: CONTACT_WIRE });
  });

  // The parity assertion: the object an application sees must match
  // `ContactMessage` in `@derec-alliance/nodejs`'s `index.d.ts` — `bigint`
  // identifiers and `Uint8Array` byte fields, not the decimal strings and
  // number arrays the JSON seam carries.
  it('decodes into the nodejs-shaped ContactMessage', async () => {
    const protocol = baseBuilder().build();
    const contact = await protocol.createContact(null, 0);

    expect(contact.channel_id).toBe(18446744073709551615n);
    expect(contact.nonce).toBe(9007199254740993n);
    expect(contact.contact_mode).toBe(0);
    expect(contact.supported_transports).toEqual([
      { uri: 'https://example.com/derec', protocol: 0 },
    ]);
    expect(contact.mlkem_encapsulation_key).toBeInstanceOf(Uint8Array);
    expect(Array.from(contact.mlkem_encapsulation_key!)).toEqual([1, 2, 3]);
    expect(contact.ecies_public_key).toBeInstanceOf(Uint8Array);
    expect(Array.from(contact.ecies_public_key!)).toEqual([4, 5, 6]);
    expect(contact.contact_binding_hash).toBeUndefined();
    expect(contact.timestamp).toEqual({ seconds: 1700000000n, nanos: 42 });
  });

  // Round trip: what `start` hands the encoder must be the JSON shape the
  // decoder produced, so a full-width `u64` survives and the byte fields go
  // back as arrays of byte values.
  it('re-encodes the decoded contact without losing identifier precision', async () => {
    const protocol = baseBuilder().build();
    const contact = await protocol.createContact(null, 0);
    await protocol.start(FlowKind.Pairing, { kind: 0, contact });

    expect(encodedContactJson).toEqual(CONTACT_JSON);
  });
});

// A `Vec<u8>` arrives from `serde_json` as an array of decimal byte values,
// while `DeRecEvent` declares `Uint8Array`. The gap is invisible until an
// application feeds `ActionRequired.action` back to `accept()`, where the
// native layer reads `.buffer` off it and finds nothing — which is exactly
// what the on-device protocol suite hit.
describe('event byte fields', () => {
  const utf8 = (text: string): Uint8Array => {
    const out = new Uint8Array(text.length);
    for (let i = 0; i < text.length; i++) {
      out[i] = text.charCodeAt(i);
    }
    return out;
  };

  let host: Record<string, unknown>;

  const nativeHost = (): unknown =>
    (globalThis as Record<string, unknown>).__DeRec;

  beforeEach(() => {
    host = {};
    // @ts-expect-error test-only global
    globalThis.__DeRec = new Proxy(
      {},
      {get: (_t, name: string) => (...args: unknown[]) => (host[name] as Function)?.(...args)},
    );
  });

  afterEach(() => {
    // @ts-expect-error test-only global
    delete globalThis.__DeRec;
  });

  it('revives action bytes and leaves ids as decimal strings', async () => {
    const events = [
      {
        type: 'ActionRequired',
        channel_id: '18446744073709551615',
        action: [1, 2, 3],
        action_kind: 'Pairing',
      },
    ];
    host.tick = () => Promise.resolve(utf8(JSON.stringify(events)).buffer);

    const { DeRecProtocol } = await import('../src/protocol');
    const protocol = DeRecProtocol.fromHost(nativeHost() as never);
    const decoded = await protocol.tick();
    const action = decoded[0] as { action: Uint8Array; channel_id: string };

    expect(action.action).toBeInstanceOf(Uint8Array);
    expect(Array.from(action.action)).toEqual([1, 2, 3]);
    // Ids stay strings: widening them the way the message codec does would
    // break every consumer that compares them.
    expect(action.channel_id).toBe('18446744073709551615');
  });

  it('passes the ActionRequired request fields through unchanged', async () => {
    const events = [
      {
        type: 'ActionRequired',
        channel_id: '7',
        action: [1],
        action_kind: 'StoreShare',
        trace_id: '18446744073709551615',
        version: 3,
        share_secret_id: '42',
        share_size: 751,
      },
      {
        type: 'ActionRequired',
        channel_id: '7',
        action: [2],
        action_kind: 'Unpair',
        trace_id: '1',
        unpair_memo: 'decommissioning',
      },
      {
        type: 'ActionRequired',
        channel_id: '7',
        action: [3],
        action_kind: 'UpdateChannelInfo',
        trace_id: '2',
        updated_communication_info: {id: 'x', data: 'y'},
        updated_transports: [{uri: 'https://new.example.com', protocol: 0}],
      },
    ];
    host.tick = () => Promise.resolve(utf8(JSON.stringify(events)).buffer);

    const { DeRecProtocol } = await import('../src/protocol');
    const protocol = DeRecProtocol.fromHost(nativeHost() as never);
    const decoded = (await protocol.tick()) as Array<
      Extract<DeRecEvent, {type: 'ActionRequired'}>
    >;

    expect(decoded[0].trace_id).toBe('18446744073709551615');
    expect(decoded[0].share_size).toBe(751);
    expect(decoded[0].share_secret_id).toBe('42');
    expect(decoded[1].unpair_memo).toBe('decommissioning');
    expect(decoded[2].updated_communication_info).toEqual({id: 'x', data: 'y'});
    expect(decoded[2].updated_transports).toEqual([
      {uri: 'https://new.example.com', protocol: 0},
    ]);
  });

  it('revives nested secret bytes in a recovery event', async () => {
    const events = [
      {
        type: 'SecretRecovered',
        secret: {
          helpers: [{channel_id: '1', transports: [{ uri: 'x', protocol: 0 }], shared_key: [9], communication_info: {}}],
          secrets: [{id: [1], name: 'n', data: [2, 3]}],
        },
      },
    ];
    host.tick = () => Promise.resolve(utf8(JSON.stringify(events)).buffer);

    const { DeRecProtocol } = await import('../src/protocol');
    const protocol = DeRecProtocol.fromHost(nativeHost() as never);
    const decoded = await protocol.tick();
    const recovered = decoded[0] as {
      secret: {
        helpers: Array<{shared_key: Uint8Array}>;
        secrets: Array<{id: Uint8Array; data: Uint8Array}>;
      };
    };

    expect(recovered.secret.helpers[0].shared_key).toBeInstanceOf(Uint8Array);
    expect(recovered.secret.secrets[0].id).toBeInstanceOf(Uint8Array);
    expect(Array.from(recovered.secret.secrets[0].data)).toEqual([2, 3]);
  });

  it('passes PeerNotRestored from restore through unchanged', async () => {
    const events = [
      {type: 'PeerNotRestored', channel_id: '18446744073709551615', reason: 'NoTransports'},
      {
        type: 'PeerNotRestored',
        channel_id: '21',
        replica_id: '18446744073709551615',
        reason: 'NoTransports',
      },
    ];
    let sent: unknown;
    host.restore = (params: Uint8Array) => {
      sent = JSON.parse(String.fromCharCode(...Array.from(params)));
      return Promise.resolve(utf8(JSON.stringify(events)).buffer);
    };

    const { DeRecProtocol } = await import('../src/protocol');
    const protocol = DeRecProtocol.fromHost(nativeHost() as never);
    const decoded = (await protocol.restore(
      {
        helpers: [{channel_id: '18446744073709551615', transports: [], shared_key: new Uint8Array([1])}],
        secrets: [],
      },
      1,
    )) as Array<Extract<DeRecEvent, {type: 'PeerNotRestored'}>>;

    // An empty endpoint list is Rust's to judge; the shim forwards it as is.
    expect((sent as {recovered_secret: {helpers: Array<{transports: unknown}>}})
      .recovered_secret.helpers[0].transports).toEqual([]);
    expect(decoded[0]).toEqual(events[0]);
    expect(decoded[0].replica_id).toBeUndefined();
    expect(decoded[1].channel_id).toBe('21');
    expect(decoded[1].replica_id).toBe('18446744073709551615');
    expect(decoded[1].reason).toBe('NoTransports');
  });
});
