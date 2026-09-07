// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

import { DeRecProtocolBuilder } from '../src/protocol';
import { FlowKind } from '../src/types';

let lastConfig: Record<string, unknown> | undefined;

beforeEach(() => {
  lastConfig = undefined;
  // @ts-expect-error test-only global
  globalThis.__DeRec = {
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
    .withOwnTransport({ uri: 'https://example.com/derec', protocol: 'https' });
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
    expect(lastConfig!.unpair_ack).toBe(1);
    expect(lastConfig!.auto_reply_to).toBe(true);
    expect(lastConfig!.auto_accept).toEqual({
      pairing: true,
      pre_pair: false,
      store_share: false,
      verify_share: false,
      discovery: false,
      get_share: false,
      unpair: false,
      update_channel_info: false,
    });
  });

  // F6: an unrecognized value must not silently become "not required" — it
  // must throw, the same way `protocolDiscriminant` throws on an unknown
  // transport protocol name.
  it('withUnpairAck throws on a value that is neither "required" nor "not_required"', () => {
    expect(() => baseBuilder().withUnpairAck('bogus' as never)).toThrow();
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
    transport_protocol: { uri: 'https://example.com/derec', protocol: 0 },
    nonce: '9007199254740993',
    mlkem_encapsulation_key: [1, 2, 3],
    ecies_public_key: [4, 5, 6],
    timestamp: { seconds: 1700000000, nanos: 42 },
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
    expect(contact.transport_protocol).toEqual({
      uri: 'https://example.com/derec',
      protocol: 0,
    });
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
});
