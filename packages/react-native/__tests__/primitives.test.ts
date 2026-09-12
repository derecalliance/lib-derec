import { primitives } from '../src/primitives';
import { MessageKind } from '../src/messages';

interface HostCall {
  name: string;
  args: unknown[];
}

let calls: HostCall[] = [];

/**
 * Replies for the host functions that return a structured object rather than
 * a buffer. Keyed by host-function name; anything absent returns an empty
 * `ArrayBuffer`, which is what the buffer-returning entry points hand back.
 */
let replies: Record<string, unknown> = {};

/** JSON a `decode_message_json` call should hand back, per invocation order. */
let decodedMessages: unknown[] = [];

function utf8(text: string): Uint8Array {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) {
    out[i] = text.charCodeAt(i);
  }
  return out;
}

beforeEach(() => {
  calls = [];
  replies = {};
  decodedMessages = [];
  // @ts-expect-error test-only global
  globalThis.__DeRec = new Proxy(
    {},
    {
      get:
        (_target, name: string) =>
        (...args: unknown[]) => {
          calls.push({ name, args });
          if (name === 'decode_message_json') {
            const next = decodedMessages.shift() ?? {};
            return utf8(JSON.stringify(next)).buffer;
          }
          if (name === 'encode_message_json' || name === 'encode_contact_message') {
            return new Uint8Array([0xaa]).buffer;
          }
          if (name in replies) {
            return replies[name];
          }
          return new Uint8Array(0).buffer;
        },
    },
  );
});

afterEach(() => {
  // @ts-expect-error test-only global
  delete globalThis.__DeRec;
});

const find = (name: string): HostCall =>
  calls.find((c) => c.name === name) ?? (() => { throw new Error(`no call to ${name}`); })();

describe('namespace parity with @derec-alliance/nodejs', () => {
  it('exposes the same top-level groups', () => {
    expect(Object.keys(primitives).sort()).toEqual(
      ['discovery', 'pairing', 'recovery', 'sharing', 'unpairing', 'verification'].sort(),
    );
  });

  it('exposes the same pairing.request keys', () => {
    expect(Object.keys(primitives.pairing.request).sort()).toEqual(
      [
        'create_contact',
        'encode_contact',
        'decode_contact',
        'produce',
        'extract',
        'produce_pre_pair',
        'extract_pre_pair',
      ].sort(),
    );
  });
});

describe('message marshalling', () => {
  // The bug this guards against: an `extract` that returned the raw
  // `{ channel_id, request_proto_bytes }` the C ABI produces, instead of the
  // decoded message the nodejs SDK returns. Routing-only assertions could not
  // see the difference.
  it('decodes an extracted request rather than returning wire bytes', () => {
    replies.extract_pair_request = { request_proto_bytes: new Uint8Array([1, 2]).buffer };
    decodedMessages = [
      { sender_kind: 0, nonce: '42', mlkem_ciphertext: [7], ecies_public_key: [8] },
    ];

    const { request } = primitives.pairing.request.extract(
      new Uint8Array([9]),
      new Uint8Array(32),
    );

    expect(find('decode_message_json').args[0]).toBe(MessageKind.PairRequest);
    expect(request.nonce).toBe(42n);
    expect(request.mlkem_ciphertext).toBeInstanceOf(Uint8Array);
    expect(Array.from(request.mlkem_ciphertext)).toEqual([7]);
    // `request_proto_bytes` is an implementation detail of the C ABI and must
    // not leak into the typed surface.
    expect((request as unknown as Record<string, unknown>).request_proto_bytes).toBeUndefined();
  });

  it('selects the right message kind for each extract', () => {
    replies.extract_verify_share_response = { response_proto_bytes: new Uint8Array().buffer };
    decodedMessages = [{ secret_id: '1', version: 1, nonce: '2', hash: [] }];
    primitives.verification.response.extract(new Uint8Array(), new Uint8Array(32));
    expect(find('decode_message_json').args[0]).toBe(MessageKind.VerifyShareResponse);
  });

  it('encodes an outbound message before handing it to the host', () => {
    primitives.sharing.response.process(3, {
      version: 3,
      secret_id: 5n,
      timestamp: undefined,
    } as never);
    expect(find('encode_message_json').args[0]).toBe(MessageKind.StoreShareResponse);
    expect(find('process_store_share_response_message').args[0]).toBe(3);
  });

  it('sends an empty buffer for an absent reply_to', () => {
    primitives.discovery.request.produce(1n, new Uint8Array(32));
    const replyTo = find('produce_get_secret_ids_versions_request_message')
      .args[2] as Uint8Array;
    expect(replyTo).toBeInstanceOf(Uint8Array);
    expect(replyTo.length).toBe(0);
    // No encode call for an absent optional — the C ABI reads zero length as
    // "no override", so nothing is synthesized here.
    expect(calls.some((c) => c.name === 'encode_message_json')).toBe(false);
  });

  it('encodes a present reply_to as a framed TransportProtocol list', () => {
    primitives.discovery.request.produce(1n, new Uint8Array(32), [
      { uri: 'https://x.example', protocol: 0 },
      { uri: 'grpcs://x.example:443', protocol: 1 },
    ]);
    const encoded = calls.filter((c) => c.name === 'encode_message_json');
    // One encode per entry: the list is framed, not a single message.
    expect(encoded).toHaveLength(2);
    expect(encoded[0]!.args[0]).toBe(MessageKind.TransportProtocol);
    expect(encoded[1]!.args[0]).toBe(MessageKind.TransportProtocol);
  });
});

describe('contact codec', () => {
  // The contact keeps its own entry points because they also enforce the
  // mode/field invariant; going through the generic codec would skip that.
  it('routes to the dedicated contact entry points', () => {
    primitives.pairing.request.encode_contact({
      channel_id: 1n,
      contact_mode: 0,
      nonce: 2n,
    } as never);
    expect(find('encode_contact_message')).toBeDefined();
    expect(calls.some((c) => c.name === 'encode_message_json')).toBe(false);
  });
});
