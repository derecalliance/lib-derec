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
      null,
    );

    expect(find('decode_message_json').args[0]).toBe(MessageKind.PairRequest);
    expect(request.nonce).toBe(42n);
    expect(request.mlkem_ciphertext).toBeInstanceOf(Uint8Array);
    expect(Array.from(request.mlkem_ciphertext)).toEqual([7]);
    // `request_proto_bytes` is an implementation detail of the C ABI and must
    // not leak into the typed surface.
    expect((request as unknown as Record<string, unknown>).request_proto_bytes).toBeUndefined();
  });

  // Parameter-range compatibility is decided in the core; the binding only
  // forwards the caller's range, and an absent one as an empty buffer.
  it('forwards the local parameter range to extract and process', () => {
    const range = {
      min_share_size: 1n,
      max_share_size: 2n,
      min_time_between_verifications: 0n,
      max_time_between_verifications: 0n,
      min_time_between_share_updates: 0n,
      max_time_between_share_updates: 0n,
      min_unresponsive_deletion_timeout: 0n,
      max_unresponsive_deletion_timeout: 0n,
      min_unresponsive_deactivation_timeout: 0n,
      max_unresponsive_deactivation_timeout: 0n,
    };
    replies.extract_pair_request = { request_proto_bytes: new Uint8Array().buffer };
    replies.process_pair_response_message = {
      shared_key: new Uint8Array(32).buffer,
      channel_id: 1n,
    };

    primitives.pairing.request.extract(new Uint8Array([9]), new Uint8Array(32), range);
    const extract = find('extract_pair_request');
    expect(extract.args).toHaveLength(3);
    expect(Array.from(extract.args[2] as Uint8Array)).toEqual([0xaa]);
    expect(
      calls.some(
        (c) => c.name === 'encode_message_json' && c.args[0] === MessageKind.ParameterRange,
      ),
    ).toBe(true);

    primitives.pairing.response.process(
      { channel_id: 1n, nonce: 2n, contact_mode: 0, supported_transports: [] } as never,
      { nonce: 2n } as never,
      new Uint8Array(32),
      null,
    );
    const process = find('process_pair_response_message');
    expect(process.args).toHaveLength(4);
    expect((process.args[3] as Uint8Array).length).toBe(0);
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

describe('create_contact nonce', () => {
  // The C entry point carries `Option<u64>` as a presence flag plus a value.
  // A NoKeys contact is useless without the caller's nonce, so it has to
  // reach the host rather than be replaced by a library-generated one.
  beforeEach(() => {
    replies.create_contact_message = {
      contact_wire_bytes: new ArrayBuffer(0),
      secret_key_material: new ArrayBuffer(0),
    };
    replies.decode_contact_message = utf8(
      JSON.stringify({ channel_id: '3', contact_mode: 2, nonce: '424242' }),
    ).buffer;
  });

  it('forwards an explicit nonce with the presence flag set', () => {
    primitives.pairing.request.create_contact(3n, 2, [], 424242n);
    const { args } = find('create_contact_message');
    expect(args[3]).toBe(1);
    expect(args[4]).toBe(424242n);
  });

  it('clears the presence flag when no nonce is given', () => {
    primitives.pairing.request.create_contact(3n, 2, []);
    const { args } = find('create_contact_message');
    expect(args[3]).toBe(0);
  });

  it('clears the presence flag for a null nonce', () => {
    primitives.pairing.request.create_contact(3n, 2, [], null);
    const { args } = find('create_contact_message');
    expect(args[3]).toBe(0);
  });
});

describe('NoKeys pre-pair and fingerprint', () => {
  it('exposes the same pairing and pairing.response keys', () => {
    expect(Object.keys(primitives.pairing).sort()).toEqual(
      ['fingerprint', 'request', 'response'].sort(),
    );
    expect(Object.keys(primitives.pairing.response).sort()).toEqual(
      [
        'produce',
        'extract',
        'process',
        'produce_pre_pair',
        'extract_pre_pair',
        'process_pre_pair',
        'produce_pre_pair_no_keys',
        'process_pre_pair_no_keys',
      ].sort(),
    );
  });

  it('forwards produce_pre_pair_no_keys and surfaces both buffers', () => {
    replies.produce_pre_pair_no_keys_response_message = {
      envelope_wire_bytes: new Uint8Array([1, 2]).buffer,
      secret_key_material: new Uint8Array([3, 4, 5]).buffer,
    };
    const result = primitives.pairing.response.produce_pre_pair_no_keys(7n, {
      nonce: 9n,
    } as never);
    const { args } = find('produce_pre_pair_no_keys_response_message');
    expect(args).toHaveLength(2);
    expect(args[0]).toBe(7n);
    expect(find('encode_message_json').args[0]).toBe(MessageKind.PrePairRequest);
    expect(Array.from(result.envelope)).toEqual([1, 2]);
    expect(Array.from(result.secret_key_material)).toEqual([3, 4, 5]);
  });

  it('forwards process_pre_pair_no_keys through the contact codec', () => {
    replies.process_pre_pair_no_keys_response_message = {
      mlkem_encapsulation_key: new Uint8Array([1]).buffer,
      ecies_public_key: new Uint8Array([2]).buffer,
      nonce: 424242n,
    };
    const result = primitives.pairing.response.process_pre_pair_no_keys(
      { channel_id: 3n, contact_mode: 2, nonce: 424242n } as never,
      { nonce: 424242n } as never,
    );
    expect(find('encode_contact_message')).toBeDefined();
    expect(find('encode_message_json').args[0]).toBe(MessageKind.PrePairResponse);
    expect(find('process_pre_pair_no_keys_response_message').args).toHaveLength(2);
    expect(Array.from(result.mlkem_encapsulation_key)).toEqual([1]);
    expect(Array.from(result.ecies_public_key)).toEqual([2]);
    expect(result.nonce).toBe(424242n);
  });

  it('forwards the shared key to pairing_fingerprint and returns its string', () => {
    replies.pairing_fingerprint = 'ABCD-EFGH';
    const key = new Uint8Array(32).fill(1);
    expect(primitives.pairing.fingerprint(key)).toBe('ABCD-EFGH');
    expect(find('pairing_fingerprint').args).toEqual([key]);
  });
});
