import {
  decodeCommittedShareEntries,
  decodeSecretList,
  encodeSecretList,
  encodeShareResponses,
} from '../src/binary';
import { plainMessage, reviveMessage } from '../src/messages';

describe('wide numerics', () => {
  // The whole reason these fields cross as decimal strings: `JSON.parse`
  // silently rounds anything above 2^53, and every one of them is an
  // identifier, so a rounded value names a different channel or secret.
  it('revives id strings above 2^53 exactly', () => {
    const revived = reviveMessage({
      channel_id: '18446744073709551615',
      nonce: '9007199254740993',
      secret_id: '42',
      version: 7,
    }) as Record<string, unknown>;

    expect(revived.channel_id).toBe(18446744073709551615n);
    expect(revived.nonce).toBe(9007199254740993n);
    expect(revived.secret_id).toBe(42n);
    // `version` is a u32 and must stay a number.
    expect(revived.version).toBe(7);
  });

  it('narrows them back to the same decimal strings', () => {
    const plain = plainMessage({
      channel_id: 18446744073709551615n,
      nonce: 9007199254740993n,
    }) as Record<string, unknown>;

    expect(plain.channel_id).toBe('18446744073709551615');
    expect(plain.nonce).toBe('9007199254740993');
  });

  it('widens nested ids, not just top-level ones', () => {
    const revived = reviveMessage({
      secret_list: [{ secret_id: '18446744073709551615', versions: [{ version: 1 }] }],
    }) as { secret_list: Array<{ secret_id: bigint }> };

    expect(revived.secret_list[0].secret_id).toBe(18446744073709551615n);
  });

  it('carries ParameterRange bounds as bigint', () => {
    const revived = reviveMessage({
      parameter_range: { max_share_size: '9223372036854775807' },
    }) as { parameter_range: { max_share_size: bigint } };

    expect(revived.parameter_range.max_share_size).toBe(9223372036854775807n);
  });

  // `Timestamp.seconds` stays a JSON number on the wire but is `bigint` in the
  // typed surface, matching @derec-alliance/nodejs.
  it('converts timestamp seconds between number and bigint', () => {
    const revived = reviveMessage({ timestamp: { seconds: 1700000000, nanos: 5 } }) as {
      timestamp: { seconds: bigint; nanos: number };
    };
    expect(revived.timestamp.seconds).toBe(1700000000n);
    expect(revived.timestamp.nanos).toBe(5);

    const plain = plainMessage(revived) as { timestamp: { seconds: number } };
    expect(plain.timestamp.seconds).toBe(1700000000);
  });
});

describe('byte fields', () => {
  it('revives declared byte fields as Uint8Array', () => {
    const revived = reviveMessage({
      mlkem_ciphertext: [1, 2, 3],
      hash: [9],
    }) as Record<string, Uint8Array>;

    expect(revived.mlkem_ciphertext).toBeInstanceOf(Uint8Array);
    expect(Array.from(revived.mlkem_ciphertext)).toEqual([1, 2, 3]);
    expect(Array.from(revived.hash)).toEqual([9]);
  });

  // `keep_list` is a genuine number[]. A structural "array of numbers is
  // bytes" rule would corrupt it, which is why the conversion is name-keyed.
  it('leaves keep_list as an array of numbers', () => {
    const revived = reviveMessage({ keep_list: [1, 2, 3] }) as { keep_list: unknown };
    expect(Array.isArray(revived.keep_list)).toBe(true);
    expect(revived.keep_list).toEqual([1, 2, 3]);
  });

  it('narrows Uint8Array back to a byte array', () => {
    const plain = plainMessage({ share: Uint8Array.from([4, 5]) }) as { share: unknown };
    expect(plain.share).toEqual([4, 5]);
  });
});

describe('optional fields', () => {
  it('reads null as undefined', () => {
    const revived = reviveMessage({ timestamp: null, reply_to: null }) as Record<
      string,
      unknown
    >;
    expect(revived.timestamp).toBeUndefined();
    expect(revived.reply_to).toBeUndefined();
  });

  // Omitted rather than sent as null: serde reads a missing `Option` as
  // `None`, while an explicit null for a non-Option field fails to decode.
  it('omits undefined instead of emitting null', () => {
    const plain = plainMessage({ memo: 'x', reply_to: undefined }) as Record<string, unknown>;
    expect('reply_to' in plain).toBe(false);
    expect(plain.memo).toBe('x');
  });
});

describe('FFI container formats', () => {
  it('round-trips the discovery secret list', () => {
    const entries = [
      {
        secret_id: 18446744073709551615n,
        versions: [
          { version: 1, description: 'first' },
          { version: 2, description: '' },
        ],
      },
      { secret_id: 7n, versions: [] },
    ];

    expect(decodeSecretList(encodeSecretList(entries))).toEqual(entries);
  });

  it('encodes the secret list little-endian with a leading count', () => {
    const packed = encodeSecretList([{ secret_id: 1n, versions: [] }]);
    // [count u32][secret_id u64][versions u32]
    expect(Array.from(packed)).toEqual([
      1, 0, 0, 0, //
      1, 0, 0, 0, 0, 0, 0, 0, //
      0, 0, 0, 0,
    ]);
  });

  it('length-prefixes each recovery response', () => {
    const packed = encodeShareResponses([Uint8Array.from([1, 2]), Uint8Array.from([3])]);
    expect(Array.from(packed)).toEqual([2, 0, 0, 0, 2, 0, 0, 0, 1, 2, 1, 0, 0, 0, 3]);
  });

  it('reads the committed-share map', () => {
    const packed = Uint8Array.from([
      1, 0, 0, 0, // count
      5, 0, 0, 0, 0, 0, 0, 0, // channel_id
      2, 0, 0, 0, // share_len
      0xab, 0xcd,
    ]);
    const entries = decodeCommittedShareEntries(packed);
    expect(entries).toHaveLength(1);
    expect(entries[0].channelId).toBe(5n);
    expect(Array.from(entries[0].shareProto)).toEqual([0xab, 0xcd]);
  });

  // A truncated container means the SDK and the library disagree about the
  // format. Half a set read as a whole one would silently lose shares.
  it('rejects a truncated container instead of returning a partial set', () => {
    expect(() => decodeSecretList(Uint8Array.from([2, 0, 0, 0]))).toThrow(
      /malformed FFI container/,
    );
  });

  it('rejects trailing bytes after the committed-share map', () => {
    const packed = Uint8Array.from([0, 0, 0, 0, 0xff]);
    expect(() => decodeCommittedShareEntries(packed)).toThrow(/trailing bytes/);
  });
});
