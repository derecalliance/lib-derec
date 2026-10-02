import { getNative } from '../src/native';
import { generate_replica_id, protocol_version } from '../src';

describe('native host object', () => {
  afterEach(() => {
    // @ts-expect-error test-only global
    delete globalThis.__DeRec;
  });

  it('throws a clear error when the host object is absent', () => {
    expect(() => getNative()).toThrow(
      /DeRec native module is not installed/,
    );
  });

  it('returns the host object once installed', () => {
    // @ts-expect-error test-only global
    globalThis.__DeRec = { version: () => ({ major: 0, minor: 0 }) };
    expect(getNative().version()).toEqual({ major: 0, minor: 0 });
  });

  // The host reports the core's protocol version as two numbers; the package
  // entry hands them through unchanged, with no parsing or formatting here.
  it('protocol_version forwards the host major/minor', () => {
    // @ts-expect-error test-only global
    globalThis.__DeRec = { version: () => ({ major: 3, minor: 7 }) };
    expect(protocol_version()).toEqual({ major: 3, minor: 7 });
  });

  it('generate_replica_id forwards the host bigint', () => {
    // @ts-expect-error test-only global
    globalThis.__DeRec = { generate_replica_id: () => 0x1234_5678_9abc_def0n };
    expect(generate_replica_id()).toBe(0x1234_5678_9abc_def0n);
  });
});
