import { getNative } from '../src/native';

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
    globalThis.__DeRec = { version: () => '0.0.1-alpha.10' };
    expect(getNative().version()).toBe('0.0.1-alpha.10');
  });
});
