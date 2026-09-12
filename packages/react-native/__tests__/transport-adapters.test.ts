import { sequentialFailover, singleEndpointTransport } from '../src/types';
import type { SendOne } from '../src/types';

const a = { uri: 'https://a.example', protocol: 'https' };
const b = { uri: 'https://b.example', protocol: 'https' };
const c = { uri: 'https://c.example', protocol: 'https' };

const message = new Uint8Array([1, 2, 3]);

/** Records every endpoint it was asked to dial, and refuses the ones named. */
function recorder(...refuse: string[]): { dialer: SendOne; attempted: string[] } {
  const attempted: string[] = [];
  const dialer: SendOne = async (endpoint) => {
    attempted.push(endpoint.uri);
    if (refuse.includes(endpoint.uri)) {
      throw new Error(`refused ${endpoint.uri}`);
    }
  };
  return { dialer, attempted };
}

describe('sequentialFailover', () => {
  it('stops at the first success rather than delivering twice', async () => {
    const { dialer, attempted } = recorder();
    await sequentialFailover(dialer).send([a, b], message);
    expect(attempted).toEqual([a.uri]);
  });

  it('advances past a failing endpoint', async () => {
    const { dialer, attempted } = recorder(a.uri);
    await sequentialFailover(dialer).send([a, b], message);
    expect(attempted).toEqual([a.uri, b.uri]);
  });

  it('tries the order the peer offered, not one of its own', async () => {
    const { dialer, attempted } = recorder(a.uri);
    await sequentialFailover(dialer).send([a, b, c], message);
    expect(attempted).toEqual([a.uri, b.uri]);
  });

  it('rejects only when every endpoint failed', async () => {
    const { dialer, attempted } = recorder(a.uri, b.uri);
    await expect(sequentialFailover(dialer).send([a, b], message)).rejects.toThrow();
    expect(attempted).toEqual([a.uri, b.uri]);
  });
});

describe('singleEndpointTransport', () => {
  it('uses the first endpoint and ignores the rest', async () => {
    const { dialer, attempted } = recorder();
    await singleEndpointTransport(dialer).send([a, b], message);
    expect(attempted).toEqual([a.uri]);
  });

  it('does not fall back where sequentialFailover would recover', async () => {
    const { dialer, attempted } = recorder(a.uri);
    await expect(singleEndpointTransport(dialer).send([a, b], message)).rejects.toThrow();
    expect(attempted).toEqual([a.uri]);
  });
});
