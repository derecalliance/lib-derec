import { advertisedEndpoints } from '../src/types';
import type { TransportProtocol } from '../src/types';

const https: TransportProtocol = {
  uri: 'https://peer.example.com/derec',
  protocol: 0,
};
const grpcs: TransportProtocol = {
  uri: 'grpcs://peer.example.com:443',
  protocol: 1,
};

describe('advertisedEndpoints', () => {
  it('returns the offer list, preserving the peer order', () => {
    expect(
      advertisedEndpoints({ supported_transports: [grpcs, https] }),
    ).toEqual([grpcs, https]);
  });

  it('yields nothing rather than a placeholder when the list is absent', () => {
    expect(advertisedEndpoints({})).toEqual([]);
    expect(advertisedEndpoints({ supported_transports: [] })).toEqual([]);
    expect(advertisedEndpoints(null)).toEqual([]);
    expect(advertisedEndpoints(undefined)).toEqual([]);
  });
});
