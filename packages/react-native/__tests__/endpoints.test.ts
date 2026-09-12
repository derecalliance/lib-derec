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
  it('prefers the offer list, preserving the peer order', () => {
    expect(
      advertisedEndpoints({ supported_transports: [grpcs, https] }),
    ).toEqual([grpcs, https]);
  });

  it('falls back to the singular field when the offer list is empty', () => {
    expect(
      advertisedEndpoints({ transport_protocol: https, supported_transports: [] }),
    ).toEqual([https]);
  });

  it('reads a peer that sends only the singular field', () => {
    expect(advertisedEndpoints({ transport_protocol: https })).toEqual([https]);
  });

  it('reads a peer that sends only the offer list', () => {
    expect(advertisedEndpoints({ supported_transports: [grpcs] })).toEqual([
      grpcs,
    ]);
  });

  it('ignores the singular field when both are present', () => {
    expect(
      advertisedEndpoints({
        transport_protocol: https,
        supported_transports: [grpcs],
      }),
    ).toEqual([grpcs]);
  });

  it('yields nothing rather than a placeholder when neither is present', () => {
    expect(advertisedEndpoints({})).toEqual([]);
    expect(advertisedEndpoints(null)).toEqual([]);
    expect(advertisedEndpoints(undefined)).toEqual([]);
  });
});
