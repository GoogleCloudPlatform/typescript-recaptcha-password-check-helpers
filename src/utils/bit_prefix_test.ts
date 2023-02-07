import 'jasmine';

import {BitPrefix} from './bit_prefix';

/**
 * These tests were built based on
 * google3/javatests/com/google/identity/passwords/leak/check/common/opensource/BitPrefixTest.java
 * to keep compatibility across versions.
 */

describe('bit prefix', () => {
  it('handles multiple bytes', () => {
    const prefix = BitPrefix.of(Uint8Array.of(0b11111111, 0b01010101), 9);
    expect(prefix.length).toBe(9);
    expect(prefix.toString()).toBe('0b111111110');
  });

  it('handles byte boundary', () => {
    const prefix = BitPrefix.of(Uint8Array.of(0b11111111, 0b01010101), 8);
    expect(prefix.length).toBe(8);
    expect(prefix.toString()).toBe('0b11111111');
  });

  it('handles leading zeros', () => {
    const prefix = BitPrefix.of(Uint8Array.of(0b00000000, 0b01010101), 9);
    expect(prefix.length).toBe(9);
    expect(prefix.toString()).toBe('0b000000000');
  });

  it('handles leading zeros when array size is 1', () => {
    const prefix = BitPrefix.of(Uint8Array.of(0b00000010), 7);
    expect(prefix.length).toBe(7);
    expect(prefix.toString()).toBe('0b0000001');
  });

  it('handles single bit prefix', () => {
    const prefix = BitPrefix.of(Uint8Array.of(0b11111111), 1);
    expect(prefix.length).toBe(1);
    expect(prefix.toString()).toBe('0b1');
  });

  it('masks properly the last byte', () => {
    const prefix = BitPrefix.of(Uint8Array.of(0xce, 0x8c, 0x59, 0xdf), 26);
    expect(prefix.prefix.reduce((a, b) => a += b.toString(16), ''))
        .toBe('ce8c59c0');
  });

  it('masks properly the last byte with short prefix', () => {
    const prefix = BitPrefix.of(Uint8Array.of(0xce, 0x8c, 0x59, 0xdf), 12);
    expect(prefix.prefix.reduce((a, b) => a += b.toString(16), ''))
        .toBe('ce80');
  });

  it('throws error when empty bytes', () => {
    expect(() => {
      BitPrefix.of(new Uint8Array(0), 1);
    }).toThrowError('Invalid length of bytes array');
  });
});