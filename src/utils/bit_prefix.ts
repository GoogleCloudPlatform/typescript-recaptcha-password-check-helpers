/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

export class BitPrefix {
  private static readonly BYTE_SIZE = 8;

  private constructor(
      readonly prefix: BigInteger,  // = Uint8Array
      readonly length: number) {}

  /**
   * Takes the bit-wise prefix of `fullBytes` with length `prefixLength` in
   * bits.
   *
   * *Note*: This will treat `fullBytes` in a big-endian fashion (i.e.
   * truncate from the back).
   *
   * *Examples*:
   *
   * - fullBytes: {0b00010001, 0b10101010}, prefixLength: 12 =>
   * 0b000100011010
   * - fullBytes: {0b00010001}, prefixLength: 8 => 0b00010001
   */
  static of(fullBytes: Uint8Array, prefixLength: number): BitPrefix {
    if (prefixLength > fullBytes.length * BitPrefix.BYTE_SIZE) {
      throw new Error('Invalid length of bytes array');
    }

    const prefixBytesLength = Math.floor(
        (prefixLength + BitPrefix.BYTE_SIZE - 1) / BitPrefix.BYTE_SIZE);
    const prefix = fullBytes.subarray(0, prefixBytesLength);

    prefix[prefixBytesLength - 1] &= BitPrefix.bitMask(prefixLength);
    return new BitPrefix(prefix, prefixLength);
  }

  /** Produces binary representation of prefix. */
  toString(): string {
    if (this.length === 0) {
      return 'Empty prefix';
    }

    return this.prefix.reduce(
        (a, b, idx) => a += this.toBinaryStr(b, idx), '0b');
  }

  /**
   * Creates a bit mask for the last byte of the prefix.
   */
  private static bitMask(prefixLength: number): number {
    // The bitMask applies only for the last byte of the array. We left shift
    // the necessary amount of bits and then truncate the result to fit in one
    // byte.
    let bitMask = (1 << BitPrefix.BYTE_SIZE) - 1;

    // If the prefix is a multiple of BYTE_SIZE we should not shift but leave a
    // mask of 1s.
    if (prefixLength % BitPrefix.BYTE_SIZE !== 0) {
      bitMask <<= (BitPrefix.BYTE_SIZE - (prefixLength % BitPrefix.BYTE_SIZE));
    }

    bitMask &= 0xff;
    return bitMask;
  }

  /**
   * Produces a binary representation of the given number, conditioned to the
   * index in the prefix byte array. If it's the last index, the result will be
   * truncated to fit within the `BitArray` length.
   */
  private toBinaryStr(num: number, idx: number) {
    let result = num.toString(2);
    while (result.length < BitPrefix.BYTE_SIZE) {
      result = '0' + result;
    }

    return (idx + 1) * BitPrefix.BYTE_SIZE <= this.length ?
        result :
        result.substring(0, this.length % BitPrefix.BYTE_SIZE);
  }
}