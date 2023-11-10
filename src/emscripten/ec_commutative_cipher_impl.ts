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

/**
 * g3-format-clang
 * @fileoverview Implementation of EcCommutativeCipher in TypeScript.
 */

import ecCommutativeCipher from '../../third_party/ec_commutative_cipher_wasm_loader-closurized';
import * as wasmData from './ec_commutative_cipher_wasm_wasm_embed';

// Set max allocated memory to be at most 1 KB.
const MAX_ALLOCATED_BYTES = 1000;

// Function signature for crypto operations.
type CryptoFunctions = (p1: number, p2: Uint8Array, p3: number, p4: number) =>
    number;

/**
 * Interface describing binary.
 */
declare interface CipherBinary {
  wasmBinary: Uint8Array;
  cwrap: (p1: string, p2: string|null, p3: string[]) => CryptoFunctions;
  HEAPU8: {slice: (p1: number, p2: number) => Uint8Array};
  _malloc: (p1: number) => number;
  _free: (p1: number) => undefined;
}

/**
 * Class containing all WASM-wrapped functions.
 */
export class EcCommutativeCipherImpl {
  private readonly createWithNewKeyInternal: (p1: number, p2: number) => number;

  private readonly createFromKeyInternal:
      (p1: number, p2: number, p3: number, p4: Uint8Array) => number;

  private readonly encryptInternal: CryptoFunctions;

  private readonly decryptInternal: CryptoFunctions;

  private readonly reencryptInternal: CryptoFunctions;

  private readonly hashToTheCurveInternal: CryptoFunctions;

  private readonly destroyInternal: (p1: number) => void;

  private readonly mallocInternal: (p1: number) => number;

  private readonly freeInternal: (p1: number) => void;

  private constructor(private readonly ecCommutativeCipherBinary: unknown) {
    this.createWithNewKeyInternal = (this.ecCommutativeCipherBinary as {
      wasmBinary: Uint8Array,
      cwrap: (p1: string, p2: string|null, p3: string[]) =>
          ((p1: number, p2: number) => number)
    })['cwrap']('CreateWithNewKey', 'number', ['number', 'number']);

    this.createFromKeyInternal = (this.ecCommutativeCipherBinary as {
      wasmBinary: Uint8Array,
      cwrap: (p1: string, p2: string|null, p3: string[]) =>
          ((p1: number, p2: number, p3: number, p4: Uint8Array) => number)
    })['cwrap'](
        'CreateFromKey', 'number', ['number', 'number', 'number', 'array']);

    this.encryptInternal =
        (this.ecCommutativeCipherBinary as CipherBinary)
            .cwrap(
                'Encrypt', 'number', ['number', 'array', 'number', 'number']);

    this.decryptInternal =
        (this.ecCommutativeCipherBinary as CipherBinary)
            .cwrap(
                'Decrypt', 'number', ['number', 'array', 'number', 'number']);

    this.reencryptInternal =
        (this.ecCommutativeCipherBinary as CipherBinary)
            .cwrap(
                'ReEncrypt', 'number', ['number', 'array', 'number', 'number']);

    this.hashToTheCurveInternal =
        (this.ecCommutativeCipherBinary as CipherBinary)
            .cwrap(
                'HashToTheCurve', 'number',
                ['number', 'array', 'number', 'number']);

    this.destroyInternal = (ecCommutativeCipherBinary as {
      wasmBinary: Uint8Array,
      cwrap: (p1: string, p2: string|null, p3: string[]) =>
          ((p1: number) => undefined)
    })['cwrap']('Destroy', null, ['number']);

    this.mallocInternal =
        (this.ecCommutativeCipherBinary as CipherBinary)._malloc;

    this.freeInternal = (this.ecCommutativeCipherBinary as CipherBinary)._free;
  }

  /**
   * Factory function to create crypto implementation. Promise will be resolved
   * once all dependencies are initialized.
   */
  static async createEcCommutativeCipherImpl():
      Promise<EcCommutativeCipherImpl> {
    const ecCommutativeCipherBinary = {
      wasmBinary: Buffer.from(wasmData.EC_COMMUTATIVE_CIPHER_BASE64,
      'base64')
    };

    if (typeof ecCommutativeCipher !== 'function') {
      throw new Error('WASM loader is not a function.');
    }
    return new EcCommutativeCipherImpl(
        await ecCommutativeCipher(ecCommutativeCipherBinary));
  }

  createWithNewKey(curveId: number, hashType: number): number {
    return this.createWithNewKeyInternal(curveId, hashType);
  }

  createFromKey(curveId: number, hashType: number, key: Uint8Array): number {
    return this.createFromKeyInternal(curveId, hashType, key.length, key);
  }

  encrypt(ecCipher: number, plaintext: Uint8Array): Uint8Array {
    // Allocate on heap.
    const bufPtr = this.mallocInternal(MAX_ALLOCATED_BYTES);

    const numBytes =
        this.encryptInternal(plaintext.length, plaintext, ecCipher, bufPtr);
    const encryption = (this.ecCommutativeCipherBinary as CipherBinary)
                           .HEAPU8.slice(bufPtr, bufPtr + numBytes);

    // Remove from heap.
    this.freeInternal(bufPtr);

    return encryption;
  }

  decrypt(ecCipher: number, ciphertext: Uint8Array): Uint8Array {
    // Allocate on heap.
    const bufPtr = this.mallocInternal(MAX_ALLOCATED_BYTES);

    const numBytes =
        this.decryptInternal(ciphertext.length, ciphertext, ecCipher, bufPtr);
    const decryption = (this.ecCommutativeCipherBinary as CipherBinary)
                           .HEAPU8.slice(bufPtr, bufPtr + numBytes);

    // Remove from heap.
    this.freeInternal(bufPtr);

    return decryption;
  }

  reencrypt(ecCipher: number, ciphertext: Uint8Array): Uint8Array {
    // Allocate on heap.
    const bufPtr = this.mallocInternal(MAX_ALLOCATED_BYTES);

    const numBytes =
        this.reencryptInternal(ciphertext.length, ciphertext, ecCipher, bufPtr);
    const encryption = (this.ecCommutativeCipherBinary as CipherBinary)
                           .HEAPU8.slice(bufPtr, bufPtr + numBytes);

    // Remove from heap.
    this.freeInternal(bufPtr);

    return encryption;
  }

  hashToTheCurve(ecCipher: number, input: Uint8Array): Uint8Array {
    // Allocate on heap.
    const bufPtr = this.mallocInternal(MAX_ALLOCATED_BYTES);

    const numBytes =
        this.hashToTheCurveInternal(input.length, input, ecCipher, bufPtr);
    const hash = (this.ecCommutativeCipherBinary as CipherBinary)
                     .HEAPU8.slice(bufPtr, bufPtr + numBytes);

    // Remove from heap.
    this.freeInternal(bufPtr);

    return hash;
  }

  destroy(ecCipher: number) {
    this.destroyInternal(ecCipher);
  }
}
