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
 * @fileoverview EcCommutativeCipher library.
 *
 * This library is not thread-safe.
 */

import {EcCommutativeCipherImpl} from './ec_commutative_cipher_impl';



/**
 * The hash function used by the ECCommutativeCipher in order to hash strings
 * to EC curve points.
 */
export enum HashType {
  SHA256,
  SHA384,
  SHA512,
}

/**
 * EcCommutativeCipher library responsible for encryption and decryption.
 */
  export class EcCommutativeCipher {
  /**
   * Initializes client.
   */
  private constructor(
      private readonly crypto: EcCommutativeCipherImpl,
      private readonly ecCipher: number) {
  }

  static create(
      crypto: EcCommutativeCipherImpl, curveId: number,
      hashType: number): EcCommutativeCipher {
    const ecCipher = crypto.createWithNewKey(curveId, hashType);
    if (ecCipher <= 0) {
      throw new Error('Failed to create WASM-wrapped EcCommutativeCipher.');
    }
    return new EcCommutativeCipher(crypto, ecCipher);
  }

  static createFromKey(
      crypto: EcCommutativeCipherImpl, curveId: number, hashType: number,
      key: Uint8Array): EcCommutativeCipher {
    const ecCipher = crypto.createFromKey(curveId, hashType, key);
    if (ecCipher <= 0) {
      throw new Error(
          'Failed to create WASM-wrapped EcCommutativeCipher from key.');
    }
    return new EcCommutativeCipher(crypto, ecCipher);
  }

  encrypt(plaintext: Uint8Array): Uint8Array {
    return this.crypto.encrypt(this.ecCipher, plaintext);
  }

  decrypt(ciphertext: Uint8Array): Uint8Array {
    return this.crypto.decrypt(this.ecCipher, ciphertext);
  }

  reencrypt(ciphertext: Uint8Array): Uint8Array {
    return this.crypto.reencrypt(this.ecCipher, ciphertext);
  }

  hashToTheCurve(input: Uint8Array): Uint8Array {
    return this.crypto.hashToTheCurve(this.ecCipher, input);
  }
}
