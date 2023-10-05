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

import {EcCommutativeCipher, HashType} from './emscripten/ec_commutative_cipher';
import {EcCommutativeCipherImpl} from './emscripten/ec_commutative_cipher_impl';
import {createHash} from 'node:crypto';

import {CryptoHelper} from './utils/crypto_helper';
import {PasswordCheckResult} from './password_check_result';


/**
 * PasswordCheckVerification
 */
export class PasswordCheckVerification {
  // Use NID_X9_62_prime256v1 (secp256r1) curve
  static readonly CURVE_ID = 415;

  // SHA256 is used for compatibility with the server and other libraries.
  static readonly HASH_TYPE = HashType.SHA256;

  static readonly USERNAME_HASH_PREFIX_LENGTH = 26;

  static readonly crypto: Promise<EcCommutativeCipherImpl> =
      EcCommutativeCipherImpl.createEcCommutativeCipherImpl();

  /**
   * Private constructor. Use PasswordCheckVerification.create to build a new
   * instance.
   */
  private constructor(
      private readonly ecCipher: EcCommutativeCipher,
      private readonly username: string,
      private readonly encryptedUserCredentialsHash: Uint8Array,
      private readonly lookupHashPrefix: Uint8Array) {}

  /**
   * Creates a new PasswordCheckVerification instance. The instance should not
   * be reused to avoid using the same cipher for more than one password leak
   * check.
   */
  static async create(username: string, password: string) {
    if (username == null || username.length === 0) {
      throw new Error('Username cannot be null or empty');
    }
    if (password == null || password.length === 0) {
      throw new Error('Password cannot be null or empty');
    }
    const ecCipher = await PasswordCheckVerification.initEcCipher();
    const canonicalizedUsername = CryptoHelper.canonicalizeUsername(username);

    const hashedUsernamePasswordPair =
        await CryptoHelper.hashUsernamePasswordPair(
            canonicalizedUsername, password);
    const encryptedUserCredentialsHash =
        ecCipher.encrypt(hashedUsernamePasswordPair);
    const lookupHashPrefix = CryptoHelper.bucketizeUsername(
        canonicalizedUsername,
        PasswordCheckVerification.USERNAME_HASH_PREFIX_LENGTH);

    return new PasswordCheckVerification(
        ecCipher, username, encryptedUserCredentialsHash, lookupHashPrefix);
  }

  /**
   * Checks whether or not a leak was found for this password check
   */
  verify(
      reEncryptedUserCredentialsHash: Uint8Array,
      encryptedLeakMatchPrefixList: Uint8Array[]): PasswordCheckResult {
    if (reEncryptedUserCredentialsHash == null ||
        reEncryptedUserCredentialsHash.length === 0) {
      throw new Error('reEncryptedLookupHash must be present');
    }

    if (encryptedLeakMatchPrefixList == null) {
      throw new Error('encryptedLeakMatchPrefixList cannot be null');
    }

    const serverEncryptedCredentialsHash =
        this.ecCipher.decrypt(reEncryptedUserCredentialsHash);
    const reHashedEncryptedCredentialsHash =
        createHash('sha256').update(serverEncryptedCredentialsHash).digest();

    const credentialsLeaked = encryptedLeakMatchPrefixList.some(
        (prefix) => this.isPrefix(reHashedEncryptedCredentialsHash, prefix));

    return new PasswordCheckResult(this, this.username, credentialsLeaked);
  }

  getUsername(): string {
    return this.username;
  }

  getEncryptedUserCredentialsHash(): Uint8Array {
    return this.encryptedUserCredentialsHash;
  }

  getLookupHashPrefix(): Uint8Array {
    return this.lookupHashPrefix;
  }

  /**
   * Creates a new EcCommutativeCipher to be used for this password check
   * verification.
   */
  private static async initEcCipher(): Promise<EcCommutativeCipher> {
    const crypto = await PasswordCheckVerification.crypto;
    return EcCommutativeCipher.create(
        crypto, PasswordCheckVerification.CURVE_ID,
        PasswordCheckVerification.HASH_TYPE);
  }

  /**
   * Determines if the given prefix matches with the encrypted credentials
   * hash.
   */
  private isPrefix(
      reHashedEncryptedCredentialsHash: Uint8Array,
      prefix: Uint8Array): boolean {
    for (let i = 0; i < prefix.length; i++) {
      if (prefix[i] !== reHashedEncryptedCredentialsHash[i]) {
        return false;
      }
    }
    return true;
  }
}
