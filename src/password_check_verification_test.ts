import 'jasmine';

import {EcCommutativeCipher} from './emscripten/ec_commutative_cipher';
import {EcCommutativeCipherImpl} from './emscripten/ec_commutative_cipher_impl';
import {createHash} from 'node:crypto';

import {PasswordCheckVerification} from './password_check_verification';
import {CryptoHelper} from './utils/crypto_helper';

describe('password check verification test', () => {
  it('creates a password check verification', async () => {
    const verification =
        await PasswordCheckVerification.create(TEST_USERNAME, TEST_PASSWORD);
    expect(verification.getUsername()).toBe(TEST_USERNAME);
    expect(verification.getEncryptedUserCredentialsHash().length)
        .toBeGreaterThan(0);
    expect(verification.getLookupHashPrefix().length).toBeGreaterThan(0);
  });

  it('password check response is well formed', async () => {
    const verification =
        await PasswordCheckVerification.create(TEST_USERNAME, TEST_PASSWORD);
    const serverResponse = await TestServerResponse.create(
        verification, TEST_MATCHING_USERNAME_LIST);
    const passwordCheckResponse = await verification.verify(
        serverResponse.getServerReencryptedLookupHash(),
        serverResponse.getEncryptedLeakMatchPrefixTestList());

    expect(passwordCheckResponse.getUsername()).toBe(TEST_USERNAME);
    expect(passwordCheckResponse.getVerification()).toEqual(verification);
    expect(passwordCheckResponse.areCredentialsLeaked()).toBeTrue();
  });

  it('throws if username is empty', async () => {
    await expectAsync(PasswordCheckVerification.create('', TEST_PASSWORD))
        .toBeRejectedWithError('Username cannot be null or empty');
  });

  it('throws if password is empty', async () => {
    await expectAsync(PasswordCheckVerification.create(TEST_USERNAME, ''))
        .toBeRejectedWithError('Password cannot be null or empty');
  });

  it('returns leak found', async () => {
    const verification =
        await PasswordCheckVerification.create(TEST_USERNAME, TEST_PASSWORD);
    const response = await TestServerResponse.create(
        verification, TEST_MATCHING_USERNAME_LIST);
    expect(response.checkCredentialsLeaked(verification)).toBeTrue();
  });

  it('returns not leak found', async () => {
    const verification =
        await PasswordCheckVerification.create(TEST_USERNAME, TEST_PASSWORD);
    const response = await TestServerResponse.create(
        verification, TEST_NOT_MATCHING_USERNAME_LIST);
    expect(response.checkCredentialsLeaked(verification)).toBeFalse();
  });

  it('returns not leak found when empty list of prefixes is given',
     async () => {
       const verification =
           await PasswordCheckVerification.create(TEST_USERNAME, TEST_PASSWORD);
       const response = await TestServerResponse.create(verification, []);
       expect(response.checkCredentialsLeaked(verification)).toBeFalse();
     });

  it('throws exception when encrypted user credentials hash is empty',
     async () => {
       const verification =
           await PasswordCheckVerification.create(TEST_USERNAME, TEST_PASSWORD);
       expect(() => verification.verify(new Uint8Array(0), [Uint8Array.of(1)]))
           .toThrow();
     });
});

// ============= Utility classes & constants ===================

class Credentials {
  constructor(readonly username: string, readonly password: string) {}
}

class TestServerResponse {
  private constructor(
      private readonly serverReEncryptedLookupHash: Uint8Array,
      private readonly encryptedLeakMatchPrefixTestList: Uint8Array[]) {}

  static async create(
      verification: PasswordCheckVerification,
      credentialsList: Credentials[]): Promise<TestServerResponse> {
    const crypto: EcCommutativeCipherImpl =
        await EcCommutativeCipherImpl.createEcCommutativeCipherImpl();

    const serverCipher = EcCommutativeCipher.create(
        crypto, PasswordCheckVerification.CURVE_ID,
        PasswordCheckVerification.HASH_TYPE);

    const encryptedUserCredentialsHash =
        serverCipher.reencrypt(verification.getEncryptedUserCredentialsHash());

    const encryptedLeakMatchPrefixTestList = [];

    for (const credentials of credentialsList) {
      const prefix = (await TestServerResponse.serverEncryptAndRehash(
                          serverCipher, credentials))
                         .subarray(0, 20);
      encryptedLeakMatchPrefixTestList.push(prefix);
    }

    return new TestServerResponse(
        encryptedUserCredentialsHash, encryptedLeakMatchPrefixTestList);
  }

  checkCredentialsLeaked(verification: PasswordCheckVerification): boolean {
    return verification
        .verify(
            this.serverReEncryptedLookupHash,
            this.encryptedLeakMatchPrefixTestList)
        .areCredentialsLeaked();
  }

  getServerReencryptedLookupHash(): Uint8Array {
    return this.serverReEncryptedLookupHash;
  }

  getEncryptedLeakMatchPrefixTestList(): Uint8Array[] {
    return this.encryptedLeakMatchPrefixTestList;
  }

  private static async serverEncryptAndRehash(
      serverCipher: EcCommutativeCipher,
      credentials: Credentials): Promise<Uint8Array> {
    const serverEncrypted =
        serverCipher.encrypt(await CryptoHelper.hashUsernamePasswordPair(
            credentials.username, credentials.password));
    return createHash('sha256').update(serverEncrypted).digest();
  }
}

const TEST_USERNAME = 'foo';
const TEST_PASSWORD = 'bar';
const TEST_MATCHING_USERNAME_LIST = [
  new Credentials(TEST_USERNAME, TEST_PASSWORD), new Credentials('baz', 'pass')
];
const TEST_NOT_MATCHING_USERNAME_LIST =
    [new Credentials('foo', 'diff_password'), new Credentials('baz', 'pass')];
