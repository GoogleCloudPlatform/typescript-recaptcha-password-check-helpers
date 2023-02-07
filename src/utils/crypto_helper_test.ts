import 'jasmine';

import {CryptoHelper} from './crypto_helper';

/**
 * These tests were built based on
 * google3/javatests/com/google/identity/passwords/leak/check/common/opensource/CryptoHelperTest.java
 * to keep compatibility across versions.
 */

function byteArrayToHexString(byteArray: Uint8Array): string {
  return Array
      .from(
          byteArray,
          (byte) => {
            return ('0' + (byte & 0xFF).toString(16)).slice(-2);
          })
      .join('');
}

describe('crypto helper test', () => {
  it('Computes the hash of a username', () => {
    expect(byteArrayToHexString(CryptoHelper.hashUsername('jonsnow')))
        .toEqual(
            '3d70d37bfc1a3d8145e6c7a3a4d7927661c1e8df82bd0c9f619aa3c996ec4cb3');
  });

  it('Computes the hash of a username and password pair', (done) => {
    CryptoHelper.hashUsernamePasswordPair('jonsnow', 'Targaryen').then((result) => {
      expect(byteArrayToHexString(result))
          .toEqual(
              'f6e6fdb323af6f3d0310bb300e5a786b39a9a387c2eddecdfe184bf22330b272');
      done();
    });
  });

  it('Canonicalizes a username not changing ascii characters', () => {
    expect(CryptoHelper.canonicalizeUsername('test')).toEqual('test');
  });

  it('Canonicalizes a username not changing special characters', () => {
    expect(CryptoHelper.canonicalizeUsername('äöü日本語العَرَبِيَّة'))
        .toEqual('äöü日本語العَرَبِيَّة');
  });

  it('Canonicalizes a username with uppercase characters', () => {
    expect(CryptoHelper.canonicalizeUsername('Test')).toEqual('test');
  });

  it('Canonicalizes a username stripping dots', () => {
    expect(CryptoHelper.canonicalizeUsername('test.test')).toEqual('testtest');
  });

  it('Canonicalizes a username stripping host', () => {
    expect(CryptoHelper.canonicalizeUsername('test@example.com'))
        .toEqual('test');
  });

  it('Canonicalizes a username stripping host with i18n user', () => {
    expect(CryptoHelper.canonicalizeUsername('例え@例え.テスト'))
        .toEqual('例え');
  });
  it('Bucketizes a username', () => {
    expect(CryptoHelper.bucketizeUsername('leakedusername', 26))
        .toEqual(Uint8Array.of(0xce, 0x8c, 0x59, 0xc0));
  });
});