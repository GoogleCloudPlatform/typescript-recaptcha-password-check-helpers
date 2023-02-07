# reCAPTCHA Password Check - Typescript

Typescript client library for reCAPTCHA's
[private password check API](https://cloud.google.com/recaptcha-enterprise/docs/check-passwords).
It exposes functionality to make password leak check requests in a private
manner (i.e credentials are sent encrypted and the server cannot—and doesn't
need to—decrypt them).

## Usage

1.  Create a verification with some user credentials and extract the parameters
    generated

    ```typescript
    const verification =
        await PasswordCheckVerification.create(username, password);

    const lookupHashPrefix = verification.getLookupHashPrefix();
    const encryptedUserCredentialsHash = verification.getEncryptedUserCredentialsHash();
    ```

3.  Next, use the parameters generated to include in your reCAPTCHA
    [assessment request](https://cloud.google.com/recaptcha-enterprise/docs/create-assessment)

4.  Then, extract the `reEncryptedUserCredentialsHash` and
    `encryptedLeakMatchPrefixes` from the response of the assessment request and
    use them to verify them and determine whether the user credentials are
    leaked or not:

    ```typescript
    const leakFound = verification.verify(
        reencryptedUserCredentialsHash, encryptedLeakMatchPrefixes);
    ```

## Example

The following example assumes the requests to the reCAPTCHA API are made via a
custom http client.

```typescript

// Create a password check verification
const verification =
    await PasswordCheckVerification.create(username, password);

// Extract the generated parameters
const lookupHashPrefix = verification.getLookupHashPrefix();
const encryptedUserCredentialsHash = verification.getEncryptedUserCredentialsHash();

// Build the http request body
const body = JSON.stringify({
  event: {
    expectedAction: 'login',
  },
  privatePasswordLeakVerification: {
    lookupHashPrefix: Buffer.from(lookupHashPrefix).toString('base64'),
    encryptedUserCredentialsHash: Buffer.from(encryptedUserCredentialsHash).toString('base64'),
  }
});

// makeRequest makes an http request to the reCAPTCHA API
const res = await makeRequest(body);

// Extract result fields from response
const encryptedLeakMatchPrefixes = res.encryptedLeakMatchPrefixes.map((prefix) => {
  return Buffer.from(prefix, 'base64');
});
const reencryptedUserCredentialsHash =
    Buffer.from(res.reencryptedUserCredentialsHash, 'base64');

const credentialsLeaked = verification.verify(
    reencryptedUserCredentialsHash, encryptedLeakMatchPrefixes);

if (credentialsLeaked) {
  console.log("Credentials leaked!");
} else {
  console.log("No leak found");
}

```
