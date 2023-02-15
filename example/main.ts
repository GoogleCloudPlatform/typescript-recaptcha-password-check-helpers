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

import {request} from 'https';
import {PasswordCheckVerification} from 'recaptcha-password-check-helpers';
import yargs from 'yargs/yargs';

const BASE_URL = 'https://recaptchaenterprise.googleapis.com';

interface ApiResponse {
  privatePasswordLeakVerification: PrivatePasswordLeakVerification;
}

interface PrivatePasswordLeakVerification {
  reencryptedUserCredentialsHash: string;
  encryptedLeakMatchPrefixes: string[];
}

class Main {
  constructor(
      private readonly username: string, private readonly password: string,
      private readonly projectId: string, private readonly apiKey: string) {
    if (apiKey === '') {
      throw new Error('`api_key` must be provided for local runs');
    }
  }

  run() {
    this.checkCredentials()
        .then((leakFound) => {
          console.log(`Leak found: ${leakFound}`);
        })
        .catch((e) => {
          console.log('Something went wrong', e);
        });
  }

  private async checkCredentials(): Promise<boolean> {
    const verification =
        await PasswordCheckVerification.create(this.username, this.password);
    const res = await this.createAssessment(verification);

    const encryptedLeakMatchPrefixes =
        res.encryptedLeakMatchPrefixes.map((prefix) => {
          return Buffer.from(prefix, 'base64');
        });
    const reencryptedUserCredentialsHash =
        Buffer.from(res.reencryptedUserCredentialsHash, 'base64');

    return verification
        .verify(reencryptedUserCredentialsHash, encryptedLeakMatchPrefixes)
        .areCredentialsLeaked();
  }

  private async createAssessment(verification: PasswordCheckVerification):
      Promise<PrivatePasswordLeakVerification> {
    const body = JSON.stringify({
      event: {
        expectedAction: 'login',
      },
      privatePasswordLeakVerification: {
        lookupHashPrefix:
            Buffer.from(verification.getLookupHashPrefix()).toString('base64'),
        encryptedUserCredentialsHash:
            Buffer.from(verification.getEncryptedUserCredentialsHash())
                .toString('base64'),
      }
    });

    const res = await this.makeRequest(body);
    return res.privatePasswordLeakVerification;
  }

  private async makeRequest(body: string): Promise<ApiResponse> {
    const headers = await this.buildHeaders();

    const url = `${BASE_URL}/v1/projects/${this.projectId}/assessments?key=${
        this.apiKey}`;

    return new Promise((resolve, reject) => {
      const options = {method: 'POST', headers};

      const req = request(url, options, (res) => {
        res.setEncoding('utf8');
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          if (res.statusCode !== 200) {
            throw new Error('Request failed: ' + data);
          }
          resolve(JSON.parse(data) as ApiResponse);
        });
      });

      req.on('error', (e) => {
        console.log('Something went wrong', e);
        reject(e);
      });

      // Write data to request body
      req.write(body);
      req.end();
    });
  }

  private async buildHeaders() {
    const headers: {[key: string]: string} = {
      'Content-type': 'application/json; charset=utf-8',
    };

    return headers;
  }
}

const parser = yargs(process.argv.slice(2)).options({
  u: {type: 'string', alias: 'username', demandOption: true},
  p: {type: 'string', alias: 'password', demandOption: true},
  i: {type: 'string', alias: 'project_id', demandOption: true},
  k: {type: 'string', alias: 'api_key', default: ''}
});
(async () => {
  const argv = await parser.argv;
  const main = new Main(argv.u, argv.p, argv.i, argv.k);
  main.run();
})();
