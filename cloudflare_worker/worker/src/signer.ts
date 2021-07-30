/**
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

const privateKeyPromise = (async function initPrivateKey() {
  if (!PRIVATE_KEY_JWK) {
    throw `The wrangler secret PRIVATE_KEY_JWK is not set.`;
  }
  return await crypto.subtle.importKey(
      "jwk",
      JSON.parse(PRIVATE_KEY_JWK),
      {
        name: "ECDSA",
        namedCurve: 'P-256',
      },
      /*extractable=*/false,
      ['sign'],
  );
})();

export async function signer(message: Uint8Array): Promise<Uint8Array> {
  const privateKey = await privateKeyPromise;
  const signature = await crypto.subtle.sign(
      {
        name: "ECDSA",
        hash: 'SHA-256',
      },
      privateKey,
      message,
  );
  return new Uint8Array(signature);
}
