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

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

function acceptsSxg(request) {
  const accept = request.headers.get('accept') ?? '';
  return accept.includes('application/signed-exchange');
}

function cloneUrlWith(urlString, mutate) {
  const url = new URL(urlString);
  mutate(url);
  return url.href;
}

// https://wicg.github.io/webpackage/draft-yasskin-httpbis-origin-signed-exchanges-impl.html#name-uncached-header-fields
const UNCACHED_HEADERS = [
  'connection',
  'keep-alive',
  'proxy-connection',
  'trailer',
  'transfer-encoding',
  'upgrade',
];

// https://wicg.github.io/webpackage/draft-yasskin-http-origin-signed-responses.html#stateful-headers
const STATEFUL_HEADERS = [
  'authentication-control',
  'authentication-info',
  'clear-site-data',
  'optional-www-authenticate',
  'proxy-authenticate',
  'proxy-authentication-info',
  'public-key-pins',
  'sec-websocket-accept',
  'set-cookie',
  'set-cookie2',
  'setprofile',
  'strict-transport-security',
  'www-authenticate',
];

const VARIANT_HEADERS = [
  'variant-key-04',
  'variants-04',
];


/**
 * Fetch and log a request
 * @param {Request} request
 */
async function handleRequest(request) {
  const requestUrl = request.url;
  const certUrl = cloneUrlWith(requestUrl, u => u.pathname = '/.sxg_cert');
  const fallbackUrl = cloneUrlWith(requestUrl, u => u.host = HOST);
  const validityUrl = cloneUrlWith(fallbackUrl, u => u.pathname = '/.sxg_validity');
  const {
    createCertCbor,
    createSignedExchange,
  } = wasm_bindgen;
  await wasm_bindgen(wasm);
  if (requestUrl === certUrl) {
    return new Response(
      createCertCbor(),
      {
        status: 200,
        headers: {
          'content-type': 'application/cert-chain+cbor',
        },
      },
    );
  }
  if (!acceptsSxg(request)) {
    return fetch(request);
  }
  const response = await fetch(fallbackUrl);
  const headers = Array.from(response.headers).filter((entry) => {
    const key = entry[0].toLowerCase();
    return key.startsWith('cf-') === false &&
      UNCACHED_HEADERS.includes(key) === false;
  });
  const containsHarmfulHeader = headers.some((entry) => {
    const key = entry[0].toLowerCase();
    return STATEFUL_HEADERS.includes(key) || VARIANT_HEADERS.includes(key);
  });
  if (containsHarmfulHeader) {
    return response;
  }
  const payloadBody = await response.text();
  const sxg = createSignedExchange(
    certUrl,
    validityUrl,
    fallbackUrl,
    response.status,
    headers,
    payloadBody,
    Math.round(Date.now() / 1000 - 60 * 60 * 12),
  );
  return new Response(
      sxg,
      {
        status: 200,
        headers: {
          'Content-Type': 'application/signed-exchange;v=b3',
          'X-Content-Type-Options': 'nosniff',
        },
      },
  );
}
