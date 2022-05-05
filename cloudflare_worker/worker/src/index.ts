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

import {
  PromoteLinkTagsToHeaders,
  SXGOnly,
  processHTML,
  // eslint-disable-next-line node/no-unpublished-import
} from '../../../typescript_utilities/src/processor';
import {fromJwk as createSignerFromJwk} from './signer';
import {
  PAYLOAD_SIZE_LIMIT,
  readIntoArray,
  teeResponse,
  // eslint-disable-next-line node/no-unpublished-import
} from '../../../typescript_utilities/src/streams';
import {
  arrayBufferToBase64,
  // eslint-disable-next-line node/no-unpublished-import
} from '../../../typescript_utilities/src/utils';
import {WasmResponse, WasmRequest, createWorker} from './wasmFunctions';

// This variable is added by the runtime of Cloudflare worker. It contains the
// binary data of the wasm file.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
declare let wasm: any;

const workerPromise = createWorker(wasm, SXG_CONFIG, CERT_PEM, ISSUER_PEM);

if (typeof PRIVATE_KEY_JWK === 'undefined') {
  throw 'The wrangler secret PRIVATE_KEY_JWK is not set.';
}
const signer = createSignerFromJwk(crypto.subtle, JSON.parse(PRIVATE_KEY_JWK));

addEventListener('fetch', (event: FetchEvent) => {
  event.passThroughOnException();
  event.respondWith(handleRequest(event.request));
});

function responseFromWasm(data: WasmResponse): Response {
  return new Response(new Uint8Array(data.body), {
    status: data.status,
    headers: data.headers,
  });
}

async function wasmFromResponse(response: Response): Promise<WasmResponse> {
  return {
    body: Array.from(new Uint8Array(await response.arrayBuffer())),
    headers: Array.from(response.headers),
    status: response.status,
  };
}

// Fetches latest OCSP from the CA, and writes it into key-value store.
// The outgoing traffic to the CA is throttled; when this function is called
// concurrently, the first fetched OCSP will be reused to be returned to all
// callers.
const fetchOcspFromCa = (() => {
  // The un-throttled implementation to fetch OCSP
  async function fetchOcspFromCaImpl() {
    const worker = await workerPromise;
    const ocspDer = await worker.fetchOcspFromCa(fetcher);
    const ocspBase64 = arrayBufferToBase64(ocspDer);
    const now = Date.now() / 1000;
    OCSP.put(
      /*key=*/ 'ocsp',
      /*value=*/ JSON.stringify({
        expirationTime: now + 3600 * 24 * 6,
        nextFetchTime: now + 3600 * 24,
        ocspBase64,
      }),
      {
        expirationTtl: 3600 * 24 * 6, // in seconds
      }
    );
    return ocspBase64;
  }
  let singletonTask: Promise<string> | null = null;
  return async function () {
    if (singletonTask !== null) {
      return await singletonTask;
    } else {
      singletonTask = fetchOcspFromCaImpl();
      const result = await singletonTask;
      singletonTask = null;
      return result;
    }
  };
})();

async function getOcsp() {
  const ocspInCache = await OCSP.get('ocsp');
  if (ocspInCache) {
    const {expirationTime, nextFetchTime, ocspBase64} = JSON.parse(ocspInCache);
    const now = Date.now() / 1000;
    if (now >= expirationTime) {
      return await fetchOcspFromCa();
    }
    if (now >= nextFetchTime) {
      // Spawns a non-blocking task to update latest OCSP in store
      fetchOcspFromCa();
    }
    return ocspBase64;
  } else {
    return await fetchOcspFromCa();
  }
}

// Returns the proper fallbackUrl and certOrigin. fallbackUrl should be
// https://my_domain.com in all environments, and certOrigin should be the
// origin of the worker (localhost, foo.bar.workers.dev, or my_domain.com).
//
// The request.url for each environment is as follows:
// wrangler dev:                           https://my_domain.com/
// wrangler publish + workers_dev = true:  https://sxg.user.workers.dev/
// wrangler publish + workers_dev = false: https://my_domain.com/
//
// So gen-config tool sets HTML_HOST = my_domain.com when workers_dev is true.
//
// For wrangler dev, add CERT_ORIGIN = 'http://localhost:8787' to [vars] in
// wrangler.toml. Afterwards, set it to '' for production.
//
// For preset content, replaceHost is false because the fallback is on the
// worker origin, not the HTML_HOST.
function fallbackUrlAndCertOrigin(
  url: string,
  replaceHost: boolean
): [string, string] {
  const fallbackUrl = new URL(url);
  const certOrigin =
    typeof CERT_ORIGIN !== 'undefined' && CERT_ORIGIN
      ? CERT_ORIGIN
      : fallbackUrl.origin;
  if (replaceHost && typeof HTML_HOST !== 'undefined' && HTML_HOST) {
    fallbackUrl.host = HTML_HOST;
  }
  return [fallbackUrl.toString(), certOrigin];
}

async function handleRequest(request: Request) {
  const worker = await workerPromise;
  let sxgPayload: Response | undefined;
  let fallback: Response | undefined;
  let response: Response | undefined;
  try {
    const ocsp = await getOcsp();
    const presetContent = await worker.servePresetContent(request.url, ocsp);
    let fallbackUrl: string;
    let certOrigin: string;
    if (presetContent) {
      if (presetContent.kind === 'direct') {
        return responseFromWasm(presetContent);
      } else {
        [fallbackUrl, certOrigin] = fallbackUrlAndCertOrigin(
          presetContent.url,
          false
        );
        fallback = responseFromWasm(presetContent.fallback);
        sxgPayload = responseFromWasm(presetContent.payload);
        // Although we are not sending any request to the backend,
        // we still need to check the validity of the request header.
        // For example, if the header does not contain
        // `Accept: signed-exchange;v=b3`, we will throw an error.
        worker.createRequestHeaders('AcceptsSxg', Array.from(request.headers));
      }
    } else {
      [fallbackUrl, certOrigin] = fallbackUrlAndCertOrigin(request.url, true);
      const requestHeaders = worker.createRequestHeaders(
        'PrefersSxg',
        Array.from(request.headers)
      );
      [sxgPayload, fallback] = teeResponse(
        await fetch(fallbackUrl, {
          headers: requestHeaders,
        })
      );
    }
    sxgPayload = await processHTML(sxgPayload, [
      new PromoteLinkTagsToHeaders(),
      new SXGOnly(true),
    ]);
    response = await generateSxgResponse(fallbackUrl, certOrigin, sxgPayload);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } catch (e: any) {
    console.error(e);
    sxgPayload?.body?.cancel();
    if (!fallback) {
      // The error occurs before fetching from origin server, hence we need to
      // fetch now. Since we are not generating SXG anyway in this case, we
      // simply use all http headers from the user.
      fallback = await fetch(request);
    }
    let fallwayback;
    [fallback, fallwayback] = teeResponse(fallback);
    try {
      // If the body is HTML >8MB, processHTML will fail.
      fallback = await processHTML(fallback, [new SXGOnly(false)]);
      fallwayback.body?.cancel();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (e: any) {
      console.error(e);
      fallback.body?.cancel();
      fallback = fallwayback;
    }
    return fallback;
  }
  fallback.body?.cancel();
  return response;
}

async function generateSxgResponse(
  fallbackUrl: string,
  certOrigin: string,
  payload: Response
) {
  const worker = await workerPromise;
  const payloadHeaders: Array<[string, string]> = Array.from(payload.headers);
  worker.validatePayloadHeaders(payloadHeaders);
  const payloadBody = await readIntoArray(payload.body, PAYLOAD_SIZE_LIMIT);
  if (!payloadBody) {
    throw `The size of payload exceeds the limit ${PAYLOAD_SIZE_LIMIT}`;
  }
  const {get: headerIntegrityGet, put: headerIntegrityPut} =
    await headerIntegrityCache();
  const nowInSeconds = Math.floor(Date.now() / 1000);
  const sxg = await worker.createSignedExchange({
    fallbackUrl,
    certOrigin,
    statusCode: payload.status,
    payloadHeaders,
    payloadBody,
    skipProcessLink: false,
    nowInSeconds,
    signer,
    subresourceFetcher: fetcher,
    headerIntegrityGet,
    headerIntegrityPut,
  });
  return responseFromWasm(sxg);
}

async function fetcher(request: WasmRequest): Promise<WasmResponse> {
  const requestInit: RequestInit = {
    headers: request.headers,
    method: request.method,
  };
  if (request.body.length > 0) {
    requestInit.body = new Uint8Array(request.body);
  }
  const response = await fetch(request.url, requestInit);

  let body;
  if (response.body) {
    body = await readIntoArray(response.body, PAYLOAD_SIZE_LIMIT);
    if (!body) {
      throw `The size of payload exceeds the limit ${PAYLOAD_SIZE_LIMIT}`;
    }
  } else {
    body = new Uint8Array(0);
  }
  return await wasmFromResponse(
    new Response(body, {
      headers: response.headers,
      status: response.status,
    })
  );
}

type HttpCache = {
  get: (url: string) => Promise<WasmResponse>;
  put: (url: string, response: WasmResponse) => Promise<void>;
};
const NOT_FOUND_RESPONSE: WasmResponse = {
  body: [],
  headers: [],
  status: 404,
};
async function headerIntegrityCache(): Promise<HttpCache> {
  const cache = await caches.open('header-integrity');
  return {
    get: async (url: string) => {
      const response = await cache.match(url);
      return response ? await wasmFromResponse(response) : NOT_FOUND_RESPONSE;
    },
    put: async (url: string, response: WasmResponse) => {
      return cache.put(url, responseFromWasm(response));
    },
  };
}
