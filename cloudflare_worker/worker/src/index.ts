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
import {fromJwk as createSignerFromJwk, Signer} from './signer';
import {storageRead, storageWrite} from './storage';
import {
  PAYLOAD_SIZE_LIMIT,
  readIntoArray,
  teeResponse,
  // eslint-disable-next-line node/no-unpublished-import
} from '../../../typescript_utilities/src/streams';
import {
  WasmResponse,
  WasmRequest,
  WasmWorker,
  createWorker,
} from './wasmFunctions';

// This variable is added by the runtime of Cloudflare worker. It contains the
// binary data of the wasm file.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
declare let wasm: any;

const workerPromise = (async () => {
  let worker: WasmWorker;
  if (typeof CERT_PEM === 'string' && typeof ISSUER_PEM === 'string') {
    worker = await createWorker(wasm, SXG_CONFIG, [CERT_PEM, ISSUER_PEM]);
  } else {
    worker = await createWorker(wasm, SXG_CONFIG, undefined);
  }
  await worker.addAcmeCertificatesFromStorage(createRuntime());
  return worker;
})();

const sxgSigner = createSignerFromJwk(
  crypto.subtle,
  typeof PRIVATE_KEY_JWK === 'string' ? JSON.parse(PRIVATE_KEY_JWK) : null
);

addEventListener('fetch', (event: FetchEvent) => {
  event.passThroughOnException();
  event.respondWith(handleRequest(event.request));
});

addEventListener('scheduled', (event: ScheduledEvent) => {
  event.waitUntil(updateStateMachine());
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

function createRuntime() {
  let acmeRawSigner: Signer | undefined;
  if (typeof ACME_PRIVATE_KEY_JWK === 'string') {
    acmeRawSigner = createSignerFromJwk(
      crypto.subtle,
      JSON.parse(ACME_PRIVATE_KEY_JWK)
    );
  }

  return {
    nowInSeconds: Math.floor(Date.now() / 1000),
    fetcher,
    storageRead,
    storageWrite,
    sxgRawSigner: sxgSigner,
    sxgAsn1Signer: undefined,
    acmeRawSigner,
  };
}

async function updateStateMachine() {
  const worker = await workerPromise;
  const runtime = createRuntime();
  await worker.updateAcmeStateMachine(runtime, ACME_ACCOUNT);
  await worker.updateOcspInStorage(runtime);
}

async function handleRequest(request: Request) {
  const worker = await workerPromise;
  let sxgPayload: Response | undefined;
  let fallback: Response | undefined;
  let response: Response | undefined;
  try {
    const presetContent = await worker.servePresetContent(
      createRuntime(),
      request.url
    );
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
      const requestHeaders = await worker.createRequestHeaders(
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
  const sxg = await worker.createSignedExchange(createRuntime(), {
    fallbackUrl,
    certOrigin,
    statusCode: payload.status,
    payloadHeaders,
    payloadBody,
    skipProcessLink: false,
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
