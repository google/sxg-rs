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
  signer,
} from './signer';
import {
  arrayBufferToBase64,
} from './utils';
import {
  WasmResponse,
  wasmFunctionsPromise,
  WasmRequest,
} from './wasmFunctions';

addEventListener('fetch', (event) => {
  event.respondWith(handleRequest(event.request))
})

function responseFromWasm(data: WasmResponse) {
  return new Response(
    new Uint8Array(data.body),
    {
      status: data.status,
      headers: data.headers,
    },
  );
}

/**
 * Consumes the input stream, and returns an byte array containing the data in
 * the input stream. If the input stream contains more bytes than `maxSize`,
 * returns null.
 * @param {ReadableStream | null} inputStream
 * @param {number} maxSize
 * @returns {Promise<Uint8Array | null>}
 */
async function readIntoArray(inputStream: ReadableStream | null, maxSize: number) {
  if (inputStream === null) {
    return new Uint8Array([]);
  }
  const reader = inputStream.getReader();
  const received = new Uint8Array(maxSize);
  let receivedSize = 0;
  while (true) {
    const {
      value,
      done,
    } = await reader.read();
    if (value) {
      if (receivedSize + value.byteLength > maxSize) {
        reader.releaseLock();
        inputStream.cancel();
        return null;
      }
      received.set(value, receivedSize);
      receivedSize += value.byteLength;
    }
    if (done) {
      return received.subarray(0, receivedSize);
    }
  }
}

function teeResponse(response: Response) {
  const {
    body,
    headers,
    status,
  } = response;
  const [body1, body2] = body?.tee() ?? [null, null];
  return [
      new Response(body1, { headers, status }),
      new Response(body2, { headers, status }),
  ] as const;
}

// Fetches latest OCSP from digicert, and writes it into key-value store.
// The outgoing traffic to digicert is throttled; when this function is called
// concurrently, the first fetched OCSP will be reused to be returned to all
// callers.
const fetchOcspFromDigicert = (() => {
  // The un-throttled implementation to fetch OCSP
  async function fetchOcspFromDigicertImpl() {
    const {
      fetchOcspFromDigicert: wasmFetchOcspFromDigicert,
    } = await wasmFunctionsPromise;
    const ocspDer = await wasmFetchOcspFromDigicert(fetcher);
    const ocspBase64 = arrayBufferToBase64(ocspDer);
    const now = Date.now() / 1000;
    OCSP.put(
      /*key=*/'ocsp',
      /*value=*/JSON.stringify({
        expirationTime: now + 3600 * 24 * 6,
        nextFetchTime: now + 3600 * 24,
        ocspBase64,
      }),
      {
        expirationTtl: 3600 * 24 * 6, // in seconds
      },
    );
    return ocspBase64;
  }
  let singletonTask: Promise<string> | null = null;
  return async function() {
    if (singletonTask !== null) {
      return await singletonTask;
    } else {
      singletonTask = fetchOcspFromDigicertImpl();
      const result = await singletonTask;
      singletonTask = null;
      return result;
    }
  };
})();

async function getOcsp() {
  const ocspInCache = await OCSP.get('ocsp');
  if (ocspInCache) {
    const {
      expirationTime,
      nextFetchTime,
      ocspBase64,
    } = JSON.parse(ocspInCache);
    const now = Date.now() / 1000;
    if (now >= expirationTime) {
      return await fetchOcspFromDigicert();
    }
    if (now >= nextFetchTime) {
      // Spawns a non-blocking task to update latest OCSP in store
      fetchOcspFromDigicert();
    }
    return ocspBase64;
  } else {
    return await fetchOcspFromDigicert();
  }
}

async function handleRequest(request: Request) {
  const {
    createRequestHeaders,
    getLastErrorMessage,
    servePresetContent,
    shouldRespondDebugInfo,
  } = await wasmFunctionsPromise;
  let fallbackUrl: string;
  let fallback: Response | undefined;
  try {
    const ocsp = await getOcsp();
    let sxgPayload: Response;
    const presetContent = servePresetContent(request.url, ocsp);
    if (presetContent) {
      if (presetContent.kind === 'direct') {
        return responseFromWasm(presetContent);
      } else {
        fallbackUrl = presetContent.url;
        fallback = responseFromWasm(presetContent.fallback);
        sxgPayload = responseFromWasm(presetContent.payload);
        // Although we are not sending any request to HTML_HOST,
        // we still need to check the validity of the request header.
        // For example, if the header does not contain
        // `Accept: signed-exchange;v=b3`, we will throw an error.
        createRequestHeaders(Array.from(request.headers));
      }
    } else {
      fallbackUrl = request.url;
      const requestHeaders = createRequestHeaders(Array.from(request.headers));
      [sxgPayload, fallback] = teeResponse(await fetch(
        fallbackUrl,
        {
          headers: requestHeaders,
        }
      ));
    }
    return await generateSxgResponse(fallbackUrl, sxgPayload);
  } catch (e) {
    if (shouldRespondDebugInfo()) {
      let message;
      if (e instanceof WebAssembly.RuntimeError) {
        message = `WebAssembly code is aborted.\n${e}.\n${getLastErrorMessage()}`;
      } else if (typeof e === 'string') {
        message = `A message is gracefully thrown.\n${e}`;
      } else {
        message = `JavaScript code throws an error.\n${e}`;
      }
      if (!fallback) {
        fallback = new Response(message);
      }
      return new Response(
        fallback.body,
        {
          status: fallback.status,
          headers: [
              ...Array.from(fallback.headers || []),
              ['sxg-edge-worker-debug-info', JSON.stringify(message)],
          ],
        },
      );
    } else {
      if (fallback) {
        // The error occurs after fetching from origin server, hence we reuse
        // the response of that fetch.
        return fallback;
      } else {
        // The error occurs before fetching from origin server, hence we need to
        // fetch now. Since we are not generating SXG anyway in this case, we
        // simply use all http headers from the user.
        return fetch(request);
      }
    }
  }
}

async function generateSxgResponse(fallbackUrl: string, payload: Response) {
  const {
    createSignedExchange,
    validatePayloadHeaders,
  } = await wasmFunctionsPromise;
  const payloadStatusCode = payload.status;
  if (payloadStatusCode !== 200) {
    throw `The resource status code is ${payloadStatusCode}`;
  }
  const payloadHeaders = Array.from(payload.headers);
  validatePayloadHeaders(payloadHeaders);
  const PAYLOAD_SIZE_LIMIT = 8000000;
  const payloadBody = await readIntoArray(payload.body, PAYLOAD_SIZE_LIMIT);
  if (!payloadBody) {
    throw `The size of payload exceeds the limit ${PAYLOAD_SIZE_LIMIT}`;
  }
  const sxg = await createSignedExchange(
    fallbackUrl,
    payloadStatusCode,
    payloadHeaders,
    new Uint8Array(payloadBody),
    Math.round(Date.now() / 1000 - 60 * 60 * 12),
    signer,
  );
  return responseFromWasm(sxg);
}

async function fetcher(request: WasmRequest): Promise<WasmResponse> {
  const response = await fetch(
    request.url,
    {
      body: new Uint8Array(request.body),
      headers: request.headers,
      method: request.method,
    },
  );
  const responseBody = await response.arrayBuffer();
  return {
    body: Array.from(new Uint8Array(responseBody)),
    headers: [],
    status: response.status,
  };
}
