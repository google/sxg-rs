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
      createOcspRequest,
    } = await wasmFunctionsPromise;
    const ocspRequest = createOcspRequest();
    const ocspResponse = await fetch('http://ocsp.digicert.com', {
      method: 'POST',
      body: ocspRequest,
      headers: {
        'content-type': 'application/ocsp-request',
      },
    });
    const ocspDer = await ocspResponse.arrayBuffer();
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
  let fallback = null;
  try {
    const ocsp = await getOcsp();
    const presetContent = servePresetContent(request.url, ocsp);
    if (presetContent) {
      return responseFromWasm(presetContent);
    }
    const requestHeaders = createRequestHeaders(Array.from(request.headers));
    let sxgPayload;
    [sxgPayload, fallback] = teeResponse(await fetch(
      request.url,
      {
        headers: requestHeaders,
      }
    ));
    return await generateSxgResponse(request, sxgPayload);
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

async function generateSxgResponse(request: Request, payload: Response) {
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
    request.url,
    payloadStatusCode,
    payloadHeaders,
    new Uint8Array(payloadBody),
    Math.round(Date.now() / 1000 - 60 * 60 * 12),
    signer,
  );
  return responseFromWasm(sxg);
}
