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

async function importWasmFunctions() {
  await wasm_bindgen(wasm);
  wasm_bindgen.init();
  return wasm_bindgen;
}

function responseFromWasm(data) {
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
 * @param {ReadableStream} inputStream
 * @param {number} maxSize
 * @returns {Promise<Uint8Array | null>}
 */
async function readIntoArray(inputStream, maxSize) {
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

function teeResponse(response) {
  const {
    body,
    headers,
    status,
  } = response;
  const [body1, body2] = response.body.tee();
  return [
      new Response(body1, { headers, status }),
      new Response(body2, { headers, status }),
  ];
}

async function handleRequest(request) {
  const {
    servePresetContent,
    shouldResponseDebugInfo,
  } = await importWasmFunctions();
  const presetContent = servePresetContent(request.url);
  if (presetContent) {
    return responseFromWasm(presetContent);
  }
  const payload = await fetch(request);
  const [payload1, payload2] = teeResponse(payload);
  let response;
  try {
    response = await genereateResponse(request, payload1);
  } catch (e) {
    if (shouldResponseDebugInfo()) {
      response = new Response(
        `Failed to create SXG.\n${e}`,
        {
          status: 500,
          headers: {
            'Content-Type': 'text/plain',
          },
        },
      );
    } else {
      response = payload2;
    }
  }
  return response;
}

async function genereateResponse(request, payload) {
  const {
    createSignedExchange,
    validatePayloadHeaders,
    validateRequestAcceptHeader,
  } = await importWasmFunctions();
  validateRequestAcceptHeader(request.headers.get('accept') || '');
  const payloadStatusCode = payload.status;
  if (payloadStatusCode !== 200) {
    throw `The resource status code is ${payloadStatusCode}`;
  }
  const payloadHeaders = Object.fromEntries(payload.headers);
  validatePayloadHeaders(payloadHeaders);
  const PAYLOAD_SIZE_LIMIT = 8000000;
  const payloadBody = await readIntoArray(payload.body, PAYLOAD_SIZE_LIMIT);
  if (!payloadBody) {
    throw `The size of payload exceeds the limit ${PAYLOAD_SIZE_LIMIT}`;
  }
  const sxg = createSignedExchange(
    request.url,
    payloadStatusCode,
    payloadHeaders,
    new Uint8Array(payloadBody),
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
