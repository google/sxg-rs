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
  let response;
  try {
    response = await genereateResponse(request, payload);
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
      response = payload;
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
  const payloadBody = await payload.arrayBuffer();
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
