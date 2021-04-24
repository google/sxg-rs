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
  const accept = request.headers.get('accept') || '';
  return accept.includes('application/signed-exchange');
}

async function importWasmFunctions() {
  await wasm_bindgen(wasm);
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
    canSignHeaders,
    createSignedExchange,
    servePresetContent,
  } = await importWasmFunctions();
  const {
    url,
  } = request;
  const presetContent = servePresetContent(url);
  if (presetContent) {
    return responseFromWasm(presetContent);
  }
  if (!acceptsSxg(request)) {
    return fetch(request);
  }
  const payload = await fetch(url);
  const payloadStatusCode = payload.status;
  const payloadHeaders = Array.from(payload.headers);
  if (payloadStatusCode !== 200 || !canSignHeaders(payloadHeaders)) {
    return payload;
  }
  const payloadBody = await payload.arrayBuffer();
  const sxg = createSignedExchange(
    url,
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
