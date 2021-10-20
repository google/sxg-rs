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
  workerPromise,
  WasmRequest,
} from './wasmFunctions';

addEventListener('fetch', (event) => {
  event.respondWith(handleRequest(event.request))
})

function responseFromWasm(data: WasmResponse): Response {
  return new Response(
    new Uint8Array(data.body),
    {
      status: data.status,
      headers: data.headers,
    },
  );
}

async function wasmFromResponse(response: Response): Promise<WasmResponse> {
  return {
    body: Array.from(new Uint8Array(await response.arrayBuffer())),
    headers: Array.from(response.headers),
    status: response.status,
  };
}

// Returns true if inputStream's total byte length is <= maxSize. After the
// promise resolves, the inputStream is closed and need not be canceled.
// (This function could be genericized to all TypedArrays, but no such
// interface exists in TypeScript, and not all uses of it below could be
// generalized.)
async function streamFrom(inputStream: ReadableStream, maxSize: number,
                          process?: (currentPos: number, value: Uint8Array) => void): Promise<boolean> {
  const reader = inputStream.getReader();
  let receivedSize = 0;
  while (true) {
    const { value, done } = await reader.read();
    if (value) {
      process?.(receivedSize, value);
      receivedSize += value.byteLength;
      if (receivedSize > maxSize) {
        reader.releaseLock();
        inputStream.cancel();
        return false;
      }
    }
    if (done) {
      // This implies closed per
      // https://streams.spec.whatwg.org/#default-reader-read.
      return true;
    }
  }
}

// Consumes up to maxSize bytes of inputStream, discarding the bytes.
async function consumeBytes(inputStream: ReadableStream<Uint8Array> | null, maxSize: number): Promise<void> {
  if (inputStream === null) {
    return;
  }
  await streamFrom(inputStream, maxSize);
}

// Consumes the input stream, and returns a byte array containing the first
// size bytes, or null if there aren't enough bytes.
async function readArrayPrefix(inputStream: ReadableStream<Uint8Array> | null, size: number): Promise<Uint8Array | null> {
  if (inputStream === null) {
    return new Uint8Array([]);
  }
  const received = new Uint8Array(size);
  let reachedEOS = await streamFrom(inputStream, size, (currentPos, value) => {
    if (currentPos + value.byteLength > size) {
      value = value.subarray(0, size - currentPos);
    }
    received.set(value, currentPos);
  });
  return reachedEOS ? null : received;
}

// Consumes the input stream, and returns a byte array containing the data in
// the input stream. If the input stream contains more bytes than `maxSize`,
// returns null.
async function readIntoArray(inputStream: ReadableStream<Uint8Array> | null, maxSize: number): Promise<Uint8Array | null> {
  if (inputStream === null) {
    return new Uint8Array([]);
  }
  const received = new Uint8Array(maxSize);
  let size = 0;
  let reachedEOS = await streamFrom(inputStream, maxSize, (currentPos, value) => {
    if (currentPos + value.byteLength <= maxSize) {
      received.set(value, currentPos);
      size = currentPos + value.byteLength;
    }
  });
  return reachedEOS ? received.subarray(0, size) : null;
}

function teeResponse(response: Response): [Response, Response] {
  const {
    body,
    headers,
    status,
  } = response;
  const [body1, body2] = body?.tee() ?? [null, null];
  return [
      new Response(body1, { headers, status }),
      new Response(body2, { headers, status }),
  ];
}

// Fetches latest OCSP from the CA, and writes it into key-value store.
// The outgoing traffic to the CA is throttled; when this function is called
// concurrently, the first fetched OCSP will be reused to be returned to all
// callers.
const fetchOcspFromCa = (() => {
  // The un-throttled implementation to fetch OCSP
  async function fetchOcspFromCaImpl() {
    let worker = await workerPromise;
    const ocspDer = await worker.fetchOcspFromCa(fetcher);
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
    const {
      expirationTime,
      nextFetchTime,
      ocspBase64,
    } = JSON.parse(ocspInCache);
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
// So config-generator sets HTML_HOST = my_domain.com when workers_dev is true.
//
// For wrangler dev, add CERT_ORIGIN = 'http://localhost:8787' to [vars] in
// wrangler.toml. Afterwards, set it to '' for production.
//
// For preset content, replaceHost is false because the fallback is on the
// worker origin, not the HTML_HOST.
function fallbackUrlAndCertOrigin(url: string, replaceHost: boolean): [string, string] {
  let fallbackUrl = new URL(url);
  let certOrigin = typeof CERT_ORIGIN !== 'undefined' && CERT_ORIGIN ?
      CERT_ORIGIN : fallbackUrl.origin;
  if (replaceHost && typeof HTML_HOST !== 'undefined' && HTML_HOST) {
      fallbackUrl.host = HTML_HOST;
  }
  return [fallbackUrl.toString(), certOrigin];
}

async function handleRequest(request: Request) {
  let worker = await workerPromise;
  let sxgPayload: Response | undefined;
  let fallback: Response | undefined;
  try {
    const ocsp = await getOcsp();
    const presetContent = worker.servePresetContent(request.url, ocsp);
    let fallbackUrl: string;
    let certOrigin: string;
    if (presetContent) {
      if (presetContent.kind === 'direct') {
        return responseFromWasm(presetContent);
      } else {
        [fallbackUrl, certOrigin] = fallbackUrlAndCertOrigin(presetContent.url, false);
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
      const requestHeaders = worker.createRequestHeaders('PrefersSxg', Array.from(request.headers));
      [sxgPayload, fallback] = teeResponse(await fetch(
        fallbackUrl,
        {
          headers: requestHeaders,
        }
      ));
    }
    sxgPayload = await promoteLinkTagsToHeaders(sxgPayload);
    let response = await generateSxgResponse(fallbackUrl, certOrigin, sxgPayload);
    fallback.body?.cancel();
    return response;
  } catch (e: any) {
    sxgPayload?.body?.cancel();
    if (!fallback) {
        // The error occurs before fetching from origin server, hence we need to
        // fetch now. Since we are not generating SXG anyway in this case, we
        // simply use all http headers from the user.
        fallback = await fetch(request);
    }
    if (worker.shouldRespondDebugInfo() && e.toString) {
      let message = e.toString();
      return new Response(
        fallback.body,
        {
          status: fallback.status,
          headers: [
              ...Array.from(fallback.headers || []),
              ['sxg-edge-worker-debug-info', message],
          ],
        },
      );
    } else {
      return fallback;
    }
  }
}

const PAYLOAD_SIZE_LIMIT = 8000000;

// https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.6
const TOKEN = /^[!#$%&'*+.^_`|~0-9a-zA-Z-]+$/;

// Matcher for HTML with either UTF-8 or unspecified character encoding.
// Capture group 1 indicates that charset=utf-8 was explicitly stated.
//
// https://datatracker.ietf.org/doc/html/rfc7231#section-3.1.1.5
//
// The list of aliases for UTF-8 is codified in
// https://source.chromium.org/chromium/chromium/src/+/main:third_party/blink/renderer/platform/wtf/text/text_codec_utf8.cc;l=52-68;drc=984c3018ecb2ff818e900fdb7c743fc00caf7efe
// and https://encoding.spec.whatwg.org/#concept-encoding-get.
// These are not currently supported, but could be if desired.
const HTML = /^text\/html([ \t]*;[ \t]*charset=(utf-8|"utf-8"))?$/i;

// If any <link rel=preload>s are found, they are promoted to Link headers.
// Later, generateSxgResponse will further modify the link header to support SXG
// preloading of eligible subresources.
//
// Out of an abundance of caution, this is limited to documents that are
// explicitly labeled as UTF-8 via Content-Type or <meta>. This could be
// expanded in the future, as the risk of misinterpreting type or encoding is
// rare and low-impact: producing `Link: rel=preload` headers for incorrect
// refs, which would waste bytes.
async function promoteLinkTagsToHeaders(payload: Response): Promise<Response> {
  if (!payload.body) {
    return payload;
  }

  let known_utf8 = false;

  // Only run HTMLRewriter if the content is HTML.
  const content_type_match = payload.headers.get('content-type')?.match(HTML);
  if (!content_type_match) {
    return payload;
  }
  if (content_type_match[1]) {
    known_utf8 = true;
  }

  // A temporary response.
  let toConsume;

  // Check for UTF-16 BOM, which overrides the <meta> tag, per the implementation at
  // https://source.chromium.org/chromium/chromium/src/+/main:third_party/blink/renderer/core/html/parser/text_resource_decoder.cc;l=394;drc=7a0b88f6d5c015fd3c280b58c7a99d8e1dca28ac
  // and the spec at
  // https://html.spec.whatwg.org/multipage/parsing.html#encoding-sniffing-algorithm.
  [payload, toConsume] = teeResponse(payload);
  const bom = await readArrayPrefix(toConsume.body, 2);
  if (bom &&
      (bom[0] == 0xFE && bom[1] == 0xFF || bom[0] == 0xFF && bom[1] == 0xFE)) {
    // Somebody set up us the BOM.
    return payload;
  }

  // Tee the original payload to be sure that HTMLRewriter doesn't make any
  // breaking modifications to the HTML. This is especially likely if the
  // document is in a non-ASCII-compatible encoding like UTF-16.
  [payload, toConsume] = teeResponse(payload);

  let link_tags: {href: string, as: string}[] = [];
  toConsume = new HTMLRewriter()
    .on('link[rel~="preload" i][href][as]', {
      element: (link: Element) => {
        const href = link.getAttribute('href');
        const as = link.getAttribute('as');
        // Ensure the values can be placed inside a Link header without
        // escaping or quoting.
        if (href && !href.includes('>') && as?.match(TOKEN)) {
          link_tags.push({href, as});
        }
      },
    })
    // Parse the meta tag, per the implementation in HTMLMetaCharsetParser::CheckForMetaCharset:
    // https://source.chromium.org/chromium/chromium/src/+/main:third_party/blink/renderer/core/html/parser/html_meta_charset_parser.cc;l=62-125;drc=7a0b88f6d5c015fd3c280b58c7a99d8e1dca28ac.
    // This differs slightly from what's described at https://github.com/whatwg/html/issues/6962, and
    // differs drastically from what's specified in
    // https://html.spec.whatwg.org/multipage/parsing.html#prescan-a-byte-stream-to-determine-its-encoding.
    .on('meta', {
      element: (meta: Element) => {
        // EncodingFromMetaAttributes:
        // https://source.chromium.org/chromium/chromium/src/+/main:third_party/blink/renderer/core/html/parser/html_parser_idioms.cc;l=362-393;drc=7a0b88f6d5c015fd3c280b58c7a99d8e1dca28ac
        let value = meta.getAttribute('charset');
        if (value) {
          if (value.toLowerCase() === 'utf-8') {
            known_utf8 = true;
          }
        } else if (meta.getAttribute('http-equiv')?.toLowerCase() === 'content-type' &&
                   meta.getAttribute('content')?.match(HTML)?.[1]) {
          // https://source.chromium.org/chromium/chromium/src/+/main:third_party/blink/renderer/core/html/parser/html_parser_idioms.cc;l=308-354;drc=984c3018ecb2ff818e900fdb7c743fc00caf7efe
          // https://html.spec.whatwg.org/multipage/urls-and-fetching.html#extracting-character-encodings-from-meta-elements
          // HTMLRewriter doesn't appear to decode HTML entities inside
          // attribute values, so a tag like
          //   <meta http-equiv=content-type content="text/html;charset=&quot;utf-8&quot;">
          // won't work. This could be supported in the future.
          known_utf8 = true;
        }
      },
    })
    .transform(toConsume);
  await consumeBytes(toConsume.body, PAYLOAD_SIZE_LIMIT);

  // NOTE: It's also possible for a <?xml encoding="utf-16"?> directive to
  // override <meta>, per
  // https://source.chromium.org/chromium/chromium/src/+/main:third_party/blink/renderer/core/html/parser/text_resource_decoder.cc;l=427-441;drc=7a0b88f6d5c015fd3c280b58c7a99d8e1dca28ac.
  // (This differs from the specification, which prioritizes <meta> over
  // <?xml?>.) However, the case is very rare, and HTMLRewriter doesn't have a
  // handler for XML declarations, so we skip the check.

  if (known_utf8 && link_tags.length) {
    const link = link_tags.map(({href, as}) => `<${href}>;rel=preload;as=${as}`).join(',');
    payload.headers.append('Link', link);
  }
  return payload;
}

async function generateSxgResponse(fallbackUrl: string, certOrigin: string, payload: Response) {
  let worker = await workerPromise;
  const payloadHeaders = Array.from(payload.headers);
  worker.validatePayloadHeaders(payloadHeaders);
  const payloadBody = await readIntoArray(payload.body, PAYLOAD_SIZE_LIMIT);
  if (!payloadBody) {
    throw `The size of payload exceeds the limit ${PAYLOAD_SIZE_LIMIT}`;
  }
  let {get: headerIntegrityGet, put: headerIntegrityPut} = await headerIntegrityCache();
  const now_in_seconds = Math.floor(Date.now() / 1000);
  const sxg = await worker.createSignedExchange(
    fallbackUrl,
    certOrigin,
    payload.status,
    payloadHeaders,
    new Uint8Array(payloadBody),
    now_in_seconds,
    signer,
    fetcher,
    headerIntegrityGet,
    headerIntegrityPut,
  );
  return responseFromWasm(sxg);
}

// SXGs larger than 8MB are not accepted by
// https://github.com/google/webpackager/blob/main/docs/cache_requirements.md.
const MAX_BYTES: number = 8000000;
async function fetcher(request: WasmRequest): Promise<WasmResponse> {
  let requestInit: RequestInit = {
      headers: request.headers,
      method: request.method,
  };
  if (request.body.length > 0) {
    requestInit.body = new Uint8Array(request.body);
  }
  const response = await fetch(request.url, requestInit);

  let body: ArrayBuffer;
  if (response.body) {
    const bodyReader = response.body.pipeThrough(limitBytes(MAX_BYTES));
    body = await new Response(bodyReader).arrayBuffer();
  } else {
    body = new ArrayBuffer(0);
  }
  return await wasmFromResponse(new Response(body, {
    headers: response.headers,
    status: response.status,
  }));
}

function limitBytes(maxBytes: number): TransformStream {
  let bytes = 0;
  return new TransformStream({
    transform: (chunk: Uint8Array, controller: TransformStreamDefaultController) => {
      bytes += chunk.byteLength;
      if (bytes <= maxBytes) {
        controller.enqueue(chunk);
      } else {
        // TODO: Should this be controller.error(...) instead?
        controller.terminate();
      }
    },
  });
}

type HttpCache = {
  get: (url: string) => Promise<WasmResponse>,
  put: (url: string, response: WasmResponse) => Promise<void>,
};
const NOT_FOUND_RESPONSE: WasmResponse = {
  body: [],
  headers: [],
  status: 404,
};
async function headerIntegrityCache(): Promise<HttpCache> {
  let cache = await caches.open('header-integrity');
  return {
    get: async (url: string) => {
      const response = await cache.match(url);
      return response ? await wasmFromResponse(response) : NOT_FOUND_RESPONSE;
    },
    put: async (url: string, response: WasmResponse) => {
      return cache.put(url, responseFromWasm(response));
    }
  }
}
