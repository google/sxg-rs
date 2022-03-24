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

import {fromJwk as createSignerFromJwk} from './signer';
import {readArrayPrefix, readIntoArray, teeResponse} from './streams';
import {TOKEN, arrayBufferToBase64, escapeLinkParamValue} from './utils';
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
    const presetContent = worker.servePresetContent(request.url, ocsp);
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
    } catch {
      fallback.body?.cancel();
      fallback = fallwayback;
    }
    if (worker.shouldRespondDebugInfo() && e.toString) {
      const message: string = e.toString();
      return new Response(fallback.body, {
        status: fallback.status,
        headers: [
          ...Array.from(fallback.headers || []),
          ['sxg-edge-worker-debug-info', message],
        ],
      });
    } else {
      return fallback;
    }
  }
  fallback.body?.cancel();
  return response;
}

// SXGs larger than 8MB are not accepted by
// https://github.com/google/webpackager/blob/main/docs/cache_requirements.md.
const PAYLOAD_SIZE_LIMIT = 8000000;

// Approximate matcher for a valid URL; that it only contains characters
// allowed by https://datatracker.ietf.org/doc/html/rfc3986#appendix-A.
const URL_CHARS = /^[%A-Za-z0-9._~:/?#[\]@!$&'()*+,;=-]*$/;

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

// Attributes allowed on Link headers by
// https://github.com/google/webpackager/blob/main/docs/cache_requirements.md.
const ALLOWED_LINK_ATTRS = new Set([
  'as',
  'header-integrity',
  'media',
  'rel',
  'imagesrcset',
  'imagesizes',
  'crossorigin',
]);

interface HTMLProcessor {
  register(rewriter: HTMLRewriter): void;
  // Returns true iff the processor modified the HTML body. processHTML uses
  // the rewritten HTML body iff one of the processors returns true.
  modified: boolean;
  onEnd(payload: Response): void;
}

// If any <link rel=preload>s are found, they are promoted to Link headers.
// Later, generateSxgResponse will further modify the link header to support
// SXG preloading of eligible subresources.
class PromoteLinkTagsToHeaders implements HTMLProcessor {
  modified = false;
  link_tags: {href: string; attrs: string[][]}[] = [];
  register(rewriter: HTMLRewriter): void {
    rewriter.on('link[rel~="preload" i][href][as]:not([data-sxg-no-header])', {
      element: (link: Element) => {
        const href = link.getAttribute('href');
        const as = link.getAttribute('as');
        // Ensure the values can be placed inside a Link header without
        // escaping or quoting.
        if (href?.match(URL_CHARS) && as?.match(TOKEN)) {
          // link.attributes is somehow being mistyped as an Attr[], per the
          // definition of Attr from typescript/lib/lib.dom.d.ts. Not sure why;
          // @cloudflare/workers-types/index.d.ts says it's a string[][].
          const attrs = [...(link.attributes as unknown as string[][])].filter(
            // eslint-disable-next-line @typescript-eslint/no-unused-vars
            ([name, _value]) => name && ALLOWED_LINK_ATTRS.has(name)
          );
          this.link_tags.push({href, attrs});
        }
      },
    });
  }
  onEnd(payload: Response): void {
    if (this.link_tags.length) {
      const link = this.link_tags
        .map(({href, attrs}) => {
          return (
            `<${href}>` +
            attrs
              .map(([name, value]) => {
                const escaped = value ? escapeLinkParamValue(value) : null;
                return escaped ? `;${name}=${escaped}` : '';
              })
              .join('')
          );
        })
        .join(',');
      payload.headers.append('Link', link);
    }
  }
}

// Provides two syntaxes for SXG-only behavior:
//
// For `<template data-sxg-only>` elements:
// - If SXG, they are "unwrapped" (i.e. their children promoted out of the <teplate>).
// - Else, they are deleted.
//
// For `<meta name=declare-issxg-var>` elements, they are replaced with
// `<script>window.isSXG=...</script>`, where `...` is true or false.
class SXGOnly {
  isSXG: boolean;
  modified = false;
  constructor(isSXG: boolean) {
    this.isSXG = isSXG;
  }
  register(rewriter: HTMLRewriter): void {
    rewriter
      .on('script[data-issxg-var]', {
        element: (script: Element) => {
          script.setInnerContent(`window.isSXG=${this.isSXG}`);
          this.modified = true;
        },
      })
      .on('template[data-sxg-only]', {
        element: (template: Element) => {
          if (this.isSXG) {
            template.removeAndKeepContent();
          } else {
            template.remove();
          }
          this.modified = true;
        },
      });
  }
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  onEnd(_payload: Response): void {}
}

// Processes HTML using the given processors.
//
// Out of an abundance of caution, this is limited to documents that are
// explicitly labeled as UTF-8 via Content-Type or <meta>. This could be
// expanded in the future, as the risk of misinterpreting type or encoding is
// rare and low-impact: producing `Link: rel=preload` headers for incorrect
// refs, which would waste bytes.
async function processHTML(
  payload: Response,
  processors: HTMLProcessor[]
): Promise<Response> {
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
  if (
    bom &&
    ((bom[0] === 0xfe && bom[1] === 0xff) ||
      (bom[0] === 0xff && bom[1] === 0xfe))
  ) {
    // Somebody set up us the BOM.
    return payload;
  }

  // Tee the original payload to be sure that HTMLRewriter doesn't make any
  // breaking modifications to the HTML. This is especially likely if the
  // document is in a non-ASCII-compatible encoding like UTF-16.
  [payload, toConsume] = teeResponse(payload);

  const rewriter = new HTMLRewriter()
    // Parse the meta tag, per the implementation in HTMLMetaCharsetParser::CheckForMetaCharset:
    // https://source.chromium.org/chromium/chromium/src/+/main:third_party/blink/renderer/core/html/parser/html_meta_charset_parser.cc;l=62-125;drc=7a0b88f6d5c015fd3c280b58c7a99d8e1dca28ac.
    // This differs slightly from what's described at https://github.com/whatwg/html/issues/6962, and
    // differs drastically from what's specified in
    // https://html.spec.whatwg.org/multipage/parsing.html#prescan-a-byte-stream-to-determine-its-encoding.
    .on('meta', {
      element: (meta: Element) => {
        // EncodingFromMetaAttributes:
        // https://source.chromium.org/chromium/chromium/src/+/main:third_party/blink/renderer/core/html/parser/html_parser_idioms.cc;l=362-393;drc=7a0b88f6d5c015fd3c280b58c7a99d8e1dca28ac
        const value = meta.getAttribute('charset');
        if (value) {
          if (value.toLowerCase() === 'utf-8') {
            known_utf8 = true;
          }
        } else if (
          meta.getAttribute('http-equiv')?.toLowerCase() === 'content-type' &&
          meta.getAttribute('content')?.match(HTML)?.[1]
        ) {
          // https://source.chromium.org/chromium/chromium/src/+/main:third_party/blink/renderer/core/html/parser/html_parser_idioms.cc;l=308-354;drc=984c3018ecb2ff818e900fdb7c743fc00caf7efe
          // https://html.spec.whatwg.org/multipage/urls-and-fetching.html#extracting-character-encodings-from-meta-elements
          // HTMLRewriter doesn't appear to decode HTML entities inside
          // attribute values, so a tag like
          //   <meta http-equiv=content-type content="text/html;charset=&quot;utf-8&quot;">
          // won't work. This could be supported in the future.
          known_utf8 = true;
        }
      },
    });
  processors.forEach(p => p.register(rewriter));
  toConsume = rewriter.transform(toConsume);
  const modifiedBody = await readIntoArray(toConsume.body, PAYLOAD_SIZE_LIMIT);
  if (!modifiedBody) {
    throw `The size of payload exceeds the limit ${PAYLOAD_SIZE_LIMIT}`;
  }

  // NOTE: It's also possible for a <?xml encoding="utf-16"?> directive to
  // override <meta>, per
  // https://source.chromium.org/chromium/chromium/src/+/main:third_party/blink/renderer/core/html/parser/text_resource_decoder.cc;l=427-441;drc=7a0b88f6d5c015fd3c280b58c7a99d8e1dca28ac.
  // (This differs from the specification, which prioritizes <meta> over
  // <?xml?>.) However, the case is very rare, and HTMLRewriter doesn't have a
  // handler for XML declarations, so we skip the check.

  if (known_utf8) {
    if (processors.some(p => p.modified)) {
      payload = new Response(modifiedBody, {
        status: payload.status,
        statusText: payload.statusText,
        headers: payload.headers,
      });
      // TODO: This modifiedBody is later extracted again via the readIntoArray
      // call in generateSxgResponse. Is this a significant performance hit? If
      // so, return the array from this function.
    }
    processors.forEach(p => p.onEnd(payload));
  }
  return payload;
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
  const now_in_seconds = Math.floor(Date.now() / 1000);
  const sxg = await worker.createSignedExchange(
    fallbackUrl,
    certOrigin,
    payload.status,
    payloadHeaders,
    payloadBody,
    now_in_seconds,
    signer,
    fetcher,
    headerIntegrityGet,
    headerIntegrityPut
  );
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
