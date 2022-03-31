/**
 * Copyright 2022 Google LLC
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
  PAYLOAD_SIZE_LIMIT,
  readArrayPrefix,
  readIntoArray,
  teeResponse,
} from './streams';
import {escapeLinkParamValue} from './utils';

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

// This logic is duplicated in `/sxg_rs/src/process_html.rs`, and any chages in
// `HTMLProcessor` and `processHTML` need to be replicated over there.
// TODO: Use `process_html.rs` to do everything.
interface HTMLProcessor {
  register(rewriter: HTMLRewriter): void;
  // Returns true iff the processor modified the HTML body. processHTML uses
  // the rewritten HTML body iff one of the processors returns true.
  modified: boolean;
  onEnd(payload: Response): void;
}

// Provides two syntaxes for SXG-only behavior:
//
// For `<template data-sxg-only>` elements:
// - If SXG, they are "unwrapped" (i.e. their children promoted out of the <teplate>).
// - Else, they are deleted.
//
// For `<meta name=declare-issxg-var>` elements, they are replaced with
// `<script>window.isSXG=...</script>`, where `...` is true or false.
export class SXGOnly {
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
export async function processHTML(
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

// If any <link rel=preload>s are found, they are promoted to Link headers.
// Later, generateSxgResponse will further modify the link header to support
// SXG preloading of eligible subresources.
export class PromoteLinkTagsToHeaders implements HTMLProcessor {
  modified = false;
  link_tags: {href: string; attrs: string[][]}[] = [];
  register(rewriter: HTMLRewriter): void {
    rewriter.on('link[rel~="preload" i][href][as]:not([data-sxg-no-header])', {
      element: (link: Element) => {
        const href = link.getAttribute('href');
        if (href?.match(URL_CHARS)) {
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
