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

import createDomPurify from 'dompurify';
import {JSDOM} from 'jsdom';

const DomPurify = createDomPurify(new JSDOM('').window as unknown as Window);

function createLinkFromUntrustedString(href: string, text: string) {
  return DomPurify.sanitize(
    `<a id="search-result-link" href=${href}>${text}</a>`,
    {ALLOWED_TAGS: ['a']}
  );
}

export function createSearchResultPageWithoutSxg(
  targetInnerUrl: string
): string {
  return `
    <p>This is a Search Result Page without using prefetch.</p>
    ${createLinkFromUntrustedString(targetInnerUrl, targetInnerUrl)}
    <p>Click the link to load their page.</p>
  `;
}

export function createSearchResultPage(
  targetInnerUrl: string,
  sxgOuterUrl: string
): string {
  return `
    <p>This is a Search Result Page using Signed Exchanges</p>
    ${createLinkFromUntrustedString(sxgOuterUrl, targetInnerUrl)}
    <link rel="prefetch" as="document" href="${sxgOuterUrl}">
    <p>
      Resources are being prefetched.
      Open browser's developer tool to check loading state.
    </p>
  `;
}
