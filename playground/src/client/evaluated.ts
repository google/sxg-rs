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

export function clickSearchResultLink() {
  const p = document.createElement('p');
  p.textContent = 'Puppeteer clicks the link, starting to navigate.';
  document.body.appendChild(p);
  document.getElementById('search-result-link')!.click();
}

declare global {
  interface Window {
    lcpResult: number | null;
  }
}

export function setupObserver() {
  window.lcpResult = null;
  // TODO: Check whether we can use npm package `web-vitals` here.
  // The `web-vitals` package not only adds the performance observer, but also
  // [handles](https://github.com/GoogleChrome/web-vitals/blob/ed70ed4b56d3f0573da7ca8ec324e630a04beaf2/src/getLCP.ts#L64-L66)
  // some user input DOM event.
  const observer = new PerformanceObserver(entryList => {
    const entries = entryList.getEntries();
    const lastEntry = entries[entries.length - 1]!;
    if (lastEntry.entryType === 'largest-contentful-paint') {
      window.lcpResult = lastEntry.startTime;
    }
  });
  observer.observe({type: 'largest-contentful-paint', buffered: true});
}

export function getObserverResult() {
  return window.lcpResult;
}
