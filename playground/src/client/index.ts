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

import puppeteer from 'puppeteer';

export async function startClient({
  certificateSpki,
  url,
}: {
  certificateSpki: string;
  url: string;
}) {
  const browser = await puppeteer.launch({
    devtools: true,
    args: [`--ignore-certificate-errors-spki-list=${certificateSpki}`],
  });
  const page = (await browser.pages())[0]!;

  const slow3g = puppeteer.networkConditions['Slow 3G']!;
  const cdpSession = await page.target().createCDPSession();
  await cdpSession.send('Network.emulateNetworkConditions', {
    offline: false,
    downloadThroughput: slow3g.download,
    uploadThroughput: slow3g.upload,
    latency: slow3g.latency,
  });

  await page.goto(`https://localhost:8443/srp/${encodeURIComponent(url)}`);
}
