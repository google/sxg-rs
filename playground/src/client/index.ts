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

import puppeteer, {Browser} from 'puppeteer';
import {Page} from 'puppeteer';
import {
  clickSxgLink,
  clickNonsxgLink,
  setupObserver,
  getObserverResult,
} from './evaluated';

async function setupPage(page: Page) {
  await page.setCacheEnabled(false);
  await page.emulate(puppeteer.devices['Pixel 5']!);
  await page.emulateNetworkConditions(puppeteer.networkConditions['Fast 3G']!);
  await page.evaluateOnNewDocument(setupObserver);
}

async function measureLcp({
  browser,
  url,
  useSxg,
}: {
  browser: Browser;
  url: string;
  useSxg: boolean;
}) {
  const page = await browser.newPage();
  await setupPage(page);
  page.goto(`https://localhost:8443/srp/${encodeURIComponent(url)}`);
  await page.waitForNavigation({
    waitUntil: 'networkidle0',
  });
  if (useSxg) {
    await page.evaluate(clickSxgLink);
  } else {
    await page.evaluate(clickNonsxgLink);
  }
  await page.waitForNavigation({
    waitUntil: 'networkidle0',
  });
  const lcpResult = await page.evaluate(getObserverResult);
  await page.close();
  return lcpResult;
}

export async function runClient({
  certificateSpki,
  interactivelyInspect,
  repeatTime,
  url,
}: {
  certificateSpki: string;
  interactivelyInspect: boolean;
  repeatTime: number;
  url: string;
}) {
  const browser = await puppeteer.launch({
    devtools: interactivelyInspect,
    args: [`--ignore-certificate-errors-spki-list=${certificateSpki}`],
  });
  if (interactivelyInspect) {
    const page = (await browser.pages())[0]!;
    await setupPage(page);
    await page.goto(`https://localhost:8443/srp/${encodeURIComponent(url)}`);
    await new Promise<void>(resolve => {
      browser.on('disconnected', () => {
        resolve();
      });
    });
  } else {
    for (let i = 0; i < repeatTime; i += 1) {
      const sxgLcp = await measureLcp({
        browser,
        url,
        useSxg: true,
      });
      console.log(`LCP of SXG: ${sxgLcp}`);
      const nonsxgLcp = await measureLcp({
        browser,
        url,
        useSxg: false,
      });
      console.log(`LCP of Non-SXG: ${nonsxgLcp}`);
    }
    await browser.close();
  }
}
