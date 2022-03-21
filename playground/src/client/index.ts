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
  await page.emulate(puppeteer.devices['Pixel 5']!);
  await page.emulateNetworkConditions(puppeteer.networkConditions['Fast 3G']!);
  await page.evaluateOnNewDocument(setupObserver);
}

// Measures LCP of the given URL in an existing Chrome tab (page).
async function measureLcp({
  page,
  url,
  useSxg,
}: {
  page: Page;
  url: string;
  useSxg: boolean;
}) {
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
  return await page.evaluate(getObserverResult);
}

// The method to isolate cache between multiple tests.
enum IsolationMode {
  // The entire browser is cleared before running a test. The drawback is that
  // tests can not run in parallel.
  ClearBrowserCache,
  // Each test runs in an individual incognito browser context. The drawback is
  // that incognito mode might behave differently from regular context.
  IncognitoBrowserContext,
}

// Opens a new Chrome tab (page), and measures the LCP of given URL.
async function createPageAndMeasureLcp({
  browser,
  isolationMode,
  url,
  useSxg,
}: {
  browser: Browser;
  isolationMode: IsolationMode;
  url: string;
  useSxg: boolean;
}) {
  if (isolationMode === IsolationMode.IncognitoBrowserContext) {
    const context = await browser.createIncognitoBrowserContext();
    const page = await context.newPage();
    const lcpResult = await measureLcp({page, url, useSxg});
    await page.close();
    await context.close();
    return lcpResult;
  } else {
    const page = await browser.newPage();
    const client = await page.target().createCDPSession();
    await client.send('Network.clearBrowserCookies');
    await client.send('Network.clearBrowserCache');
    await client.detach();
    const lcpResult = await measureLcp({page, url, useSxg});
    await page.close();
    return lcpResult;
  }
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
      const sxgLcp = await createPageAndMeasureLcp({
        browser,
        isolationMode: IsolationMode.ClearBrowserCache,
        url,
        useSxg: true,
      });
      console.log(`LCP of SXG: ${sxgLcp}`);
      const nonsxgLcp = await createPageAndMeasureLcp({
        browser,
        isolationMode: IsolationMode.ClearBrowserCache,
        url,
        useSxg: false,
      });
      console.log(`LCP of Non-SXG: ${nonsxgLcp}`);
    }
    await browser.close();
  }
}
