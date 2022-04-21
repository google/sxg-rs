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

import fetch from 'node-fetch';
import https from 'https';
import puppeteer, {Browser} from 'puppeteer';
import {Page} from 'puppeteer';
import {
  CreateSignedExchangeRequest,
  CreateSignedExchangeResponse,
} from '../schema';
import {EmulationOptions, NOT_EMULATED} from './emulationOptions';
import {
  clickSearchResultLink,
  setupObserver,
  getObserverResult,
} from './evaluated';
import {
  createSearchResultPage,
  createSearchResultPageWithoutSxg,
} from './templates';
import {
  EstimatedValue,
  estimateMeasurements,
  formatEstimatedValue,
} from './statistics';

async function setupPage(page: Page, emulationOptions: EmulationOptions) {
  const {device, networkCondition} = emulationOptions;
  if (device !== NOT_EMULATED) {
    await page.emulate(puppeteer.devices[device]!);
  }
  if (networkCondition !== NOT_EMULATED) {
    await page.emulateNetworkConditions(
      puppeteer.networkConditions[networkCondition]!
    );
  }
  await page.evaluateOnNewDocument(setupObserver);
}

// Calls the backend server to create a signed exchange. This uses node-js
// directly, instead of using puppeteer.
async function createSignedExchange(
  request: CreateSignedExchangeRequest
): Promise<CreateSignedExchangeResponse> {
  const rsp = await fetch('https://localhost:8443/create-sxg', {
    method: 'POST',
    body: JSON.stringify(request),
    agent: new https.Agent({
      // The localhost:8443 uses a self-signed certificate, so we have to
      // disable the SSL validation.
      rejectUnauthorized: false,
    }),
  });
  return JSON.parse(await rsp.text());
}

// Creates a URL of a Search Result Page of a given target URL and an optional
// SXG outer URL.
function getSearchResultPageUrl(targetUrl: string, sxgOuterUrl?: string) {
  if (sxgOuterUrl) {
    return `data:text/html,${createSearchResultPage(targetUrl, sxgOuterUrl)}`;
  } else {
    return `data:text/html,${createSearchResultPageWithoutSxg(targetUrl)}`;
  }
}

// Measures LCP of the given URL in an existing Chrome tab (page).
async function measureLcp({
  page,
  emulationOptions,
  url,
  sxgOuterUrl,
}: {
  page: Page;
  emulationOptions: EmulationOptions;
  url: string;
  sxgOuterUrl?: string;
}) {
  await setupPage(page, emulationOptions);
  page.goto(getSearchResultPageUrl(url, sxgOuterUrl));
  try {
    await page.waitForNavigation({
      waitUntil: 'networkidle0',
    });
  } catch (e) {
    if (e instanceof puppeteer.errors['TimeoutError']!) {
      return null;
    } else {
      throw e;
    }
  }
  await page.evaluate(clickSearchResultLink);
  try {
    await page.waitForNavigation({
      waitUntil: 'networkidle0',
    });
  } catch (e) {
    if (e instanceof puppeteer.errors['TimeoutError']!) {
      return null;
    } else {
      throw e;
    }
  }
  return await page.evaluate(getObserverResult);
}

// The method to isolate cache between multiple tests.
export enum IsolationMode {
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
  emulationOptions,
  sxgOuterUrl,
  url,
}: {
  browser: Browser;
  isolationMode: IsolationMode;
  emulationOptions: EmulationOptions;
  sxgOuterUrl?: string;
  url: string;
}): Promise<number | null> {
  if (isolationMode === IsolationMode.IncognitoBrowserContext) {
    const context = await browser.createIncognitoBrowserContext();
    const page = await context.newPage();
    const lcpResult = await measureLcp({
      page,
      emulationOptions,
      url,
      sxgOuterUrl,
    });
    await page.close();
    await context.close();
    return lcpResult;
  } else {
    const page = await browser.newPage();
    const client = await page.target().createCDPSession();
    await client.send('Network.clearBrowserCookies');
    await client.send('Network.clearBrowserCache');
    await client.detach();
    const lcpResult = await measureLcp({
      page,
      emulationOptions,
      url,
      sxgOuterUrl,
    });
    await page.close();
    return lcpResult;
  }
}

// Measures the LCP of given URL multiple times and returns statistical
// analysis.
async function statisticallyEstimateLcp({
  browser,
  isolationMode,
  emulationOptions,
  repeatTime,
  sxgOuterUrl,
  url,
}: {
  browser: Browser;
  isolationMode: IsolationMode;
  emulationOptions: EmulationOptions;
  repeatTime: number;
  sxgOuterUrl?: string;
  url: string;
}): Promise<EstimatedValue> {
  const values: number[] = [];
  if (sxgOuterUrl !== undefined) {
    console.log(`Measuring SXG LCP of ${url}`);
  } else {
    console.log(`Measuring non-SXG LCP of ${url}`);
  }
  for (let i = 0; i < repeatTime; i += 1) {
    const current = await createPageAndMeasureLcp({
      browser,
      isolationMode,
      emulationOptions,
      url,
      sxgOuterUrl,
    });
    if (repeatTime > 1) {
      console.log(`LCP ${i + 1} / ${repeatTime}: ${current?.toFixed(0)}`);
    }
    if (current !== null) {
      values.push(current);
    }
  }
  return estimateMeasurements(values);
}

export async function runInteractiveClient({
  certificateSpki,
  isolationMode,
  emulationOptions,
  url,
}: {
  certificateSpki: string;
  isolationMode: IsolationMode;
  emulationOptions: EmulationOptions;
  url: string;
}) {
  let sxgOuterUrl: string;
  const sxg = await createSignedExchange({
    innerUrl: url,
  });
  if (sxg[0] === 'Ok') {
    sxgOuterUrl = sxg[1].outerUrl;
  } else if (sxg[0] === 'Err') {
    console.log(`Failed to create SXG for ${url}\n${sxg[1].message}`);
    return;
  } else {
    throw 'Unreachable';
  }
  const browser = await puppeteer.launch({
    devtools: true,
    args: [`--ignore-certificate-errors-spki-list=${certificateSpki}`],
  });
  let page: Page;
  if (isolationMode === IsolationMode.ClearBrowserCache) {
    page = (await browser.pages())[0]!;
  } else {
    const context = await browser.createIncognitoBrowserContext();
    page = await context.newPage();
  }
  await setupPage(page, emulationOptions);
  await page.goto(getSearchResultPageUrl(url, sxgOuterUrl));
  await new Promise<void>(resolve => {
    browser.on('disconnected', () => {
      resolve();
    });
  });
}

export async function runBatchClient({
  certificateSpki,
  isolationMode,
  emulationOptions,
  repeatTime,
  urlList,
}: {
  certificateSpki: string;
  isolationMode: IsolationMode;
  emulationOptions: EmulationOptions;
  repeatTime: number;
  urlList: string[];
}) {
  const browser = await puppeteer.launch({
    args: [`--ignore-certificate-errors-spki-list=${certificateSpki}`],
  });
  for (const url of urlList) {
    let sxgOuterUrl: string;
    const sxg = await createSignedExchange({
      innerUrl: url,
    });
    if (sxg[0] === 'Ok') {
      console.log(`Created SXG for ${url}`);
      sxgOuterUrl = sxg[1].outerUrl;
    } else if (sxg[0] === 'Err') {
      console.error(`Failed to create SXG for ${url}\n${sxg[1].message}`);
      continue;
    } else {
      throw 'Unreachable';
    }
    if (repeatTime > 0) {
      const nonSxgLcp = await statisticallyEstimateLcp({
        browser,
        emulationOptions,
        isolationMode,
        repeatTime,
        sxgOuterUrl: undefined,
        url,
      });
      const sxgLcp = await statisticallyEstimateLcp({
        browser,
        emulationOptions,
        isolationMode,
        repeatTime,
        sxgOuterUrl,
        url,
      });
      console.log(
        `SXG changes LCP from ${formatEstimatedValue(
          nonSxgLcp
        )} to ${formatEstimatedValue(sxgLcp)}`
      );
    }
  }
  await browser.close();
}
