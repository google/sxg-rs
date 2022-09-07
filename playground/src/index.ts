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

import fs from 'fs';
import {program, Option} from 'commander';

import {IsolationMode, runBatchClient, runInteractiveClient} from './client/';
import {NOT_EMULATED} from './client/emulationOptions';
import {createSelfSignedCredentials} from './server/credentials';
import {spawnSxgServer} from './server/';

async function main() {
  program
    .addOption(
      new Option(
        '--crawler-user-agent <string>',
        'The user-agent request header to be sent to the website server'
        // The defalt value is from https://developers.google.com/search/docs/advanced/crawling/overview-google-crawlers#googlebot-smartphone
      ).default(
        'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.96 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
      )
    )
    .addOption(
      new Option(
        '--emulate-device <string>',
        'The device that puppeteer emulates'
      )
        .choices(['Pixel 5', 'iPhone XR', NOT_EMULATED])
        .default('Pixel 5')
    )
    .addOption(
      new Option(
        '--emulate-network <string>',
        'The network condition that puppeteer emulates'
      )
        .choices(['Slow 3G', 'Fast 3G', NOT_EMULATED])
        .default(NOT_EMULATED)
    )
    .addOption(
      new Option('--single-url <url>', 'A single URL to be measured').conflicts(
        'urlList'
      )
    )
    .addOption(
      new Option(
        '--url-list <file name>',
        'A JSON file containing many URLs to be measured'
      ).conflicts(['inspect', 'singleUrl'])
    )
    .addOption(
      new Option(
        '--sxg-config <file name>',
        'A YAML file containing the sxg-rs config'
      )
    )
    .addOption(
      new Option(
        '--inspect',
        'open a Chrome window and use ChromeDevTools to preview SXG'
      )
        .default(false)
        .conflicts(['repeatTime', 'urlList'])
    )
    .addOption(
      new Option(
        '--isolateBrowserContext',
        'create a new browser context when testing each URL'
      ).default(false)
    )
    .addOption(
      new Option('--repeat-time <number>', 'measure LCP multiple times')
        .argParser(x => parseInt(x))
        .default(1)
        .conflicts('inspect')
    );
  program.parse();
  const opts = program.opts() as {
    crawlerUserAgent: string;
    emulateDevice: string;
    emulateNetwork: 'Fast 3G' | 'Slow 3G' | typeof NOT_EMULATED;
    inspect: boolean;
    isolateBrowserContext: boolean;
    repeatTime: number;
    singleUrl?: string;
    sxgConfig?: string;
    urlList?: string;
  };
  let urlList = [];
  if (opts.singleUrl) {
    urlList.push(opts.singleUrl);
  } else if (opts.urlList) {
    urlList = JSON.parse(fs.readFileSync(opts.urlList, 'utf8'));
  } else {
    throw new Error('Please specify either --single-url or --url-list');
  }
  const {certificatePem, privateKeyJwk, privateKeyPem, publicKeyHash} =
    await createSelfSignedCredentials('example.com');
  const stopSxgServer = await spawnSxgServer({
    certificatePem,
    crawlerUserAgent: opts.crawlerUserAgent,
    privateKeyJwk,
    privateKeyPem,
    sxgConfig: opts.sxgConfig && fs.readFileSync(opts.sxgConfig, 'utf8'),
  });
  if (opts.inspect) {
    await runInteractiveClient({
      url: urlList[0],
      certificateSpki: publicKeyHash,
      emulationOptions: {
        device: opts.emulateDevice,
        networkCondition: opts.emulateNetwork,
      },
      isolationMode: opts.isolateBrowserContext
        ? IsolationMode.IncognitoBrowserContext
        : IsolationMode.ClearBrowserCache,
    });
  } else {
    await runBatchClient({
      urlList,
      certificateSpki: publicKeyHash,
      emulationOptions: {
        device: opts.emulateDevice,
        networkCondition: opts.emulateNetwork,
      },
      isolationMode: opts.isolateBrowserContext
        ? IsolationMode.IncognitoBrowserContext
        : IsolationMode.ClearBrowserCache,
      repeatTime: opts.repeatTime,
    });
  }
  await stopSxgServer();
}

main().catch(e => console.error(e));
