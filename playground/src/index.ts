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

import {program, Option} from 'commander';

import {createSelfSignedCredentials} from './server/credentials';
import {IsolationMode, runClient} from './client/';
import {spawnSxgServer} from './server/';

async function main() {
  program
    .addOption(
      new Option(
        '--crawler-user-agent <string>',
        'the user-agent request header to be sent to the website server'
        // The defalt value is from https://developers.google.com/search/docs/advanced/crawling/overview-google-crawlers#googlebot-smartphone
      ).default(`Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.96 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`)
    )
    .addOption(
      new Option(
        '--url <url>',
        'A single URL to be measured'
      ).makeOptionMandatory(true)
    )
    .addOption(
      new Option(
        '--inspect',
        'open a Chrome window and use ChromeDevTools to preview SXG'
      )
    )
    .addOption(
      new Option(
        '--isolateBrowserContext',
        'create a new browser context when testing each URL'
      )
    )
    .addOption(
      new Option('--repeat-time <number>', 'measure LCP multiple times')
        .argParser(x => parseInt(x))
        .default(1)
    );
  program.parse();
  const opts = program.opts();
  const url: string = opts['url'];
  const {certificatePem, privateKeyJwk, privateKeyPem, publicKeyHash} =
    await createSelfSignedCredentials(new URL(opts['url']).hostname);
  const stopSxgServer = await spawnSxgServer({
    certificatePem,
    crawlerUserAgent: opts['crawlerUserAgent'],
    privateKeyJwk,
    privateKeyPem,
  });
  await runClient({
    url,
    certificateSpki: publicKeyHash,
    interactivelyInspect: opts['inspect'] ?? false,
    isolationMode: opts['isolateBrowserContext']
      ? IsolationMode.IncognitoBrowserContext
      : IsolationMode.ClearBrowserCache,
    repeatTime: opts['repeatTime'],
  });
  await stopSxgServer();
}

main().catch(e => console.error(e));
