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
import {runClient} from './client/';
import {spawnSxgServer} from './server/';

async function main() {
  program
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
    privateKeyJwk,
    privateKeyPem,
  });
  await runClient({
    url,
    certificateSpki: publicKeyHash,
    interactivelyInspect: opts['inspect'] ?? false,
    repeatTime: opts['repeatTime'],
  });
  await stopSxgServer();
}

main().catch(e => console.error(e));
