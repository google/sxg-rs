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

import assert from 'assert';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

import Fastify from 'fastify';

import {fetcher} from './fetcher';
import {
  createSearchResultPage,
  createSearchResultPageWithoutSxg,
} from './searchResultPage';
import {fromJwk as createSignerFromJwk} from './signer';
import {WasmResponse, createWorker} from './wasmFunctions';

const wasmBuffer = fs.readFileSync(
  path.resolve(
    __dirname,
    '..',
    '..',
    'cloudflare_worker',
    'pkg',
    'cloudflare_worker_bg.wasm'
  )
);

// eslint-disable-next-line @typescript-eslint/no-unused-vars
async function headerIntegrityGet(_url: string): Promise<WasmResponse> {
  return {
    body: [],
    headers: [],
    status: 404,
  };
}

async function headerIntegrityPut() {}

export const SXG_CONFIG = `
cert_url_dirname: ".well-known/sxg-certs"
forward_request_headers:
  - user-agent
  - cf-ipcountry
reserved_path: ".sxg"
respond_debug_info: false
strip_request_headers: []
strip_response_headers:
  - set-cookie
  - strict-transport-security
validity_url_dirname: ".well-known/sxg-validity"
`;

// Spawns a SXG server that runs in background, and returns a function to stop
// the server.
export async function spawnSxgServer({
  certificatePem,
  privateKeyJwk,
  privateKeyPem,
}: {
  certificatePem: string;
  privateKeyJwk: Object;
  privateKeyPem: string;
}) {
  const signer = createSignerFromJwk(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (crypto.webcrypto as any).subtle,
    privateKeyJwk
  );
  const worker = await createWorker(
    wasmBuffer,
    SXG_CONFIG,
    certificatePem,
    certificatePem
  );
  const sxgList: WasmResponse[] = [];
  async function createSxgIntoList(innerUrl: string, certOrigin: string) {
    let sxgPayload = await fetcher({
      url: innerUrl,
      body: [],
      method: 'Get',
      headers: [],
    });
    sxgPayload = worker.processHtml(sxgPayload, {isSxg: true});
    // TODO(PR#157): Use `handleRequest` function in `cloudflare_worker/worker/src/index.ts`.
    const sxg = await worker.createSignedExchange(
      innerUrl,
      certOrigin,
      sxgPayload.status,
      sxgPayload.headers,
      new Uint8Array(sxgPayload.body),
      Date.now() / 1000,
      signer,
      fetcher,
      headerIntegrityGet,
      headerIntegrityPut
    );
    sxgList.push(sxg);
    return sxgList.length - 1;
  }

  const fastify = Fastify({
    logger: false,
    https: {
      key: privateKeyPem,
      cert: certificatePem,
    },
  });
  fastify.get('/srp/:url', async (request, reply) => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const sxgInnerUrl: string = (request.params as any).url;
    let sxgId: number;
    try {
      sxgId = await createSxgIntoList(
        sxgInnerUrl,
        `https://${request.hostname}`
      );
    } catch (e) {
      return `Failed to create SXG. ${e}`;
    }
    reply.header('content-type', 'text/html');
    return createSearchResultPage(sxgInnerUrl, `/sxg/${sxgId}`);
  });
  fastify.get('/nonsxg-srp/:url', async (request, reply) => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const sxgInnerUrl: string = (request.params as any).url;
    reply.header('content-type', 'text/html');
    return createSearchResultPageWithoutSxg(sxgInnerUrl);
  });
  fastify.get('/.well-known/sxg-certs/*', async (request, reply) => {
    const x = worker.servePresetContent(
      `https://localhost:8443${request.url}`,
      'abcd'
    );
    assert(x?.kind === 'direct');
    x.headers.forEach(([k, v]) => reply.header(k, v));
    return Buffer.from(x.body);
  });
  fastify.get('/sxg/:id', async (request, reply) => {
    const params = request.params as {id: string};
    const sxg = sxgList[parseInt(params.id)]!;
    sxg.headers.forEach(([k, v]) => reply.header(k, v));
    return Buffer.from(sxg.body);
  });
  await fastify.listen(8443, '0.0.0.0');
  return async function stopServer() {
    await fastify.close();
  };
}
