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

import {WasmRequest, WasmResponse} from './wasmFunctions';
import {RequestInit, Response} from 'node-fetch';
import fetch from 'node-fetch';

export type Fetcher = (request: WasmRequest) => Promise<WasmResponse>;

async function wasmFromResponse(response: Response): Promise<WasmResponse> {
  return {
    body: Array.from(new Uint8Array(await response.arrayBuffer())),
    headers: Array.from(response.headers),
    status: response.status,
  };
}

export async function fetcher(request: WasmRequest) {
  const PAYLOAD_SIZE_LIMIT = 8000000;

  const requestInit: RequestInit = {
    headers: request.headers,
    method: request.method,
  };
  if (request.body.length > 0) {
    requestInit.body = Buffer.from(request.body);
  }
  const response = await fetch(request.url, requestInit);
  const body = await response.arrayBuffer();
  if (body.byteLength > PAYLOAD_SIZE_LIMIT) {
    throw `The size of payload exceeds the limit ${PAYLOAD_SIZE_LIMIT}`;
  }

  return await wasmFromResponse(
    new Response(Buffer.from(body), {
      headers: response.headers,
      status: response.status,
    })
  );
}
