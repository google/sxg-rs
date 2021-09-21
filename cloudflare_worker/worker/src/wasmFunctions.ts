/**
 * Copyright 2021 Google LLC
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

declare var wasm: any;
declare var wasm_bindgen: any;

type HeaderFields = Array<[string, string]>;

export type AcceptFilter = 'PrefersSxg' | 'AcceptsSxg';

export interface WasmRequest {
  body: number[],
  headers: HeaderFields,
  method: 'Get' | 'Post',
  url: string,
}

export interface WasmResponse {
  body: number[];
  headers: HeaderFields;
  status: number;
}

export type PresetContent = ({ kind: 'direct' } & WasmResponse) | {
  kind: 'toBeSigned',
  url: string,
  payload: WasmResponse,
  fallback: WasmResponse,
}

interface WasmWorker {
  new(configYaml: string, certPem: string, issuerPem: string): WasmWorker;
  createRequestHeaders(accept_filter: AcceptFilter, fields: HeaderFields): HeaderFields;
  createSignedExchange(
    fallbackUrl: string,
    certOrigin: string,
    statusCode: number,
    payloadHeaders: HeaderFields,
    payloadBody: Uint8Array,
    nowInSeconds: number,
    signer: (input: Uint8Array) => Promise<Uint8Array>,
    subresourceFetcher: (request: WasmRequest) => Promise<WasmResponse>,
    headerIntegrityGet: (url: string) => Promise<WasmResponse>,
    headerIntegrityPut: (url: string, response: WasmResponse) => Promise<void>,
  ): WasmResponse,
  fetchOcspFromCa(fetcher: (request: WasmRequest) => Promise<WasmResponse>): Uint8Array,
  getLastErrorMessage(): string;
  servePresetContent(url: string, ocsp: Uint8Array): PresetContent | undefined;
  shouldRespondDebugInfo(): boolean;
  validatePayloadHeaders(fields: HeaderFields): void,
}

interface WasmFunctions {
  init: () => void,
  WasmWorker: WasmWorker,
}

export const workerPromise = (async function initWorker() {
  await wasm_bindgen(wasm);
  const {
    init,
    WasmWorker,
  } = wasm_bindgen as WasmFunctions;
  init();
  return new WasmWorker(SXG_CONFIG, CERT_PEM, ISSUER_PEM);
})();
