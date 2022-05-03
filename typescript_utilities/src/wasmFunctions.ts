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

// `wrangler` uses `wasm-pack build --target no-modules` [^1] to build wasm.
// When the target is `no-modules`, `wasm-bindgen` declares a global variable
// to initialize wasm [^2].
// The default name of this global variable is `wasm_bindgen` [^3].
// The example is here [^4].
// [^1] https://github.com/cloudflare/wrangler/blob/37caf3cb08db3e84fee4c503e1a08f849371c4b8/src/build/mod.rs#L48
// [^2] https://github.com/rustwasm/wasm-bindgen/blob/dc9141e7ccd143e67a282cfa73717bb165049169/crates/cli/src/bin/wasm-bindgen.rs#L27
// [^3] https://github.com/rustwasm/wasm-bindgen/blob/dc9141e7ccd143e67a282cfa73717bb165049169/crates/cli-support/src/lib.rs#L208
// [^4] https://rustwasm.github.io/docs/wasm-bindgen/examples/without-a-bundler.html#using-the-older---target-no-modules
// eslint-disable-next-line @typescript-eslint/no-explicit-any
declare let wasm_bindgen: any;

type HeaderFields = Array<[string, string]>;

export type AcceptFilter = 'PrefersSxg' | 'AcceptsSxg';

export interface WasmRequest {
  body: number[];
  headers: HeaderFields;
  method: 'Get' | 'Post';
  url: string;
}

export interface WasmResponse {
  body: number[];
  headers: HeaderFields;
  status: number;
}

export type PresetContent =
  | ({kind: 'direct'} & WasmResponse)
  | {
      kind: 'toBeSigned';
      url: string;
      payload: WasmResponse;
      fallback: WasmResponse;
    };

export type CreateSignedExchangedOptions = {
  fallbackUrl: string;
  certOrigin: string;
  statusCode: number;
  payloadHeaders: HeaderFields;
  payloadBody: Uint8Array;
  skipProcessLink: boolean;
  nowInSeconds: number;
  signer: (input: Uint8Array) => Promise<Uint8Array>;
  subresourceFetcher: (request: WasmRequest) => Promise<WasmResponse>;
  headerIntegrityGet: (url: string) => Promise<WasmResponse>;
  headerIntegrityPut: (url: string, response: WasmResponse) => Promise<void>;
};

export interface ProcessHtmlOption {
  isSxg: boolean;
}

export interface WasmWorker {
  // eslint-disable-next-line @typescript-eslint/no-misused-new
  new (configYaml: string, certPem: string, issuerPem: string): WasmWorker;
  createRequestHeaders(
    accept_filter: AcceptFilter,
    fields: HeaderFields
  ): HeaderFields;
  processHtml(input: WasmResponse, option: ProcessHtmlOption): WasmResponse;
  createSignedExchange(options: CreateSignedExchangedOptions): WasmResponse;
  fetchOcspFromCa(
    fetcher: (request: WasmRequest) => Promise<WasmResponse>
  ): Uint8Array;
  getLastErrorMessage(): string;
  servePresetContent(
    url: string,
    ocsp: string
  ): Promise<PresetContent | undefined>;
  shouldRespondDebugInfo(): boolean;
  validatePayloadHeaders(fields: HeaderFields): void;
}

interface WasmFunctions {
  init: () => void;
  WasmWorker: WasmWorker;
}

export async function createWorker(
  wasmBytes: BufferSource,
  configYaml: string,
  certPem: string,
  issuerPem: string
) {
  await wasm_bindgen(wasmBytes);
  const {init, WasmWorker} = wasm_bindgen as WasmFunctions;
  init();
  return new WasmWorker(configYaml, certPem, issuerPem);
}
