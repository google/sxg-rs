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

import type {WasmResponse} from './wasmFunctions';

// A cache of URL and HTTP response, and a function to get all URLs visited by
// this cache.
interface RecordedCache {
  get: (url: string) => Promise<WasmResponse>;
  put: (url: string, response: WasmResponse) => Promise<void>;
  visitedUrls: () => Set<string>;
}

// An in-memory cache to store URLs and their HTTP response.
export class SubresourceCache {
  #data = new Map<string, WasmResponse>();
  constructor() {}
  async #get(url: string): Promise<WasmResponse> {
    const x = this.#data.get(url);
    if (x) {
      return x;
    } else {
      return {
        body: [],
        headers: [],
        status: 404,
      };
    }
  }
  async #put(url: string, response: WasmResponse): Promise<void> {
    this.#data.set(url, response);
  }
  // Creates a recorder. All recorders share the same cached HTTP response, but
  // each recorder tracks their own list of which URLs have been visited.
  createRecorder(): RecordedCache {
    const urls = new Set<string>();
    return {
      get: async (url: string) => {
        urls.add(url);
        return await this.#get(url);
      },
      put: async (url: string, response: WasmResponse) => {
        urls.add(url);
        return await this.#put(url, response);
      },
      visitedUrls: () => {
        return urls;
      },
    };
  }
}
