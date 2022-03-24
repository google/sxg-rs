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

import {arrayBufferToBase64, escapeLinkParamValue} from './utils';

describe('arrayBufferToBase64', () => {
  it('works', () => {
    const a = new Uint8Array([1, 2, 3]);
    expect(arrayBufferToBase64(a.buffer)).toEqual('AQID');
  });
});

describe('escapeLinkParamValue', () => {
  it('returns tokens as-is', () => {
    expect(escapeLinkParamValue('hello-world')).toEqual('hello-world');
  });
  it('quotes empty string', () => {
    expect(escapeLinkParamValue('')).toEqual('""');
  });
  it('quotes non-tokens', () => {
    expect(escapeLinkParamValue('hello world')).toEqual('"hello world"');
  });
  it('escapes "', () => {
    expect(escapeLinkParamValue('hello, "world"')).toEqual(
      String.raw`"hello, \"world\""`
    );
  });
  it('escapes \\', () => {
    expect(escapeLinkParamValue(String.raw`hello\world`)).toEqual(
      String.raw`"hello\\world"`
    );
  });
  it('returns null for non-representable strings', () => {
    expect(escapeLinkParamValue('👋🌎')).toEqual(null);
  });
});
