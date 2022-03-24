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

import {readIntoArray} from './streams';

describe('readIntoArray', () => {
  it('reads a stream <= maxSize', async () => {
    const input = new Response('hello').body;
    const output = await readIntoArray(input, 1000);
    expect(output).toEqual(new TextEncoder().encode('hello'));
  });
  it('reads an empty stream', async () => {
    const input = new Response('').body;
    const output = await readIntoArray(input, 1000);
    expect(output).toEqual(new TextEncoder().encode(''));
  });
  it('reads a stream with two chunks', async () => {
    const {writable, readable} = new TransformStream();
    const write = (async () => {
      const writer = writable.getWriter();
      for (let i = 0; i < 2; i++) {
        await writer.write(new TextEncoder().encode('hello'));
      }
      await writer.close();
    })();
    const output = await readIntoArray(readable, 0x1000);
    expect(output).toEqual(new TextEncoder().encode('hellohello'));
    await write;
  });
  it('errors if stream > maxSize', async () => {
    const input = new Response('hello').body;
    const output = await readIntoArray(input, 2);
    expect(output).toBe(null);
  });
  it('errors if second chunk > maxSize', async () => {
    const {writable, readable} = new TransformStream();
    const write = (async () => {
      const writer = writable.getWriter();
      for (let i = 0; i < 2; i++) {
        await writer.write(new TextEncoder().encode('hello'));
      }
      // Don't close the writer; it'll be cancelled by readIntoArray.
    })();
    const output = await readIntoArray(readable, 7);
    expect(output).toBe(null);
    await write;
  });
});
