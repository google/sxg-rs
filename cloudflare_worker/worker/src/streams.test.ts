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

import {
  readIntoArray,
} from './streams';

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
  it('reads a stream === SEGMENT_SIZE', async () => {
    const {writable, readable} = new TransformStream;
    const writer = writable.getWriter();
    writer.write(new TextEncoder().encode('.'.repeat(0x1000)));
    writer.close();
    const output = await readIntoArray(readable, 0x1000);
    expect(output).toEqual(new TextEncoder().encode('.'.repeat(0x1000)));
  });
  it('reads a stream > SEGMENT_SIZE', async () => {
    const {writable, readable} = new TransformStream;
    const writer = writable.getWriter();
    for (let i = 0; i < 2; i++) {
      // Write 4000 bytes. This means the second chunk will overlap the segment
      // boundary.
      writer.write(new TextEncoder().encode('hello'.repeat(800)));
    }
    writer.close();
    const output = await readIntoArray(readable, 8000);
    expect(output).toEqual(new TextEncoder().encode('hello'.repeat(1600)));
  });
  it('errors if stream > maxSize', async () => {
    const input = new Response('hello').body;
    const output = await readIntoArray(input, 2);
    expect(output).toBe(null);
  });
})
