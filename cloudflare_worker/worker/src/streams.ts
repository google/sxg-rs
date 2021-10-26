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

// Calls process for each chunk from inputStream, up to maxSize. The last chunk
// may extend beyond maxSize; process should handle this case.
//
// Returns true if inputStream's total byte length is <= maxSize. After the
// promise resolves, the inputStream is closed and need not be canceled.
//
// (This function could be genericized to all TypedArrays, but no such
// interface exists in TypeScript.)
async function streamFrom(inputStream: ReadableStream, maxSize: number,
                          process?: (currentPos: number, value: Uint8Array) => void): Promise<boolean> {
  const reader = inputStream.getReader();
  let receivedSize = 0;
  while (true) {
    const { value, done } = await reader.read();
    if (value) {
      process?.(receivedSize, value);
      receivedSize += value.length;
      if (receivedSize > maxSize) {
        reader.releaseLock();
        inputStream.cancel();
        return false;
      }
    }
    if (done) {
      // This implies closed per
      // https://streams.spec.whatwg.org/#default-reader-read.
      return true;
    }
  }
}

// Consumes the input stream, and returns a byte array containing the first
// size bytes, or null if there aren't enough bytes.
export async function readArrayPrefix(inputStream: ReadableStream<Uint8Array> | null,
                                      size: number): Promise<Uint8Array | null> {
  if (inputStream === null) {
    return new Uint8Array([]);
  }
  const received = new Uint8Array(size);
  let reachedEOS = await streamFrom(inputStream, size, (currentPos: number, value: Uint8Array) => {
    if (currentPos + value.length > size) {
      value = value.subarray(0, size - currentPos);
    }
    // value must be Uint8Array, or else this set() will overflow:
    received.set(value, currentPos);
  });
  return reachedEOS ? null : received;
}

// Bytes of contiguous memory to allocate at a time.
// https://source.chromium.org/chromium/chromium/src/+/main:third_party/blink/renderer/platform/wtf/shared_buffer.h;l=95;drc=5539ecff898c79b0771340051d62bf81649e448d
const SEGMENT_SIZE = 0x1000;

// Consumes the input stream, and returns a byte array containing the data in
// the input stream, not allocating more than maxSize. If the input stream
// contains more bytes than maxSize, returns null.
export async function readIntoArray(inputStream: ReadableStream<Uint8Array> | null,
                                    maxSize: number): Promise<Uint8Array | null> {
  // NOTE: maxSize could be implemented more simply using TransformStream, but
  // non-identity TransformStreams don't work on Cloudflare Workers. (See
  // https://community.cloudflare.com/t/running-into-unimplemented-functionality/77343.)
  // Therefore, we cannot rely on Response.arrayBuffer() and must re-implement
  // https://streams.spec.whatwg.org/#readablestreamdefaultreader-read-all-bytes.
  // This is a rough port of ScriptPromise::arrayBuffer
  // (https://source.chromium.org/chromium/chromium/src/+/main:third_party/blink/renderer/core/fetch/body.cc;l=186;drc=5539ecff898c79b0771340051d62bf81649e448d),
  // on the assumption that its performance has been well-informed. (That may
  // not be a safe assumption; it looks like its behavior hasn't changed in
  // quite a while.)
  if (inputStream === null) {
    return new Uint8Array([]);
  }
  let segments: Uint8Array[] = [];
  let size = 0;
  let reachedEOS = await streamFrom(inputStream, maxSize, (currentPos: number, value: Uint8Array) => {
    //console.log(`iteration [${currentPos}, ${value.length}]`);
    for (let innerPos = 0; innerPos < value.length;) {
      // Allocate a new segment if the last one is full (and on first run).
      const segmentPos = (currentPos + innerPos) % SEGMENT_SIZE;
      if (segmentPos === 0) {
        segments.push(new Uint8Array(SEGMENT_SIZE));
      }
      // Write the largest contiguous array possible (to the end of value or
      // segment, whichever's first).
      const lastSegment = segments[segments.length-1] as Uint8Array;
      const innerEnd = Math.min(value.length,
                                innerPos + (lastSegment.length - segmentPos));
      // value must be Uint8Array, or else this set() will overflow:
      lastSegment.set(value.subarray(innerPos, innerEnd), segmentPos);
      innerPos = innerEnd;
    }
    size = currentPos + value.length;
  });
  if (!reachedEOS) {
    return null;
  }
  const buffer = new Uint8Array(size);
  let bufferPos = 0;
  segments.forEach((segment) => {
    const end = Math.min(segment.length, size - bufferPos);
    buffer.set(segment.subarray(0, end), bufferPos);
    bufferPos += end;
  });
  return buffer;
}

export function teeResponse(response: Response): [Response, Response] {
  const {
    body,
    headers,
    status,
  } = response;
  const [body1, body2] = body?.tee() ?? [null, null];
  return [
      new Response(body1, { headers, status }),
      new Response(body2, { headers, status }),
  ];
}
