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

// SXGs larger than 8MB are not accepted by
// https://github.com/google/webpackager/blob/main/docs/cache_requirements.md.
export const PAYLOAD_SIZE_LIMIT = 8000000;

// Calls process for each chunk from inputStream, up to maxSize. The last chunk
// may extend beyond maxSize; process should handle this case.
//
// Returns true if inputStream's total byte length is <= maxSize. After the
// promise resolves, the inputStream is closed and need not be canceled.
//
// (This function could be genericized to all TypedArrays, but no such
// interface exists in TypeScript.)
async function streamFrom(
  inputStream: ReadableStream,
  maxSize: number,
  process?: (currentPos: number, value: Uint8Array) => void
): Promise<boolean> {
  const reader = inputStream.getReader();
  let receivedSize = 0;
  for (;;) {
    const {value, done} = await reader.read();
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
export async function readArrayPrefix(
  inputStream: ReadableStream<Uint8Array> | null,
  size: number
): Promise<Uint8Array | null> {
  if (inputStream === null) {
    return new Uint8Array([]);
  }
  const received = new Uint8Array(size);
  const reachedEOS = await streamFrom(
    inputStream,
    size,
    (currentPos: number, value: Uint8Array) => {
      if (currentPos + value.length > size) {
        value = value.subarray(0, size - currentPos);
      }
      // value must be Uint8Array, or else this set() will overflow:
      received.set(value, currentPos);
    }
  );
  return reachedEOS ? null : received;
}

// Consumes the input stream, and returns a byte array containing the data in
// the input stream. Allocates about 2x the size of the stream (during the
// transfer from discontiguous to contiguous memory). If the input stream
// contains more bytes than maxSize, returns null.
//
// TODO: Consider reducing memory usage at the expense of increased CPU, by
// allocating a contiguous buffer upfront and growing it exponentially as
// necessary. It would be good to do so with a benchmark and an approximate
// distribution of body sizes in the wild (e.g. from HTTP Archive).
export async function readIntoArray(
  inputStream: ReadableStream<Uint8Array> | null,
  maxSize: number
): Promise<Uint8Array | null> {
  // NOTE: maxSize could be implemented more simply using TransformStream, but
  // non-identity TransformStreams don't work on Cloudflare Workers. (See
  // https://community.cloudflare.com/t/running-into-unimplemented-functionality/77343.)
  // Therefore, we cannot rely on Response.arrayBuffer() and must re-implement
  // https://streams.spec.whatwg.org/#readablestreamdefaultreader-read-all-bytes.
  // This is a rough port of blink::ScriptPromise::arrayBuffer
  // (https://source.chromium.org/chromium/chromium/src/+/main:third_party/blink/renderer/core/fetch/body.cc;l=186;drc=5539ecff898c79b0771340051d62bf81649e448d),
  // but using the variable-length chunks that the Streams API provides, rather
  // than 4K segments as defined by WTF::SharedBuffer::kSegmentSize
  // (https://source.chromium.org/chromium/chromium/src/+/main:third_party/blink/renderer/platform/wtf/shared_buffer.h;l=95;drc=5539ecff898c79b0771340051d62bf81649e448d).
  if (inputStream === null) {
    return new Uint8Array([]);
  }
  const segments: Uint8Array[] = [];
  let size = 0;
  const reachedEOS = await streamFrom(
    inputStream,
    maxSize,
    (_currentPos: number, value: Uint8Array) => {
      segments.push(value);
      size += value.length;
    }
  );
  // End-of-stream was not reached before maxSize.
  if (!reachedEOS) {
    return null;
  }
  // Avoid copying to a new buffer if there's no need to concatenate.
  if (segments.length === 1) {
    return segments[0] as Uint8Array;
  }
  // Concatenate segments into a contiguous buffer.
  const buffer = new Uint8Array(size);
  let bufferPos = 0;
  segments.forEach(segment => {
    const end = Math.min(segment.length, size - bufferPos);
    buffer.set(segment.subarray(0, end), bufferPos);
    bufferPos += end;
  });
  return buffer;
}

export function teeResponse(response: Response): [Response, Response] {
  const {body, headers, status} = response;
  const [body1, body2] = body?.tee() ?? [null, null];
  return [
    new Response(body1, {headers, status}),
    new Response(body2, {headers, status}),
  ];
}
