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

// https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.6
export const TOKEN = /^[!#$%&'*+.^_`|~0-9a-zA-Z-]+$/;

export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const data = Array.from(new Uint8Array(buffer));
  const s = data.map(x => String.fromCharCode(x)).join('');
  return btoa(s);
}

// Strings representable in a quoted-string, per
// https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.6 (including \x22
// ["] and \x5C [\])..
const ALLOWED_QUOTED_STRING_VALUE = /^[\t \x21-\x7E]*$/;

// Escapes a value for use as a Link header param, per
// https://datatracker.ietf.org/doc/html/rfc8288#section-3.
export function escapeLinkParamValue(value: string): string | null {
  if (value.match(TOKEN)) {
    return value;
  } else if (value.match(ALLOWED_QUOTED_STRING_VALUE)) {
    return (
      '"' +
      [...value]
        .map(char => (char === '\\' || char === '"' ? '\\' + char : char))
        .join('') +
      '"'
    );
  } else {
    return null;
  }
}
