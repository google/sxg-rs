// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use anyhow::{Error, Result};

// https://wicg.github.io/webpackage/draft-yasskin-httpbis-origin-signed-exchanges-impl.html#application-signed-exchange
pub fn build(
    fallback_url: &str,
    signature: &[u8],
    signed_headers: &[u8],
    payload_body: &[u8],
) -> Result<Vec<u8>> {
    // https://wicg.github.io/webpackage/draft-yasskin-http-origin-signed-responses.html#name-application-signed-exchange
    const SIG_LEN_LIMIT: usize = 16384;
    let sig_len = signature.len();
    if sig_len > SIG_LEN_LIMIT {
        return Err(Error::msg(format!(
            "sigLength {} is and larger than the limit {}",
            sig_len, SIG_LEN_LIMIT
        )));
    }
    const HEADER_LEN_LIMIT: usize = 524288;
    let header_len = signed_headers.len();
    if header_len > HEADER_LEN_LIMIT {
        return Err(Error::msg(format!(
            "headerLength {} is larger than the limit {}",
            header_len, HEADER_LEN_LIMIT
        )));
    }
    Ok([
        "sxg1-b3\0".as_bytes(),
        &(fallback_url.len() as u16).to_be_bytes(),
        fallback_url.as_bytes(),
        (sig_len as u32).to_be_bytes().get(1..4).unwrap(),
        (header_len as u32).to_be_bytes().get(1..4).unwrap(),
        signature,
        signed_headers,
        payload_body,
    ]
    .concat())
}
