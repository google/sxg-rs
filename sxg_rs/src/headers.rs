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

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct Headers(Vec<(String, String)>);

impl Headers {
    pub fn can_be_signed(&self, reject_stateful_headers: bool) -> bool {
        for (k, v) in self.0.iter() {
            if reject_stateful_headers && find_header_in(k, &STATEFUL_HEADERS) {
                return false;
            }
            if k.eq_ignore_ascii_case("cache-control") {
                // https://github.com/google/webpackager/blob/master/docs/cache_requirements.md#user-content-google-sxg-cache
                if v.contains("no-cache") || v.contains("private") {
                    return false;
                }
            }
        }
        true
    }
    pub fn get_signed_headers_bytes(&self, status_code: u16, mice_digest: &[u8]) -> Vec<u8> {
        use crate::cbor::DataItem;
        let mut entries: Vec<(&str, &str)> = vec![];
        for (k, v) in self.0.iter() {
            if find_header_in(k, &UNCACHED_HEADERS) || find_header_in(k, &STATEFUL_HEADERS) {
                continue;
            }
            entries.push((k, v));
        }
        let status_code = status_code.to_string();
        let digest = format!("mi-sha256-03={}", ::base64::encode(&mice_digest));
        entries.push((":status", &status_code));
        entries.push(("content-encoding", "mi-sha256-03"));
        entries.push(("digest", &digest));
        let cbor_data = DataItem::Map(
            entries.iter().map(|(key, value)| {
                (DataItem::ByteString(key.as_bytes()), DataItem::ByteString(value.as_bytes()))
            }).collect()
        );
        cbor_data.serialize()
    }
}

const UNCACHED_HEADERS: [&'static str; 11] = [
    // https://wicg.github.io/webpackage/draft-yasskin-httpbis-origin-signed-exchanges-impl.html#name-uncached-header-fields
    "connection",
    "keep-alive",
    "proxy-connection",
    "trailer",
    "transfer-encoding",
    "upgrade",

    // These headers are reserved for SXG
    ":status",
    "content-encoding",
    "digest",
    "variant-key-04",
    "variants-04",
];

const STATEFUL_HEADERS: [&'static str; 13] = [
    // https://wicg.github.io/webpackage/draft-yasskin-http-origin-signed-responses.html#stateful-headers
    "authentication-control",
    "authentication-info",
    "clear-site-data",
    "optional-www-authenticate",
    "proxy-authenticate",
    "proxy-authentication-info",
    "public-key-pins",
    "sec-websocket-accept",
    "set-cookie",
    "set-cookie2",
    "setprofile",
    "strict-transport-security",
    "www-authenticate",
];

fn find_header_in(header_name: &str, preset: &'static [&'static str]) -> bool {
    preset.iter().any(|x| x.eq_ignore_ascii_case(header_name))
}

