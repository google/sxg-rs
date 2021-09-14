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

use crate::fetcher::{Fetcher, NULL_FETCHER};
use crate::headers::Headers;
use crate::http::{HttpRequest, HttpResponse, Method};
use crate::http_cache::{HttpCache, NullCache};
use crate::utils::{get_sha, signed_headers_and_payload};
use anyhow::{anyhow, Error, Result};
use async_trait::async_trait;
use once_cell::sync::Lazy;
use std::collections::BTreeSet;
use url::Url;

#[async_trait(?Send)]
pub trait HeaderIntegrityFetcher {
    async fn fetch(&mut self, url: &str) -> Result<String>;
}

pub fn new_fetcher<'a, F: Fetcher, C: HttpCache>(
    subresource_fetcher: F,
    header_integrity_cache: &'a mut C,
    strip_response_headers: &'a BTreeSet<String>,
) -> HeaderIntegrityFetcherImpl<'a, F, C> {
    HeaderIntegrityFetcherImpl {
        subresource_fetcher,
        header_integrity_cache,
        strip_response_headers,
    }
}

pub struct HeaderIntegrityFetcherImpl<'a, F: Fetcher, C: HttpCache> {
    subresource_fetcher: F,
    header_integrity_cache: &'a mut C,
    strip_response_headers: &'a BTreeSet<String>,
}

// A synthesized error response that can be cached, to prevent overloading the
// origin for non-SXG subresources that it preloads.
static ERROR_RESPONSE: Lazy<HttpResponse> = Lazy::new(|| HttpResponse {
    body: vec![],
    headers: vec![("cache-control".into(), "max-age=3600".into())],
    status: 406,
});

#[async_trait(?Send)]
impl<'a, F: Fetcher, C: HttpCache> HeaderIntegrityFetcher for HeaderIntegrityFetcherImpl<'a, F, C> {
    async fn fetch(&mut self, url: &str) -> Result<String> {
        let integrity_response = match self.header_integrity_cache.get(url).await {
            // Use cached header-integrity.
            Ok(response @ HttpResponse { status: 200, .. }) => response,
            // Respect the cached error status; don't fetch from origin.
            Ok(response @ HttpResponse { status: 406, .. }) => {
                console_log(&format!(
                    "Cached header-integrity error for {}; not refetching for up to an hour: {}",
                    url,
                    String::from_utf8_lossy(&response.body),
                ));
                response
            }
            // Cache miss or error fetching from cache; fall back to origin.
            _ => {
                console_log(&format!(
                    "{} not found in header-integrity cache. Fetching.",
                    url
                ));
                let response = match self.fetch_subresource(url).await {
                    Ok(response) => {
                        match self.compute_integrity(url, &response).await {
                            Ok(integrity) => {
                                // Keep original cache-control headers, so the integrity is
                                // up-to-date with the subresource.
                                HttpResponse {
                                    body: integrity,
                                    ..response
                                }
                            }
                            Err(err) => Self::error_response(&format!(
                                "Error computing header-integrity for {}: {:#}",
                                url, err
                            )),
                        }
                    }
                    Err(err) => Self::error_response(&format!(
                        "Error fetching subresource at {}: {:#}",
                        url, err
                    )),
                };
                let _ = self.header_integrity_cache.put(url, &response).await;
                response
            }
        };
        Self::extract_integrity(integrity_response)
    }
}

impl<'a, F: Fetcher, C: HttpCache> HeaderIntegrityFetcherImpl<'a, F, C> {
    async fn fetch_subresource(&self, url: &str) -> Result<HttpResponse> {
        // A generic SXG-preferring Accept header, for use in populating the
        // subresource integrity cache. This will be cached and reused for
        // other clients, so there is no need to proxy the client's accept
        // header.
        const ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3";
        let request = HttpRequest {
            body: vec![],
            headers: vec![("Accept".into(), ACCEPT.into())],
            method: Method::Get,
            url: url.into(),
        };
        self.subresource_fetcher.fetch(request).await
    }
    // Computes header-integrity of the given unsigned response, per the definition at
    // https://github.com/WICG/webpackage/blob/main/explainers/signed-exchange-subresource-substitution.md#identifying-exactly-one-version-of-a-signed-exchange
    // and the serialization at
    // https://w3c.github.io/webappsec-csp/#grammardef-hash-source. Though it is
    // not specified, the base64 encoding must use the non-websafe alphabet with
    // padding, per this usage:
    // https://source.chromium.org/chromium/chromium/src/+/main:content/browser/web_package/prefetched_signed_exchange_cache.cc;l=616;drc=d6962609965d2b9f804e66792486506de801f46c
    async fn compute_integrity(&self, url: &str, response: &HttpResponse) -> Result<Vec<u8>> {
        let fallback_base =
            Url::parse(url).map_err(|e| Error::new(e).context("parsing fallback URL"))?;
        // TODO: Figure out how to reduce the amount of data cloned.
        let payload_headers = Headers::new(response.headers.clone(), self.strip_response_headers);
        let (signed_headers, _) = signed_headers_and_payload(
            &fallback_base,
            response.status,
            &payload_headers,
            &response.body,
            NULL_FETCHER,
            &mut NullCache {},
            self.strip_response_headers,
        )
        .await?;
        Ok([
            b"sha256-",
            base64::encode(get_sha(&signed_headers)).as_bytes(),
        ]
        .concat())
    }
    fn error_response(msg: &str) -> HttpResponse {
        console_log(&msg.clone());
        HttpResponse {
            body: msg.as_bytes().into(),
            ..ERROR_RESPONSE.clone()
        }
    }
    fn extract_integrity(response: HttpResponse) -> Result<String> {
        if response.status == 200 && response.body.is_ascii() {
            String::from_utf8(response.body)
                .map_err(|e| Error::new(e).context("parsing header-integrity as utf8"))
        } else {
            Err(anyhow!("{}", String::from_utf8_lossy(&response.body)))
        }
    }
}

#[cfg(target_family = "wasm")]
fn console_log(msg: &str) {
    web_sys::console::log_1(&msg.into());
}

#[cfg(not(target_family = "wasm"))]
fn console_log(msg: &str) {
    println!("{}", msg);
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::fetcher::{NullFetcher, NULL_FETCHER};
    use crate::http_cache::NullCache;
    use anyhow::{anyhow, Result};
    use std::collections::HashMap;

    static EMPTY_SET: Lazy<BTreeSet<String>> = Lazy::new(|| BTreeSet::new());
    static mut NULL_CACHE: NullCache = NullCache {};

    // For use in other modules' tests.
    pub fn null_integrity_fetcher() -> HeaderIntegrityFetcherImpl<'static, NullFetcher, NullCache> {
        // The unsafe should be OK since there's no data in NULL_CACHE to race.
        new_fetcher(NULL_FETCHER, unsafe { &mut NULL_CACHE }, &*EMPTY_SET)
    }

    const TEST_URL: &str = "https://signed-exchange-testing.dev/sxgs/image.jpg";
    static TEST_RESPONSE: Lazy<HttpResponse> = Lazy::new(|| HttpResponse {
        // The result of `curl $TEST_URL`.
        body: include_bytes!("static/image.jpg").to_vec(),
        // The headers from `dump-signedexchange -payload=false -uri $TEST_URL`.
        headers: vec![("content-type".into(), "image/jpeg".into())],
        status: 200,
    });
    // The result of `dump-signedexchange -headerIntegrity -uri $TEST_URL`.
    const EXPECTED_HEADER_INTEGRITY: &str = "sha256-ypu/jZuGukVK2EEGlEkiN92qQDg3Zw6Fb0kCtees1bo=";

    struct FakeFetcher<'a>(&'a HttpResponse);

    #[async_trait(?Send)]
    impl<'a> Fetcher for FakeFetcher<'a> {
        async fn fetch(&self, _request: HttpRequest) -> Result<HttpResponse> {
            Ok(self.0.clone())
        }
    }

    #[async_std::test]
    async fn computes_integrity() {
        let strip_response_headers = BTreeSet::new();
        let mut cache = NullCache {};
        let mut fetcher = new_fetcher(
            FakeFetcher(&TEST_RESPONSE),
            &mut cache,
            &strip_response_headers,
        );
        assert_eq!(
            fetcher.fetch(TEST_URL).await.unwrap(),
            EXPECTED_HEADER_INTEGRITY
        );
    }

    struct InMemoryCache(HashMap<String, HttpResponse>);

    impl InMemoryCache {
        fn new() -> Self {
            InMemoryCache(HashMap::new())
        }
    }

    #[async_trait(?Send)]
    impl HttpCache for InMemoryCache {
        async fn get(&mut self, url: &str) -> Result<HttpResponse> {
            self.0
                .get(url)
                .map(|r| r.clone())
                .ok_or(anyhow!("not found"))
        }
        async fn put(&mut self, url: &str, response: &HttpResponse) -> Result<()> {
            self.0.insert(url.into(), response.clone());
            Ok(())
        }
    }

    #[async_std::test]
    async fn gets_header_integrity_from_cache() {
        let mut cache = InMemoryCache::new();
        let response = HttpResponse {
            body: b"sha256-blah".to_vec(),
            headers: vec![],
            status: 200,
        };
        let _ = cache.put(TEST_URL, &response).await;

        let strip_response_headers = BTreeSet::new();
        let mut fetcher = new_fetcher(
            FakeFetcher(&TEST_RESPONSE),
            &mut cache,
            &strip_response_headers,
        );

        assert_eq!(fetcher.fetch(TEST_URL).await.unwrap(), "sha256-blah",);
    }
    #[async_std::test]
    async fn gets_error_from_cache() {
        let mut cache = InMemoryCache::new();
        let response = HttpResponse {
            body: b"something went wrong".to_vec(),
            headers: vec![],
            status: 406,
        };
        let _ = cache.put(TEST_URL, &response).await;

        let strip_response_headers = BTreeSet::new();
        let mut fetcher = new_fetcher(
            FakeFetcher(&TEST_RESPONSE),
            &mut cache,
            &strip_response_headers,
        );

        assert_eq!(
            fetcher.fetch(TEST_URL).await.unwrap_err().to_string(),
            "something went wrong",
        )
    }
    #[async_std::test]
    async fn puts_into_cache() {
        let mut cache = InMemoryCache::new();

        let strip_response_headers = BTreeSet::new();
        let mut fetcher = new_fetcher(
            FakeFetcher(&TEST_RESPONSE),
            &mut cache,
            &strip_response_headers,
        );

        let _ = fetcher.fetch(TEST_URL).await;
        assert_eq!(
            cache.get(TEST_URL).await.unwrap().body,
            EXPECTED_HEADER_INTEGRITY.as_bytes(),
        );
    }
}
