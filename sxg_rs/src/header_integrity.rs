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

use crate::crypto::HashAlgorithm;
use crate::fetcher::{Fetcher, NULL_FETCHER};
use crate::headers::Headers;
use crate::http::{HttpRequest, HttpResponse, Method};
use crate::http_cache::{HttpCache, NullCache};
use crate::utils::{signed_headers_and_payload, MaybeSend, MaybeSync};
use anyhow::{anyhow, Error, Result};
use async_trait::async_trait;
use once_cell::sync::Lazy;
use std::collections::BTreeSet;
use url::Url;

#[cfg_attr(feature = "wasm", async_trait(?Send))]
#[cfg_attr(not(feature = "wasm"), async_trait)]
pub trait HeaderIntegrityFetcher: MaybeSend + MaybeSync {
    async fn fetch(&self, url: &str) -> Result<String>;
}

pub fn new_fetcher<'a, C: HttpCache>(
    subresource_fetcher: &'a dyn Fetcher,
    header_integrity_cache: C,
    strip_response_headers: &'a BTreeSet<String>,
) -> HeaderIntegrityFetcherImpl<'a, C> {
    HeaderIntegrityFetcherImpl {
        subresource_fetcher,
        header_integrity_cache,
        strip_response_headers,
    }
}

pub struct HeaderIntegrityFetcherImpl<'a, C: HttpCache> {
    subresource_fetcher: &'a dyn Fetcher,
    header_integrity_cache: C,
    strip_response_headers: &'a BTreeSet<String>,
}

// A synthesized error response that can be cached, to prevent overloading the
// origin for non-SXG subresources that it preloads.
static ERROR_RESPONSE: Lazy<HttpResponse> = Lazy::new(|| HttpResponse {
    body: vec![],
    headers: vec![("cache-control".into(), "max-age=3600".into())],
    status: 406,
});

#[cfg_attr(feature = "wasm", async_trait(?Send))]
#[cfg_attr(not(feature = "wasm"), async_trait)]
impl<'a, C: HttpCache> HeaderIntegrityFetcher for HeaderIntegrityFetcherImpl<'a, C> {
    async fn fetch(&self, url: &str) -> Result<String> {
        let integrity_response = match self.cache_get(url).await {
            // Use cached header-integrity.
            Ok(response @ HttpResponse { status: 200, .. }) => response,
            // Respect the cached error status; don't fetch from origin.
            Ok(response @ HttpResponse { status: 406, .. }) => response,
            // Cache miss or error fetching from cache; fall back to origin.
            _ => {
                let response = match self.fetch_subresource(url).await {
                    Ok(response) => {
                        match self.compute_integrity(url, &response, true).await {
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
                let _ = self.cache_put(url, &response).await;
                response
            }
        };
        Self::extract_integrity(integrity_response)
    }
}

impl<'a, C: HttpCache> HeaderIntegrityFetcherImpl<'a, C> {
    async fn cache_get(&self, url: &str) -> Result<HttpResponse> {
        self.header_integrity_cache.get(url).await
    }
    async fn cache_put(&self, url: &str, response: &HttpResponse) -> Result<()> {
        self.header_integrity_cache.put(url, response).await
    }
    /// Fetches unsigned subresource from URL.
    async fn fetch_subresource(&self, url: &str) -> Result<HttpResponse> {
        // A generic Accept header, for use in populating the
        // subresource integrity cache. This will be cached and reused for
        // other clients, so there is no need to proxy the client's accept
        // header.
        const ACCEPT: &str =
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8";
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
    async fn compute_integrity(
        &self,
        url: &str,
        response: &HttpResponse,
        skip_process_link: bool,
    ) -> Result<Vec<u8>> {
        let fallback_base =
            Url::parse(url).map_err(|e| Error::new(e).context("parsing fallback URL"))?;
        // TODO: Figure out how to reduce the amount of data cloned.
        let payload_headers = Headers::new(response.headers.clone(), self.strip_response_headers);
        let mut header_integrity_fetcher =
            new_fetcher(&NULL_FETCHER, NullCache, self.strip_response_headers);
        let (signed_headers, _) = signed_headers_and_payload(
            &fallback_base,
            response.status,
            &payload_headers,
            &response.body,
            &mut header_integrity_fetcher,
            skip_process_link,
        )
        .await?;
        Ok([
            b"sha256-",
            base64::encode(HashAlgorithm::Sha256.digest(&signed_headers)).as_bytes(),
        ]
        .concat())
    }
    fn error_response(msg: &str) -> HttpResponse {
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

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::fetcher::NULL_FETCHER;
    use crate::http_cache::NullCache;
    use anyhow::{anyhow, Result};
    use std::collections::HashMap;
    use std::sync::Mutex;

    static EMPTY_SET: Lazy<BTreeSet<String>> = Lazy::new(BTreeSet::new);

    // For use in other modules' tests.
    pub fn null_integrity_fetcher() -> HeaderIntegrityFetcherImpl<'static, NullCache> {
        new_fetcher(&NULL_FETCHER, NullCache {}, &EMPTY_SET)
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

    #[cfg_attr(feature = "wasm", async_trait(?Send))]
    #[cfg_attr(not(feature = "wasm"), async_trait)]
    impl<'a> Fetcher for FakeFetcher<'a> {
        async fn fetch(&self, _request: HttpRequest) -> Result<HttpResponse> {
            Ok(self.0.clone())
        }
    }

    static FAKE_FETCHER_WITH_TEST_RESPONSE: Lazy<FakeFetcher<'static>> = Lazy::new(|| {
        let test_response = Box::new(TEST_RESPONSE.clone());
        FakeFetcher(Box::leak(test_response))
    });

    #[tokio::test]
    async fn computes_integrity() {
        let strip_response_headers = BTreeSet::new();
        let fetcher = new_fetcher(
            &*FAKE_FETCHER_WITH_TEST_RESPONSE,
            NullCache {},
            &strip_response_headers,
        );
        assert_eq!(
            fetcher.fetch(TEST_URL).await.unwrap(),
            EXPECTED_HEADER_INTEGRITY
        );
    }

    struct InMemoryCache<'a>(&'a Mutex<HashMap<String, HttpResponse>>);

    #[cfg_attr(feature = "wasm", async_trait(?Send))]
    #[cfg_attr(not(feature = "wasm"), async_trait)]
    impl HttpCache for InMemoryCache<'_> {
        async fn get(&self, url: &str) -> Result<HttpResponse> {
            self.0
                .try_lock()
                .map_err(|_| anyhow!("locking mutex"))?
                .get(url)
                .cloned()
                .ok_or_else(|| anyhow!("not found"))
        }
        async fn put(&self, url: &str, response: &HttpResponse) -> Result<()> {
            self.0
                .try_lock()
                .map_err(|_| anyhow!("locking mutex"))?
                .insert(url.into(), response.clone());
            Ok(())
        }
    }

    #[tokio::test]
    async fn gets_header_integrity_from_cache() {
        let store = Mutex::new(HashMap::new());
        let cache = InMemoryCache(&store);
        let response = HttpResponse {
            body: b"sha256-blah".to_vec(),
            headers: vec![],
            status: 200,
        };
        let _ = cache.put(TEST_URL, &response).await;

        let strip_response_headers = BTreeSet::new();
        let fetcher = new_fetcher(
            &*FAKE_FETCHER_WITH_TEST_RESPONSE,
            cache,
            &strip_response_headers,
        );

        assert_eq!(fetcher.fetch(TEST_URL).await.unwrap(), "sha256-blah",);
    }
    #[tokio::test]
    async fn gets_error_from_cache() {
        let store = Mutex::new(HashMap::new());
        let cache = InMemoryCache(&store);
        let response = HttpResponse {
            body: b"something went wrong".to_vec(),
            headers: vec![],
            status: 406,
        };
        let _ = cache.put(TEST_URL, &response).await;

        let strip_response_headers = BTreeSet::new();
        let fetcher = new_fetcher(
            &*FAKE_FETCHER_WITH_TEST_RESPONSE,
            cache,
            &strip_response_headers,
        );

        assert_eq!(
            fetcher.fetch(TEST_URL).await.unwrap_err().to_string(),
            "something went wrong",
        )
    }
    #[tokio::test]
    async fn puts_into_cache() {
        let store = Mutex::new(HashMap::new());

        let strip_response_headers = BTreeSet::new();
        let fetcher = new_fetcher(
            &*FAKE_FETCHER_WITH_TEST_RESPONSE,
            InMemoryCache(&store),
            &strip_response_headers,
        );

        let _ = fetcher.fetch(TEST_URL).await;
        assert_eq!(
            store.lock().unwrap().get(TEST_URL).unwrap().body,
            EXPECTED_HEADER_INTEGRITY.as_bytes(),
        );
    }
    #[tokio::test]
    async fn out_of_order() {
        use crate::utils::tests::{out_of_order, OutOfOrderState};
        use futures::{
            future::BoxFuture,
            stream::{self, StreamExt},
        };
        struct OutOfOrderCache<F: Fn() -> BoxFuture<'static, Result<HttpResponse>>>(F);
        #[cfg_attr(feature = "wasm", async_trait(?Send))]
        #[cfg_attr(not(feature = "wasm"), async_trait)]
        impl<F: Fn() -> BoxFuture<'static, Result<HttpResponse>> + Send + Sync> HttpCache
            for OutOfOrderCache<F>
        {
            async fn get(&self, url: &str) -> Result<HttpResponse> {
                println!("get: url = {}", url);
                self.0().await
            }
            async fn put(&self, url: &str, _response: &HttpResponse) -> Result<()> {
                println!("put: url = {}", url);
                Ok(())
            }
        }
        let state = OutOfOrderState::new();
        let cache = OutOfOrderCache(|| {
            out_of_order(state.clone(), || {
                Ok(HttpResponse {
                    body: b"sha256-blah".to_vec(),
                    headers: vec![],
                    status: 200,
                })
            })
        });

        let strip_response_headers = BTreeSet::new();
        let fetcher = new_fetcher(
            &*FAKE_FETCHER_WITH_TEST_RESPONSE,
            cache,
            &strip_response_headers,
        );

        stream::iter(1..=2)
            .for_each_concurrent(None, |n| {
                println!("fetch #{}", n);
                async {
                    assert_eq!(fetcher.fetch(TEST_URL).await.unwrap(), "sha256-blah");
                }
            })
            .await;
    }
}
