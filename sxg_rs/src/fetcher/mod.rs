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

#[cfg(feature = "wasm")]
pub mod js_fetcher;
pub mod mock_fetcher;

use crate::http::{HttpRequest, HttpResponse};
use crate::utils::{MaybeSend, MaybeSync};
use anyhow::{anyhow, Result};
use async_trait::async_trait;

/// An interface for fetching resources from network.
#[cfg_attr(feature = "wasm", async_trait(?Send))]
#[cfg_attr(not(feature = "wasm"), async_trait)]
pub trait Fetcher: MaybeSend + MaybeSync {
    async fn fetch(&self, request: HttpRequest) -> Result<HttpResponse>;
}

/// Uses `Get` method and returns response body,
/// iteratively following 301, 302, 303, 307, 308 redirection.
/// - Why this function is not put inside [`Fetcher`] trait?
///   If we declare `Fetcher::get` function with a default implementation,
///   we have to also add a constraint `where Self: Sized` to `Fetcher::get`,
///   because of https://github.com/rust-lang/rust/issues/51443 and in particular
///   https://docs.rs/async-trait/0.1.57/async_trait/#dyn-traits.
///   However, having such constraint `Self: Sized` prevent using `Fetcher::get` method on a
///   `dyn Fetcher` variable, because `dyn Fetcher` is not `Sized`.
pub async fn get(fetcher: &dyn Fetcher, url: impl ToString) -> Result<Vec<u8>> {
    let mut url = url.to_string();
    loop {
        let request = HttpRequest {
            body: vec![],
            headers: vec![],
            method: crate::http::Method::Get,
            url: url.to_string(),
        };
        let response = fetcher.fetch(request).await?;
        if matches!(response.status, 301 | 302 | 303 | 307 | 308) {
            let location = response.headers.into_iter().find_map(|(name, value)| {
                if name.eq_ignore_ascii_case(http::header::LOCATION.as_str()) {
                    Some(value)
                } else {
                    None
                }
            });
            if let Some(location) = location {
                url = location;
                continue;
            }
        }
        return Ok(response.body);
    }
}

pub const NULL_FETCHER: NullFetcher = NullFetcher {};

pub struct NullFetcher;

#[cfg_attr(feature = "wasm", async_trait(?Send))]
#[cfg_attr(not(feature = "wasm"), async_trait)]
impl Fetcher for NullFetcher {
    async fn fetch(&self, _request: HttpRequest) -> Result<HttpResponse> {
        Err(anyhow!("Not found"))
    }
}
