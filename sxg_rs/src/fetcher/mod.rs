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
use anyhow::{anyhow, Result};
use async_trait::async_trait;

/// An interface for fetching resources from network.
#[async_trait(?Send)]
pub trait Fetcher {
    async fn fetch(&self, request: HttpRequest) -> Result<HttpResponse>;
    /// Uses `Get` method and returns response body.
    async fn get<T: ToString>(&self, url: T) -> Result<Vec<u8>> {
        let request = HttpRequest {
            body: vec![],
            headers: vec![],
            method: crate::http::Method::Get,
            url: url.to_string(),
        };
        let response = self.fetch(request).await?;
        Ok(response.body)
    }
}

pub const NULL_FETCHER: NullFetcher = NullFetcher {};

pub struct NullFetcher;

#[async_trait(?Send)]
impl Fetcher for NullFetcher {
    async fn fetch(&self, _request: HttpRequest) -> Result<HttpResponse> {
        Err(anyhow!("Not found"))
    }
}
