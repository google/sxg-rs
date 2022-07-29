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
use async_trait::async_trait;
use fastly::{Request as FastlyRequest, Response as FastlyResponse};
use std::convert::TryInto;
use sxg_rs::{
    fetcher::Fetcher,
    http::{HttpRequest, HttpResponse},
};

/// A [`Fetcher`] implemented by
/// [Fastly backend](https://developer.fastly.com/reference/api/services/backend/).
pub struct FastlyFetcher {
    backend_name: &'static str,
}

impl FastlyFetcher {
    /// Constructs a new `FastlyFetcher` from the backend name.
    /// This function does not create the backend in Fastly;
    /// the Fastly backend need to be created via Fastly API
    /// before calling this function.
    pub fn new(backend_name: &'static str) -> Self {
        FastlyFetcher { backend_name }
    }
}

#[cfg_attr(feature = "wasm", async_trait(?Send))]
#[cfg_attr(not(feature = "wasm"), async_trait)]
impl Fetcher for FastlyFetcher {
    async fn fetch(&self, request: HttpRequest) -> Result<HttpResponse> {
        let request: ::http::request::Request<Vec<u8>> = request.try_into()?;
        let request = request.map(fastly::Body::from);
        let request: FastlyRequest = request.try_into()?;
        let response: FastlyResponse = request
            .send(self.backend_name)
            .map_err(|e| Error::new(e).context("Failed to fetch from backend."))?;

        let response: ::http::response::Response<fastly::Body> = response.into();
        let response = response.map(|body| body.into_bytes());
        response.try_into()
    }
}
