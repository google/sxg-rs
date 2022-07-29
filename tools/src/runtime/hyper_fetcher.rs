// Copyright 2022 Google LLC
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

use hyper::{client::connect::HttpConnector, Client};
use hyper_tls::HttpsConnector;

use anyhow::{Error, Result};
use async_trait::async_trait;
use std::convert::TryInto;
use sxg_rs::fetcher::Fetcher;
use sxg_rs::http::{HttpRequest as SxgRsRequest, HttpResponse as SxgRsResponse};

/// A [`Fetcher`] implemented by the external `hyper` crate.
pub struct HyperFetcher {
    client: Client<HttpsConnector<HttpConnector>>,
}

impl HyperFetcher {
    pub fn new() -> Self {
        let https = HttpsConnector::new();
        HyperFetcher {
            client: Client::builder().build(https),
        }
    }
}

impl Default for HyperFetcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg_attr(feature = "wasm", async_trait(?Send))]
#[cfg_attr(not(feature = "wasm"), async_trait)]
impl Fetcher for HyperFetcher {
    async fn fetch(&self, request: SxgRsRequest) -> Result<SxgRsResponse> {
        let request: http::Request<Vec<u8>> = request
            .try_into()
            .map_err(|e: Error| e.context("Failed to convert sxg_rs::Request to http::Request"))?;
        let request: http::Request<hyper::body::Body> = request.map(|body| body.into());
        let response = self
            .client
            .request(request)
            .await
            .map_err(|e| Error::new(e).context("Failed to request by Hyper client"))?;
        let (response_parts, response_body) = response.into_parts();
        let response_body = hyper::body::to_bytes(response_body)
            .await
            .map_err(|e| Error::new(e).context("Failed to convert response body to bytes"))?;
        let response_body = response_body.into_iter().collect();
        let response = http::Response::from_parts(response_parts, response_body);
        response.try_into()
    }
}
