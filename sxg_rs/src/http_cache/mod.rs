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
pub mod js_http_cache;

use crate::http::HttpResponse;
use crate::utils::{MaybeSend, MaybeSync};
use anyhow::{anyhow, Result};
use async_trait::async_trait;

/// An interface for storing HTTP responses in a cache.
#[cfg_attr(feature = "wasm", async_trait(?Send))]
#[cfg_attr(not(feature = "wasm"), async_trait)]
pub trait HttpCache: MaybeSend + MaybeSync {
    async fn get(&self, url: &str) -> Result<HttpResponse>;
    async fn put(&self, url: &str, response: &HttpResponse) -> Result<()>;
}

pub struct NullCache;

#[cfg_attr(feature = "wasm", async_trait(?Send))]
#[cfg_attr(not(feature = "wasm"), async_trait)]
impl HttpCache for NullCache {
    async fn get(&self, _url: &str) -> Result<HttpResponse> {
        Err(anyhow!("No cache entry found in NullCache"))
    }
    async fn put(&self, _url: &str, _response: &HttpResponse) -> Result<()> {
        Ok(())
    }
}
