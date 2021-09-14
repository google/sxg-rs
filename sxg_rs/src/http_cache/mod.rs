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
use anyhow::{anyhow, Error, Result};
use async_trait::async_trait;

/// An interface for storing HTTP responses in a cache.
#[async_trait(?Send)]
pub trait HttpCache {
    async fn get(&mut self, url: &str) -> Result<HttpResponse>;
    async fn put(&mut self, url: &str, response: &HttpResponse) -> Result<()>;
}

pub struct NullCache;

#[async_trait(?Send)]
impl HttpCache for NullCache {
    async fn get(&mut self, _url: &str) -> Result<HttpResponse> {
        Err(anyhow!("No cache entry found in NullCache"))
    }
    async fn put(&mut self, _url: &str, _response: &HttpResponse) -> Result<()> {
        Ok(())
    }
}
