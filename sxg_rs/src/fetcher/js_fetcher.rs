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
use js_sys::Function as JsFunction;
use wasm_bindgen::JsValue;
use crate::http::{HttpRequest, HttpResponse};
use super::Fetcher;

/// A [`Fetcher`] implemented by JavaScript.
pub struct JsFetcher(JsFunction);

impl JsFetcher {
    /// Constructs a new `JsFetcher` with a given JavaScript function,
    /// which takes a [`HttpRequest`] and returns a
    /// [Promise](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise)
    /// of [`HttpResponse`].
    /// ```typescript
    /// function js_function(req: HttpRequest): Promise<HttpResponse> {...}
    /// ```
    /// # Panics
    /// Panics if `js_function` throws an error.
    pub fn new(js_function: JsFunction) -> Self {
        JsFetcher(js_function)
    }
}

#[async_trait(?Send)]
impl Fetcher for JsFetcher {
    async fn fetch(&self, request: HttpRequest) -> Result<HttpResponse> {
        let request = JsValue::from_serde(&request).map_err(|e| Error::new(e).context("Failed to parse request."))?;
        let this = JsValue::null();
        let response = self.0.call1(&this, &request).map_err(|_| Error::msg("JavaScript fetcher throws an error."))?;
        let response = wasm_bindgen_futures::JsFuture::from(js_sys::Promise::from(response));
        let response = response.await.map_err(|_| Error::msg("JavaScript fetcher throws an error asynchronously."))?;
        let response: HttpResponse = response.into_serde().map_err(|e| Error::new(e).context("Failed to serialize response."))?;
        Ok(response)
    }
}
