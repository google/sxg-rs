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

use super::HttpCache;
use crate::http::HttpResponse;
use anyhow::{anyhow, Error, Result};
use async_trait::async_trait;
use js_sys::Function as JsFunction;
use wasm_bindgen::JsValue;

pub struct JsHttpCache {
    pub get: JsFunction,
    pub put: JsFunction,
}

#[async_trait(?Send)]
impl HttpCache for JsHttpCache {
    async fn get(&self, url: &str) -> Result<HttpResponse> {
        let url = serde_wasm_bindgen::to_value(&url)
            .map_err(|e| Error::msg(e.to_string()).context("serializing url to JS"))?;
        let this = JsValue::null();
        let response = self
            .get
            .call1(&this, &url)
            .map_err(|_| anyhow!("Error invoking JS get"))?;
        let response = wasm_bindgen_futures::JsFuture::from(js_sys::Promise::from(response));
        let response = response
            .await
            .map_err(|_| anyhow!("Error returned by JS get"))?;
        let response = serde_wasm_bindgen::from_value(response)
            .map_err(|e| Error::msg(e.to_string()).context("parsing response from JS"))?;
        Ok(response)
    }
    async fn put(&self, url: &str, response: &HttpResponse) -> Result<()> {
        let url = serde_wasm_bindgen::to_value(&url)
            .map_err(|e| Error::msg(e.to_string()).context("serializing url to JS"))?;
        let response = serde_wasm_bindgen::to_value(&response)
            .map_err(|e| Error::msg(e.to_string()).context("serializing response to JS"))?;
        let this = JsValue::null();
        let ret = self
            .put
            .call2(&this, &url, &response)
            .map_err(|_| anyhow!("Error invoking JS put"))?;
        let ret = wasm_bindgen_futures::JsFuture::from(js_sys::Promise::from(ret));
        let ret = ret.await.map_err(|_| anyhow!("Error returned by JS put"))?;
        let _ret = serde_wasm_bindgen::from_value(ret)
            .map_err(|e| Error::msg(e.to_string()).context("parsing ack from JS"))?;
        Ok(())
    }
}
