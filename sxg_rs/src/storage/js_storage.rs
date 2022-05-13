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

use super::Storage;
use crate::utils::await_js_promise;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use js_sys::Function as JsFunction;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct JsStorage {
    read: Option<JsFunction>,
    write: Option<JsFunction>,
}

#[wasm_bindgen]
impl JsStorage {
    /// Creates a storage by two JavaScript async functions.
    /// `read` must be of type `(key: string) => Promise<string | nulL>`;
    /// `write` must be of type `(key: string, value: string) => Promise<void>`.
    #[wasm_bindgen(constructor)]
    pub fn new(read: Option<JsFunction>, write: Option<JsFunction>) -> Self {
        JsStorage { read, write }
    }
}

#[async_trait(?Send)]
impl Storage for JsStorage {
    async fn read(&self, k: &str) -> Result<Option<String>> {
        if let Some(read) = &self.read {
            let k = JsValue::from_str(k);
            let v = await_js_promise(read.call1(&JsValue::NULL, &k)).await?;
            if v.is_null() {
                return Ok(None);
            }
            let v = v
                .as_string()
                .ok_or_else(|| anyhow!("Expecting JavaScript function to return a string"))?;
            Ok(Some(v))
        } else {
            Ok(None)
        }
    }
    async fn write(&self, k: &str, v: &str) -> Result<()> {
        if let Some(write) = &self.write {
            let k = JsValue::from_str(k);
            let v = JsValue::from_str(v);
            await_js_promise(write.call2(&JsValue::NULL, &k, &v)).await?;
        }
        Ok(())
    }
}
