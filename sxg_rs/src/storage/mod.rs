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

#[cfg(feature = "wasm")]
pub mod js_storage;

use crate::utils::{MaybeSend, MaybeSync};
use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[cfg_attr(feature = "wasm", async_trait(?Send))]
#[cfg_attr(not(feature = "wasm"), async_trait)]
pub trait Storage: MaybeSend + MaybeSync {
    async fn read(&self, k: &str) -> Result<Option<String>>;
    async fn write(&self, k: &str, v: &str) -> Result<()>;
}

pub struct InMemoryStorage(Arc<RwLock<HashMap<String, String>>>);

impl InMemoryStorage {
    pub fn new() -> Self {
        InMemoryStorage(Arc::new(RwLock::new(HashMap::new())))
    }
}

#[cfg_attr(feature = "wasm", async_trait(?Send))]
#[cfg_attr(not(feature = "wasm"), async_trait)]
impl Storage for InMemoryStorage {
    async fn read(&self, k: &str) -> Result<Option<String>> {
        let guard = self.0.read().await;
        Ok(guard.get(k).map(|v| v.to_string()))
    }
    async fn write(&self, k: &str, v: &str) -> Result<()> {
        let mut guard = self.0.write().await;
        guard.insert(k.to_string(), v.to_string());
        Ok(())
    }
}

impl std::default::Default for InMemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}
