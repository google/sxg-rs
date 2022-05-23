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
pub mod js_runtime;

use crate::fetcher::{Fetcher, NullFetcher};
use crate::signature::{mock_signer::MockSigner, Signer};
use crate::storage::{InMemoryStorage, Storage};
use std::sync::Arc;
use std::time::SystemTime;

pub struct Runtime {
    pub now: SystemTime,
    pub fetcher: Arc<dyn Fetcher>,
    pub storage: Arc<dyn Storage>,
    pub sxg_signer: Arc<dyn Signer>,
    pub acme_signer: Arc<dyn Signer>,
}

impl Default for Runtime {
    fn default() -> Self {
        Runtime {
            now: SystemTime::UNIX_EPOCH,
            fetcher: Arc::new(NullFetcher),
            storage: Arc::new(InMemoryStorage::default()),
            sxg_signer: Arc::new(MockSigner),
            acme_signer: Arc::new(MockSigner),
        }
    }
}
