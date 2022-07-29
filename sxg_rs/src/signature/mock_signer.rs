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

use super::{Format, Signer};
use anyhow::Result;
use async_trait::async_trait;

pub struct MockSigner;

#[cfg_attr(feature = "wasm", async_trait(?Send))]
#[cfg_attr(not(feature = "wasm"), async_trait)]
impl Signer for MockSigner {
    async fn sign(&self, _message: &[u8], format: Format) -> Result<Vec<u8>> {
        match format {
            Format::EccAsn1 => super::raw_sig_to_asn1([0].repeat(64)),
            Format::Raw => Ok([0].repeat(64)),
        }
    }
}
