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

use anyhow::Result;
use async_trait::async_trait;
use p256::ecdsa::SigningKey;
use super::Signer;

pub struct RustSigner {
    private_key: SigningKey,
}

impl RustSigner {
    pub fn new(private_key: &[u8]) -> Self {
        let private_key = SigningKey::from_bytes(private_key).unwrap();
        RustSigner { private_key }
    }
}

#[async_trait(?Send)]
impl Signer for RustSigner {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        use p256::ecdsa::signature::Signer as _;
        let sig = self.private_key.try_sign(&message)?.to_asn1();
        Ok(sig.as_bytes().to_vec())
    }
}
