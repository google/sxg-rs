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

//! This module implements External Account Binding (EAB), which is defined in
//! [RFC-8555](https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.4).

use super::jws::{Algorithm, JsonWebSignature};
use crate::crypto::EcPublicKey;
use crate::signature::Signer;
use anyhow::Result;
use serde::Serialize;

/// The protected header which is used for External Account Binding.
#[derive(Serialize)]
struct EabProtectedHeader<'a> {
    alg: Algorithm,
    /// Key identifier from Certificate Authority.
    kid: &'a str,
    /// URL of the request. This is usually the new-account URL of ACME server,
    /// because only new-account requests need EAB.
    url: &'a str,
}

pub async fn create_external_account_binding(
    alg: Algorithm,
    kid: &str,
    url: &str,
    public_key: &EcPublicKey,
    hmac_signer: &dyn Signer,
) -> Result<JsonWebSignature> {
    let protected_header = EabProtectedHeader { alg, kid, url };
    JsonWebSignature::new(
        protected_header,
        /*payload=*/ Some(public_key),
        hmac_signer,
    )
    .await
}
