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

use super::{Format, Signer};
use crate::utils::await_js_promise;
use anyhow::Result;
use async_trait::async_trait;
use js_sys::{Function as JsFunction, Uint8Array};
use wasm_bindgen::JsValue;

/// [JsSigner] allows you to implement [Signer] trait by a JavaScript function.
pub struct JsSigner {
    js_function: JsFunction,
    js_sig_format: Format,
}

impl JsSigner {
    /// Creates a signer by a JavaScript async function,
    /// `js_function` must be of type `(input: Uint8Array) => Promise<Uint8Array>`.
    /// `js_function` should return the signature in `ASN.1` format.
    pub fn from_asn1_signer(js_function: JsFunction) -> Self {
        JsSigner {
            js_function,
            js_sig_format: Format::EccAsn1,
        }
    }
    /// Creates a signer by a JavaScript async function.
    /// `js_function` must be of type `(input: Uint8Array) => Promise<Uint8Array>`.
    /// `js_function` should return the raw signature, which contains exactly 64 bytes.
    /// For example, Web API
    /// [SubtleCrypto.sign()](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/sign)
    /// returns the raw signature as 64 bytes.
    pub fn from_raw_signer(js_function: JsFunction) -> Self {
        JsSigner {
            js_function,
            js_sig_format: Format::Raw,
        }
    }
}

#[async_trait(?Send)]
impl Signer for JsSigner {
    async fn sign(&self, message: &[u8], format: Format) -> Result<Vec<u8>> {
        let a = Uint8Array::new_with_length(message.len() as u32);
        a.copy_from(message);
        let sig = await_js_promise(self.js_function.call1(&JsValue::NULL, &a)).await?;
        let sig = Uint8Array::from(sig);
        let sig = sig.to_vec();
        match (self.js_sig_format, format) {
            (Format::Raw, Format::Raw) => Ok(sig),
            (Format::EccAsn1, Format::EccAsn1) => Ok(sig),
            (Format::Raw, Format::EccAsn1) => super::raw_sig_to_asn1(sig),
            (Format::EccAsn1, Format::Raw) => super::parse_asn1_sig(&sig),
        }
    }
}
