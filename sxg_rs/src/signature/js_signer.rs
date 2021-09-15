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

use super::Signer;
use anyhow::{Error, Result};
use async_trait::async_trait;
use der_parser::ber::{BerObject, BerObjectContent};
use js_sys::{Function as JsFunction, Uint8Array};
use wasm_bindgen::JsValue;

enum SigFormat {
    Raw,
    Asn1,
}

/// [JsSigner] allows you to implement [Signer] trait by a JavaScript function.
pub struct JsSigner {
    js_function: JsFunction,
    js_sig_format: SigFormat,
}

impl JsSigner {
    /// Creates a signer by a JavaScript async function,
    /// `js_function` must be of type `(input: Uint8Array) => Promise<Uint8Array>`.
    /// `js_function` should return the signature in `ASN.1` format.
    pub fn from_asn1_signer(js_function: JsFunction) -> Self {
        JsSigner {
            js_function,
            js_sig_format: SigFormat::Asn1,
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
            js_sig_format: SigFormat::Raw,
        }
    }
}

#[async_trait(?Send)]
impl Signer for JsSigner {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let a = Uint8Array::new_with_length(message.len() as u32);
        a.copy_from(message);
        let this = JsValue::null();
        let sig = self.js_function.call1(&this, &a).map_err(|e| {
            Error::msg(format!("{:?}", e)).context("JavaScript signer throws an error.")
        })?;
        let sig = wasm_bindgen_futures::JsFuture::from(js_sys::Promise::from(sig));
        let sig = sig.await.map_err(|e| {
            Error::msg(format!("{:?}", e))
                .context("JavaScript signer throws an error asynchronously.")
        })?;
        let sig = Uint8Array::from(sig);
        let sig = sig.to_vec();
        let sig = match self.js_sig_format {
            SigFormat::Asn1 => sig,
            SigFormat::Raw => raw_sig_to_asn1(sig)?,
        };
        Ok(sig)
    }
}

fn raw_sig_to_asn1(raw: Vec<u8>) -> Result<Vec<u8>> {
    const NUMBER_LENGTH: usize = 32; // 256 bit is 32 bytes.
    const SIG_LENGTH: usize = NUMBER_LENGTH * 2; // A signature contains two numbers;
    if raw.len() != SIG_LENGTH {
        return Err(Error::msg(format!(
            "Expecting signature length to be {}, found {}.",
            SIG_LENGTH,
            raw.len()
        )));
    }
    let mut r = raw;
    let mut s = r.split_off(NUMBER_LENGTH);
    ensure_positive(&mut r);
    ensure_positive(&mut s);
    let asn1 = BerObject::from_obj(BerObjectContent::Sequence(vec![
        BerObject::from_obj(BerObjectContent::Integer(&r)),
        BerObject::from_obj(BerObjectContent::Integer(&s)),
    ]));
    asn1.to_vec()
        .map_err(|e| Error::new(e).context("Failed to serialize asn1 BER Object"))
}

// Prepend the big-endian integer with leading zeros if needed, in order to
// make it a positive integer. For example, when the input is 0xffff,
// it will be parsed as a negative number, hence we need to change it to
// 0x00ffff.
fn ensure_positive(a: &mut Vec<u8>) {
    if a[0] >= 0x80 {
        a.insert(0, 0x00);
    }
}
