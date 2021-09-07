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

use async_trait::async_trait;
use der_parser::ber::{BerObject, BerObjectContent};
use js_sys::{Function as JsFunction, Uint8Array};
use wasm_bindgen::JsValue;
use super::Signer;

pub struct JsSigner(JsFunction);

impl JsSigner {
    // The JS function should be of type
    // `(input: Uint8Array) => Promise<Uint8Array>`
    pub fn new(js_function: JsFunction) -> Self {
        JsSigner(js_function)
    }
}

#[async_trait(?Send)]
impl Signer for JsSigner {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>,String> {
        let a = Uint8Array::new_with_length(message.len() as u32);
        a.copy_from(&message);
        let this = JsValue::null();
        let sig = self.0.call1(&this, &a).map_err(|_| "Bad call")?;
        let sig = wasm_bindgen_futures::JsFuture::from(js_sys::Promise::from(sig));
        let sig = sig.await.map_err(|_| "Bad async result")?;
        let sig = Uint8Array::from(sig);
        let sig = sig.to_vec();
        // raw_sig_to_asn1(sig)
        Ok(sig)
    }
}

fn raw_sig_to_asn1(raw: Vec<u8>) -> Result<Vec<u8>, String> {
    if raw.len() != 64 {
        return Err(format!("Expecting signature length to be 64, found {}.", raw.len()));
    }
    let mut r = raw;
    let mut s = r.split_off(32);
    ensure_positive(&mut r);
    ensure_positive(&mut s);
    let asn1 = BerObject::from_obj(BerObjectContent::Sequence(vec![
        BerObject::from_obj(BerObjectContent::Integer(&r)),
        BerObject::from_obj(BerObjectContent::Integer(&s)),
    ]));
    asn1.to_vec().map_err(|_| "Bad Sig to ASN1".to_string())
}

// Prepend the big-endian integer with leading zeros if needed, in order to
// make it a positive integer. For example, when the input is 0xffff,
// it will be parsed as a negative number, hence we need to change it to
// 0x00ffff.
fn ensure_positive(a: &mut Vec<u8>) -> () {
    if a[0] >= 0x80 {
        a.insert(0, 0x00);
    }
}