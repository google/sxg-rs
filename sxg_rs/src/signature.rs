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

use der_parser::ber::{BerObject, BerObjectContent};
use js_sys::Function as JsFunction;
use js_sys::Uint8Array;
use wasm_bindgen::JsValue;
use crate::structured_header::{ShItem, ShParamList, ParamItem};

pub enum Signer<'a> {
    JsCallback(JsFunction),
    RawPrivateKey(&'a [u8]),
}

pub struct SignatureParams<'a> {
    pub cert_url: &'a str,
    pub cert_sha256: Vec<u8>,
    pub date: std::time::SystemTime,
    pub expires: std::time::SystemTime,
    pub headers: &'a [u8],
    pub id: &'a str,
    pub request_url: &'a str,
    pub signer: Signer<'a>,
    pub validity_url: &'a str,
}

// https://wicg.github.io/webpackage/draft-yasskin-httpbis-origin-signed-exchanges-impl.html#name-the-signature-header
pub struct Signature<'a> {
    cert_url: &'a str,
    cert_sha256: Vec<u8>,
    date: u64,
    expires: u64,
    id: &'a str,
    sig: Vec<u8>,
    validity_url: &'a str,
}

impl<'a> Signature<'a> {
    pub async fn new(params: SignatureParams<'a>) -> Signature<'a> {
        let SignatureParams {
            cert_url,
            cert_sha256,
            date,
            expires,
            headers,
            id,
            request_url,
            signer,
            validity_url,
        } = params;
        let date = time_to_number(date);
        let expires = time_to_number(expires);
        // https://wicg.github.io/webpackage/draft-yasskin-httpbis-origin-signed-exchanges-impl.html#name-signature-validity
        let message = [
            &[32u8; 64],
            "HTTP Exchange 1 b3".as_bytes(),
            &[0u8],
            &[32u8],
            &cert_sha256,
            &(validity_url.len() as u64).to_be_bytes(),
            validity_url.as_bytes(),
            &date.to_be_bytes(),
            &expires.to_be_bytes(),
            &(request_url.len() as u64).to_be_bytes(),
            request_url.as_bytes(),
            &(headers.len() as u64).to_be_bytes(),
            &headers,
        ].concat();
        let sig = signer.sign(&message).await;
        Signature {
            cert_url,
            cert_sha256,
            date,
            expires,
            id,
            sig,
            validity_url,
        }
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut list = ShParamList::new();
        let mut param = ParamItem::new(&self.id);
        param.push(("sig", Some(ShItem::ByteSequence(&self.sig))));
        param.push(("integrity", Some(ShItem::String("digest/mi-sha256-03"))));
        param.push(("cert-url", Some(ShItem::String(&self.cert_url))));
        param.push(("cert-sha256", Some(ShItem::ByteSequence(&self.cert_sha256))));
        param.push(("validity-url", Some(ShItem::String(&self.validity_url))));
        param.push(("date", Some(ShItem::Integer(self.date))));
        param.push(("expires", Some(ShItem::Integer(self.expires))));
        list.push(param);
        format!("{}", list).into_bytes()
    }
}

fn time_to_number(t: std::time::SystemTime) -> u64 {
    t.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

impl<'a> Signer<'a> {
    async fn sign<'b>(&self, message: &'b [u8]) -> Vec<u8> {
        match self {
            Signer::JsCallback(callback) => {
                let a = Uint8Array::new_with_length(message.len() as u32);
                a.copy_from(&message);
                let this = JsValue::null();
                let sig = callback.call1(&this, &a).unwrap();
                let sig = wasm_bindgen_futures::JsFuture::from(js_sys::Promise::from(sig));
                let sig = sig.await.unwrap();
                let sig = Uint8Array::from(sig);
                let sig = sig.to_vec();
                raw_sig_to_asn1(sig)
            },
            Signer::RawPrivateKey(private_key) => {
                use p256::ecdsa::signature::Signer as _;
                let private_key = ::p256::ecdsa::SigningKey::from_bytes(&private_key).unwrap();
                let sig = private_key.sign(&message).to_asn1();
                sig.as_bytes().to_vec()
            },
        }
    }
}

fn raw_sig_to_asn1(raw: Vec<u8>) -> Vec<u8> {
    if raw.len() != 64 {
        panic!("Expecting signature length to be 64, found {}.", raw.len());
    }
    let mut r = raw;
    let mut s = r.split_off(32);
    ensure_positive(&mut r);
    ensure_positive(&mut s);
    let asn1 = BerObject::from_obj(BerObjectContent::Sequence(vec![
        BerObject::from_obj(BerObjectContent::Integer(&r)),
        BerObject::from_obj(BerObjectContent::Integer(&s)),
    ]));
    asn1.to_vec().unwrap()
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
