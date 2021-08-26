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

#[cfg(feature="js_signer")]
pub mod js_signer;
#[cfg(feature="rust_signer")]
pub mod rust_signer;

use async_trait::async_trait;
use crate::structured_header::{ShItem, ShParamList, ParamItem};

#[async_trait(?Send)]
pub trait Signer {
    async fn sign(&self, message: &[u8]) -> Vec<u8>;
}

pub struct SignatureParams<'a> {
    pub cert_url: &'a str,
    pub cert_sha256: &'a [u8],
    pub date: std::time::SystemTime,
    pub expires: std::time::SystemTime,
    pub headers: &'a [u8],
    pub id: &'a str,
    pub request_url: &'a str,
    pub signer: Box<dyn Signer>,
    pub validity_url: &'a str,
}

// https://wicg.github.io/webpackage/draft-yasskin-httpbis-origin-signed-exchanges-impl.html#name-the-signature-header
pub struct Signature<'a> {
    cert_url: &'a str,
    cert_sha256: &'a [u8],
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
