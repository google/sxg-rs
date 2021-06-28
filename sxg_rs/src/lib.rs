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

mod cbor;
pub mod headers;
mod http_parser;
mod mice;
pub mod ocsp;
pub mod signature;
mod structured_header;
mod sxg;
mod utils;

pub fn create_cert_cbor(cert_der: &[u8], issuer_der: &[u8], ocsp_der: &[u8]) -> Vec<u8> {
    use cbor::DataItem;
    let cert_cbor = DataItem::Array(vec![
        DataItem::TextString("📜⛓"),
        DataItem::Map(vec![
            (DataItem::TextString("cert"), DataItem::ByteString(cert_der)),
            (DataItem::TextString("ocsp"), DataItem::ByteString(ocsp_der)),
        ]),
        DataItem::Map(vec![
            (DataItem::TextString("cert"), DataItem::ByteString(issuer_der)),
        ]),
    ]);
    cert_cbor.serialize()
}

pub fn create_validity() -> Vec<u8> {
    let validity = cbor::DataItem::Map(vec![]);
    validity.serialize()
}

pub struct CreateSignedExchangeParams<'a> {
    pub cert_der: &'a [u8],
    pub cert_url: &'a str,
    pub fallback_url: &'a str,
    pub now: std::time::SystemTime,
    pub payload_body: &'a [u8],
    pub payload_headers: headers::Headers,
    pub signer: signature::Signer<'a>,
    pub status_code: u16,
    pub validity_url: &'a str,
}

pub async fn create_signed_exchange<'a>(params: CreateSignedExchangeParams<'a>) -> Vec<u8> {
    let CreateSignedExchangeParams {
        cert_der,
        cert_url,
        fallback_url,
        now,
        payload_body,
        payload_headers,
        signer,
        status_code,
        validity_url,
    } = params;
    // 16384 is the max mice record size allowed by SXG spec.
    // https://wicg.github.io/webpackage/draft-yasskin-http-origin-signed-responses.html#section-3.5-7.9.1
    let (mice_digest, payload_body) = crate::mice::calculate(payload_body, 16384);
    let signed_headers = payload_headers.get_signed_headers_bytes(status_code, &mice_digest);
    let signature = signature::Signature::new(signature::SignatureParams {
        cert_url,
        cert_sha256: utils::get_sha(cert_der),
        date: now,
        expires: now + std::time::Duration::from_secs(60 * 60 * 24 * 6),
        headers: &signed_headers,
        id: "sig",
        request_url: fallback_url,
        signer,
        validity_url,
    }).await;
    sxg::build(fallback_url, &signature.serialize(), &signed_headers, &payload_body)
}
