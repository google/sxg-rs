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
pub mod config;
pub mod headers;
mod http_parser;
mod mice;
mod ocsp;
pub mod signature;
mod structured_header;
mod sxg;
mod utils;

use serde::Serialize;
use config::Config;
use headers::{Fields as HeaderFields, Headers};

#[derive(Serialize)]
pub struct HttpResponse {
    pub body: Vec<u8>,
    pub headers: Vec<(&'static str, &'static str)>,
    pub status: u16,
}

pub struct SxgWorker {
    pub config: Config,
}

impl SxgWorker {
    pub fn new(config_yaml: &str, cert_pem: &str, issuer_pem: &str) -> Self {
        let config = Config::new(config_yaml, cert_pem, issuer_pem);
        SxgWorker {
            config,
        }
    }
    // TODO: Make OCSP status as an internal state of SxgWorker, so that
    // SxgWorker is able to fetch OCSP. This will need a definition of a
    // Fetcher trait. Both js and rust callers need to implement this trait.
    pub fn create_cert_cbor(&self, ocsp_der: &[u8]) -> Vec<u8> {
        use cbor::DataItem;
        let cert_cbor = DataItem::Array(vec![
            DataItem::TextString("📜⛓"),
            DataItem::Map(vec![
                (DataItem::TextString("cert"), DataItem::ByteString(&self.config.cert_der)),
                (DataItem::TextString("ocsp"), DataItem::ByteString(ocsp_der)),
            ]),
            DataItem::Map(vec![
                (DataItem::TextString("cert"), DataItem::ByteString(&self.config.issuer_der)),
            ]),
        ]);
        cert_cbor.serialize()
    }
    pub fn create_ocsp_request(&self) -> &[u8] {
        &self.config.ocsp_request
    }
    pub async fn create_signed_exchange<'a>(&self, params: CreateSignedExchangeParams<'a>) -> HttpResponse {
        let CreateSignedExchangeParams {
            fallback_url,
            now,
            payload_body,
            payload_headers,
            signer,
            status_code,
        } = params;
        // 16384 is the max mice record size allowed by SXG spec.
        // https://wicg.github.io/webpackage/draft-yasskin-http-origin-signed-responses.html#section-3.5-7.9.1
        let (mice_digest, payload_body) = crate::mice::calculate(payload_body, 16384);
        let signed_headers = payload_headers.get_signed_headers_bytes(status_code, &mice_digest);
        const SIX_DAYS: std::time::Duration = std::time::Duration::from_secs(60 * 60 * 24 * 6);
        let signature = signature::Signature::new(signature::SignatureParams {
            cert_url: &self.config.cert_url,
            cert_sha256: utils::get_sha(&self.config.cert_der),
            date: now,
            expires: now + SIX_DAYS,
            headers: &signed_headers,
            id: "sig",
            request_url: fallback_url,
            signer,
            validity_url: &self.config.validity_url,
        }).await;
        let sxg_body = sxg::build(fallback_url, &signature.serialize(), &signed_headers, &payload_body);
        HttpResponse {
            body: sxg_body,
            headers: vec![
                ("content-type", "application/signed-exchange;v=b3"),
                ("x-content-type-options", "nosniff"),
            ],
            status: 200,
        }
    }
    pub fn create_validity(&self) -> Vec<u8> {
        let validity = cbor::DataItem::Map(vec![]);
        validity.serialize()
    }
    pub fn serve_preset_content(&self, req_path: &str, ocsp_der: &[u8]) -> Option<HttpResponse> {
        let basename = req_path.strip_prefix(&self.config.reserved_path)?;
        if basename == self.config.cert_url_basename {
            Some(HttpResponse {
                body: self.create_cert_cbor(ocsp_der),
                headers: vec![("content-type", "application/cert-chain+cbor")],
                status: 200,
            })
        } else if basename == self.config.validity_url_basename {
            Some(HttpResponse {
                body: self.create_validity(),
                headers: vec![("content-type", "application/cbor")],
                status: 200,
            })
        } else {
            Some(HttpResponse {
                body: format!("Unknown path {}", req_path).into_bytes(),
                headers: vec![("content-type", "text/plain")],
                status: 404,
            })
        }
    }
    pub fn transform_request_headers(&self, fields: HeaderFields) -> Result<HeaderFields, String> {
        let headers = Headers::new(fields);
        headers.forward_to_origin_server(&self.config.forward_request_headers)
    }
    pub fn validate_payload_headers(&self, fields: HeaderFields) -> Result<(), String> {
        let headers = Headers::new(fields);
        headers.validate_as_sxg_payload(self.config.reject_stateful_headers)
    }
}

pub struct CreateSignedExchangeParams<'a> {
    pub fallback_url: &'a str,
    pub now: std::time::SystemTime,
    pub payload_body: &'a [u8],
    pub payload_headers: headers::Headers,
    pub signer: Box<dyn signature::Signer>,
    pub status_code: u16,
}
