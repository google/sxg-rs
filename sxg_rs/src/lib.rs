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
pub mod fetcher;
pub mod headers;
pub mod http;
mod http_parser;
mod mice;
mod ocsp;
pub mod signature;
mod structured_header;
mod sxg;
mod utils;

use config::Config;
use headers::Headers;
use http::{HeaderFields, HttpResponse};
use serde::Serialize;

pub struct SxgWorker {
    pub config: Config,
}

#[derive(Serialize)]
#[serde(rename_all="camelCase", tag="kind")]
pub enum PresetContent {
    Direct(HttpResponse),
    ToBeSigned {
        url: String,
        payload: HttpResponse,
        fallback: HttpResponse,
    }
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
    pub async fn create_signed_exchange<'a>(&self, params: CreateSignedExchangeParams<'a>) -> Result<HttpResponse, String> {
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
        let sxg_body = sxg::build(fallback_url, &signature.serialize(), &signed_headers, &payload_body)?;
        Ok(HttpResponse {
            body: sxg_body,
            headers: vec![
                (String::from("content-type"), String::from("application/signed-exchange;v=b3")),
                (String::from("x-content-type-options"), String::from("nosniff")),
            ],
            status: 200,
        })
    }
    pub fn create_validity(&self) -> Vec<u8> {
        let validity = cbor::DataItem::Map(vec![]);
        validity.serialize()
    }
    pub async fn fetch_ocsp_from_digicert(&self, fetcher: Box<dyn fetcher::Fetcher>) -> Vec<u8> {
        ocsp::fetch_from_digicert(&self.config.cert_der, &self.config.issuer_der, fetcher).await
    }
    pub fn serve_preset_content(&self, req_url: &str, ocsp_der: &[u8]) -> Option<PresetContent> {
        let req_url = url::Url::parse(req_url).ok()?;
        let path: Vec<_> = req_url.path_segments()?.collect();
        let basename = if path.len() == 2 && path[0] == self.config.reserved_path.trim_matches('/') {
            path[1]
        } else {
            return None;
        };
        if basename == self.config.cert_url_basename {
            Some(PresetContent::Direct(HttpResponse {
                body: self.create_cert_cbor(ocsp_der),
                headers: vec![(String::from("content-type"), String::from("application/cert-chain+cbor"))],
                status: 200,
            }))
        } else if basename == self.config.validity_url_basename {
            Some(PresetContent::Direct(HttpResponse {
                body: self.create_validity(),
                headers: vec![(String::from("content-type"), String::from("application/cbor"))],
                status: 200,
            }))
        } else if basename == "test.html" {
            Some(PresetContent::Direct(HttpResponse {
                headers: vec![(String::from("content-type"), String::from("text/html"))],
                status: 200,
                body: include_bytes!("./static/test.html").to_vec(),
            }))
        } else if basename == "prefetch.html" {
            Some(PresetContent::Direct(HttpResponse {
                headers: vec![(String::from("content-type"), String::from("text/html"))],
                status: 200,
                body: include_bytes!("./static/prefetch.html").to_vec(),
            }))
        } else if basename == "fallback.html" {
            Some(PresetContent::Direct(HttpResponse {
                headers: vec![(String::from("content-type"), String::from("text/html"))],
                status: 200,
                body: include_bytes!("./static/fallback.html").to_vec(),
            }))
        } else if basename == "test.sxg" {
            let mut fallback_url = req_url;
            fallback_url.set_host(Some(&self.config.html_host)).ok()?;
            fallback_url.set_path(&fallback_url.path().replace("test.sxg", "fallback.html"));
            Some(PresetContent::ToBeSigned {
                url: fallback_url.to_string(),
                payload: HttpResponse {
                    headers: vec![(String::from("content-type"), String::from("text/html"))],
                    status: 200,
                    body: include_bytes!("./static/success.html").to_vec(),
                },
                fallback: HttpResponse {
                    headers: vec![(String::from("content-type"), String::from("text/html"))],
                    status: 200,
                    body: include_bytes!("./static/fallback.html").to_vec(),
                },
            })
        } else {
            Some(PresetContent::Direct(HttpResponse {
                headers: vec![(String::from("content-type"), String::from("text/plain"))],
                status: 404,
                body: format!("Unknown path {}", req_url).into_bytes(),
            }))
        }
    }
    pub fn transform_request_headers(&self, fields: HeaderFields) -> Result<HeaderFields, String> {
        let headers = Headers::new(fields, &self.config.strip_request_headers);
        headers.forward_to_origin_server(&self.config.forward_request_headers)
    }
    pub fn validate_payload_headers(&self, fields: HeaderFields) -> Result<(), String> {
        let headers = Headers::new(fields, &self.config.strip_response_headers);
        headers.validate_as_sxg_payload()
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
