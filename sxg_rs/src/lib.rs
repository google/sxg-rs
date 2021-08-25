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
use headers::{AcceptFilter, Headers};
use http::{HeaderFields, HttpResponse};
use serde::Serialize;
use url::Url;

pub struct SxgWorker {
    pub config: Config,
}

#[derive(Serialize, Debug, PartialEq)]
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
    fn cert_basename(&self) -> String {
        base64::encode_config(&self.config.cert_sha256, base64::URL_SAFE_NO_PAD)
    }
    pub async fn create_signed_exchange<'a>(&self, params: CreateSignedExchangeParams<'a>) -> Result<HttpResponse, String> {
        let CreateSignedExchangeParams {
            fallback_url,
            cert_origin,
            now,
            payload_body,
            payload_headers,
            signer,
            status_code,
        } = params;
        let fallback_base = Url::parse(fallback_url).map_err(|_| "Failed to parse fallback URL")?;
        let cert_base = Url::parse(cert_origin).map_err(|_| "Failed to parse cert origin")?;
        // 16384 is the max mice record size allowed by SXG spec.
        // https://wicg.github.io/webpackage/draft-yasskin-http-origin-signed-responses.html#section-3.5-7.9.1
        let (mice_digest, payload_body) = crate::mice::calculate(payload_body, 16384);
        let signed_headers = payload_headers.get_signed_headers_bytes(status_code, &mice_digest);
        let cert_url = cert_base.join(&format!("{}{}", &self.config.cert_url_dirname, &self.cert_basename()))
            .map_err(|_| "Failed to parse cert_url_dirname")?;
        let validity_url = fallback_base.join(&format!("{}{}", &self.config.validity_url_dirname, "validity"))
            .map_err(|_| "Failed to parse validity_url_dirname")?;
        let signature = signature::Signature::new(signature::SignatureParams {
            cert_url: cert_url.as_str(),
            cert_sha256: &self.config.cert_sha256,
            date: now,
            expires: now + payload_headers.signature_duration()?,
            headers: &signed_headers,
            id: "sig",
            request_url: fallback_url,
            signer,
            validity_url: validity_url.as_str(),
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
        let path = req_url.path();
        if let Some(basename) = path.strip_prefix(&self.config.reserved_path) {
            match basename {
                "test.html" => {
                    Some(PresetContent::Direct(HttpResponse {
                        headers: vec![(String::from("content-type"), String::from("text/html"))],
                        status: 200,
                        body: include_bytes!("./static/test.html").to_vec(),
                    }))
                },
                "prefetch.html" => {
                    Some(PresetContent::Direct(HttpResponse {
                        headers: vec![(String::from("content-type"), String::from("text/html"))],
                        status: 200,
                        body: include_bytes!("./static/prefetch.html").to_vec(),
                    }))
                },
                "fallback.html" => {
                    Some(PresetContent::Direct(HttpResponse {
                        headers: vec![(String::from("content-type"), String::from("text/html"))],
                        status: 200,
                        body: include_bytes!("./static/fallback.html").to_vec(),
                    }))
                },
                "test.sxg" => {
                    let mut fallback_url = req_url;
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
                },
                _ => None,
            }
        } else if let Some(cert_name) = path.strip_prefix(&self.config.cert_url_dirname) {
            if cert_name == self.cert_basename() {
                Some(PresetContent::Direct(HttpResponse {
                    body: self.create_cert_cbor(ocsp_der),
                    headers: vec![(String::from("content-type"), String::from("application/cert-chain+cbor"))],
                    status: 200,
                }))
            } else {
                Some(PresetContent::Direct(HttpResponse {
                    headers: vec![(String::from("content-type"), String::from("text/plain"))],
                    status: 404,
                    body: format!("Unknown path {}", req_url).into_bytes(),
                }))
            }
        } else if let Some(validity_name) = path.strip_prefix(&self.config.validity_url_dirname) {
            if validity_name == "validity" {
                Some(PresetContent::Direct(HttpResponse {
                    body: self.create_validity(),
                    headers: vec![(String::from("content-type"), String::from("application/cbor"))],
                    status: 200,
                }))
            } else {
                Some(PresetContent::Direct(HttpResponse {
                    headers: vec![(String::from("content-type"), String::from("text/plain"))],
                    status: 404,
                    body: format!("Unknown path {}", req_url).into_bytes(),
                }))
            }
        } else {
            None
        }
    }
    pub fn transform_request_headers(&self, fields: HeaderFields, accept_filter: AcceptFilter) -> Result<HeaderFields, String> {
        let headers = Headers::new(fields, &self.config.strip_request_headers);
        headers.forward_to_origin_server(accept_filter, &self.config.forward_request_headers)
    }
    pub fn validate_payload_headers(&self, fields: HeaderFields) -> Result<(), String> {
        let headers = Headers::new(fields, &self.config.strip_response_headers);
        headers.validate_as_sxg_payload()
    }
}

pub struct CreateSignedExchangeParams<'a> {
    pub fallback_url: &'a str,
    pub cert_origin: &'a str,
    pub now: std::time::SystemTime,
    pub payload_body: &'a [u8],
    pub payload_headers: headers::Headers,
    pub signer: Box<dyn signature::Signer>,
    pub status_code: u16,
}

#[cfg(test)]
mod lib_tests {
    use utils::tests as util;
    use super::*;
    fn new_worker() -> SxgWorker {
        let yaml = r#"
cert_url_dirname: ".well-known/sxg-certs/"
forward_request_headers:
  - "cf-IPCOUNTRY"
  - "USER-agent"
html_host: my_domain.com
reserved_path: ".sxg"
respond_debug_info: false
strip_request_headers: ["Forwarded"]
strip_response_headers: ["Set-Cookie", "STRICT-TRANSPORT-SECURITY"]
validity_url_dirname: "//.well-known/sxg-validity"
        "#;
        SxgWorker::new(yaml, util::SELF_SIGNED_CERT_PEM, util::SELF_SIGNED_CERT_PEM)
    }
    #[test]
    fn cert_basename() {
        assert_eq!(new_worker().cert_basename(), util::SELF_SIGNED_CERT_SHA256);
    }
    #[test]
    fn serve_preset_content() {
        let worker = new_worker();
        assert_eq!(worker.serve_preset_content("https://my_domain.com/unknown", &[]), None);
        assert!(matches!(worker.serve_preset_content("https://my_domain.com/.sxg/test.html", &[]), Some(PresetContent::Direct(HttpResponse { status: 200, .. }))));
        assert!(matches!(worker.serve_preset_content("https://my_domain.com/.sxg/test.sxg", &[]), Some(PresetContent::ToBeSigned{..})));
        assert!(matches!(
                    worker.serve_preset_content(&format!("https://my_domain.com/.well-known/sxg-certs/{}", util::SELF_SIGNED_CERT_SHA256), &[]),
                    Some(PresetContent::Direct(HttpResponse { status: 200, .. }))));
        assert!(matches!(
                    worker.serve_preset_content("https://my_domain.com/.well-known/sxg-certs/unknown", &[]),
                    Some(PresetContent::Direct(HttpResponse { status: 404, .. }))));
        assert!(matches!(
                    worker.serve_preset_content("https://my_domain.com/.well-known/sxg-validity/validity", &[]),
                    Some(PresetContent::Direct(HttpResponse { status: 200, .. }))));
        assert!(matches!(
                    worker.serve_preset_content("https://my_domain.com/.well-known/sxg-validity/unknown", &[]),
                    Some(PresetContent::Direct(HttpResponse { status: 404, .. }))));
    }
}
