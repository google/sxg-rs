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
mod header_integrity;
pub mod headers;
pub mod http;
pub mod http_cache;
mod http_parser;
mod id_headers;
mod link;
mod mice;
mod ocsp;
pub mod signature;
mod structured_header;
mod sxg;
mod utils;
#[cfg(feature = "wasm")]
mod wasm_worker;

use anyhow::{Error, Result};
use config::Config;
use fetcher::Fetcher;
use headers::{AcceptFilter, Headers};
use http::{HeaderFields, HttpResponse};
use http_cache::HttpCache;
use serde::Serialize;
use url::Url;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct SxgWorker {
    config: Config,
}

#[derive(Serialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum PresetContent {
    Direct(HttpResponse),
    ToBeSigned {
        url: String,
        payload: HttpResponse,
        fallback: HttpResponse,
    },
}

impl SxgWorker {
    pub fn new(config_yaml: &str, cert_pem: &str, issuer_pem: &str) -> Result<SxgWorker> {
        let config = Config::new(config_yaml, cert_pem, issuer_pem)?;
        Ok(SxgWorker { config })
    }
    // TODO: Make OCSP status as an internal state of SxgWorker, so that
    // SxgWorker is able to fetch OCSP. This will need a definition of a
    // Fetcher trait. Both js and rust callers need to implement this trait.
    pub fn create_cert_cbor(&self, ocsp_der: &[u8]) -> Vec<u8> {
        use cbor::DataItem;
        let cert_cbor = DataItem::Array(vec![
            DataItem::TextString("📜⛓"),
            DataItem::Map(vec![
                (
                    DataItem::TextString("cert"),
                    DataItem::ByteString(&self.config.cert_der),
                ),
                (DataItem::TextString("ocsp"), DataItem::ByteString(ocsp_der)),
            ]),
            DataItem::Map(vec![(
                DataItem::TextString("cert"),
                DataItem::ByteString(&self.config.issuer_der),
            )]),
        ]);
        cert_cbor.serialize()
    }
    pub fn cert_basename(&self) -> String {
        base64::encode_config(&self.config.cert_sha256, base64::URL_SAFE_NO_PAD)
    }
    pub async fn create_signed_exchange<S: signature::Signer, F: Fetcher, C: HttpCache>(
        &self,
        params: CreateSignedExchangeParams<'_, S, F, C>,
    ) -> Result<HttpResponse> {
        let CreateSignedExchangeParams {
            fallback_url,
            cert_origin,
            now,
            payload_body,
            payload_headers,
            signer,
            status_code,
            subresource_fetcher,
            header_integrity_cache,
        } = params;
        let fallback_base = Url::parse(fallback_url)
            .map_err(|e| Error::new(e).context("Failed to parse fallback URL"))?;
        let cert_base = Url::parse(cert_origin)
            .map_err(|e| Error::new(e).context("Failed to parse cert origin"))?;
        let (signed_headers, payload_body) = utils::signed_headers_and_payload(
            &fallback_base,
            status_code,
            &payload_headers,
            payload_body,
            subresource_fetcher,
            header_integrity_cache,
            &self.config.strip_response_headers,
        )
        .await?;
        let cert_url = cert_base
            .join(&format!(
                "{}{}",
                &self.config.cert_url_dirname,
                &self.cert_basename()
            ))
            .map_err(|e| Error::new(e).context("Failed to parse cert_url_dirname"))?;
        let validity_url = fallback_base
            .join(&format!(
                "{}{}",
                &self.config.validity_url_dirname, "validity"
            ))
            .map_err(|e| Error::new(e).context("Failed to parse validity_url_dirname"))?;
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
        })
        .await;

        let signature = signature.map_err(|e| e.context("Failed to create signature."))?;
        let sxg_body = sxg::build(
            fallback_url,
            &signature.serialize(),
            &signed_headers,
            &payload_body,
        )
        .map_err(|e| e.context("Failed to create SXG."))?;
        Ok(HttpResponse {
            body: sxg_body,
            headers: vec![
                (
                    "content-type".into(),
                    "application/signed-exchange;v=b3".into(),
                ),
                ("x-content-type-options".into(), "nosniff".into()),
            ],
            status: 200,
        })
    }
    fn create_validity(&self) -> Vec<u8> {
        let validity = cbor::DataItem::Map(vec![]);
        validity.serialize()
    }
    pub async fn fetch_ocsp_from_ca<F: fetcher::Fetcher>(&self, fetcher: F) -> Vec<u8> {
        let result =
            ocsp::fetch_from_ca(&self.config.cert_der, &self.config.issuer_der, fetcher).await;
        // TODO: Remove panic
        result.unwrap()
    }
    pub fn serve_preset_content(&self, req_url: &str, ocsp_der: &[u8]) -> Option<PresetContent> {
        let req_url = url::Url::parse(req_url).ok()?;
        let path = req_url.path();
        if let Some(basename) = path.strip_prefix(&self.config.reserved_path) {
            match basename {
                "test.html" => Some(PresetContent::Direct(HttpResponse {
                    headers: vec![(String::from("content-type"), String::from("text/html"))],
                    status: 200,
                    body: include_bytes!("./static/test.html").to_vec(),
                })),
                "prefetch.html" => Some(PresetContent::Direct(HttpResponse {
                    headers: vec![(String::from("content-type"), String::from("text/html"))],
                    status: 200,
                    body: include_bytes!("./static/prefetch.html").to_vec(),
                })),
                "fallback.html" => Some(PresetContent::Direct(HttpResponse {
                    headers: vec![(String::from("content-type"), String::from("text/html"))],
                    status: 200,
                    body: include_bytes!("./static/fallback.html").to_vec(),
                })),
                "test.sxg" => {
                    let mut fallback_url = req_url;
                    fallback_url
                        .set_path(&fallback_url.path().replace("test.sxg", "fallback.html"));
                    Some(PresetContent::ToBeSigned {
                        url: fallback_url.to_string(),
                        payload: HttpResponse {
                            headers: vec![(
                                String::from("content-type"),
                                String::from("text/html"),
                            )],
                            status: 200,
                            body: include_bytes!("./static/success.html").to_vec(),
                        },
                        fallback: HttpResponse {
                            headers: vec![(
                                String::from("content-type"),
                                String::from("text/html"),
                            )],
                            status: 200,
                            body: include_bytes!("./static/fallback.html").to_vec(),
                        },
                    })
                }
                _ => None,
            }
        } else if let Some(cert_name) = path.strip_prefix(&self.config.cert_url_dirname) {
            if cert_name == self.cert_basename() {
                Some(PresetContent::Direct(HttpResponse {
                    body: self.create_cert_cbor(ocsp_der),
                    headers: vec![(
                        String::from("content-type"),
                        String::from("application/cert-chain+cbor"),
                    )],
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
                    headers: vec![(
                        String::from("content-type"),
                        String::from("application/cbor"),
                    )],
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
    /// Checks `fields` as request headers from browser,
    /// and returns the request headers to be sent to backend server.
    pub fn transform_request_headers(
        &self,
        fields: HeaderFields,
        accept_filter: AcceptFilter,
    ) -> Result<HeaderFields> {
        let headers = Headers::new(fields, &self.config.strip_request_headers);
        headers.forward_to_origin_server(accept_filter, &self.config.forward_request_headers)
    }
    /// Checks `fields` as response headers from backend server,
    /// and returns the reqsponse headers to be sent to browser.
    pub fn transform_payload_headers(&self, fields: HeaderFields) -> Result<Headers> {
        let headers = Headers::new(fields, &self.config.strip_response_headers);
        headers.validate_as_sxg_payload()?;
        Ok(headers)
    }
    #[cfg(feature = "rust_signer")]
    pub fn create_rust_signer(&self) -> Result<signature::rust_signer::RustSigner> {
        let private_key_der = base64::decode(
            self.config
                .private_key_base64
                .as_ref()
                .ok_or_else(|| Error::msg("Config private_key_base64 is not set"))?,
        )?;
        signature::rust_signer::RustSigner::new(&private_key_der)
            .map_err(|e| e.context("Failed to call RustSigner::new()."))
    }
    pub fn should_respond_debug_info(&self) -> bool {
        self.config.respond_debug_info
    }
    /// Replaces the host name to be the html_host in the config.
    // TODO: implement get_fallback_url_and_cert_origin, so that Cloudflare Worker can use it.
    pub fn get_fallback_url(&self, original_url: &Url) -> Result<Url> {
        let mut fallback = original_url.clone();
        if let Some(html_host) = &self.config.html_host {
            if !html_host.is_empty() {
                fallback.set_host(Some(html_host)).map_err(Error::new)?;
            }
        }
        Ok(fallback)
    }
}

pub struct CreateSignedExchangeParams<'a, S: signature::Signer, F: Fetcher, C: HttpCache> {
    pub fallback_url: &'a str,
    pub cert_origin: &'a str,
    pub now: std::time::SystemTime,
    pub payload_body: &'a [u8],
    pub payload_headers: headers::Headers,
    pub signer: S,
    pub status_code: u16,
    pub subresource_fetcher: F,
    pub header_integrity_cache: C,
}

#[cfg(test)]
mod lib_tests {
    use super::*;
    use utils::tests as util;
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
        SxgWorker::new(yaml, util::SELF_SIGNED_CERT_PEM, util::SELF_SIGNED_CERT_PEM).unwrap()
    }
    #[test]
    fn cert_basename() {
        assert_eq!(new_worker().cert_basename(), util::SELF_SIGNED_CERT_SHA256);
    }
    #[test]
    fn serve_preset_content() {
        let worker = new_worker();
        assert_eq!(
            worker.serve_preset_content("https://my_domain.com/unknown", &[]),
            None
        );
        assert!(matches!(
            worker.serve_preset_content("https://my_domain.com/.sxg/test.html", &[]),
            Some(PresetContent::Direct(HttpResponse { status: 200, .. }))
        ));
        assert!(matches!(
            worker.serve_preset_content("https://my_domain.com/.sxg/test.sxg", &[]),
            Some(PresetContent::ToBeSigned { .. })
        ));
        assert!(matches!(
            worker.serve_preset_content(
                &format!(
                    "https://my_domain.com/.well-known/sxg-certs/{}",
                    util::SELF_SIGNED_CERT_SHA256
                ),
                &[]
            ),
            Some(PresetContent::Direct(HttpResponse { status: 200, .. }))
        ));
        assert!(matches!(
            worker.serve_preset_content("https://my_domain.com/.well-known/sxg-certs/unknown", &[]),
            Some(PresetContent::Direct(HttpResponse { status: 404, .. }))
        ));
        assert!(matches!(
            worker.serve_preset_content(
                "https://my_domain.com/.well-known/sxg-validity/validity",
                &[]
            ),
            Some(PresetContent::Direct(HttpResponse { status: 200, .. }))
        ));
        assert!(matches!(
            worker.serve_preset_content(
                "https://my_domain.com/.well-known/sxg-validity/unknown",
                &[]
            ),
            Some(PresetContent::Direct(HttpResponse { status: 404, .. }))
        ));
    }
}
