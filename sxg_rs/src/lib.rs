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

pub mod acme;
mod cbor;
pub mod config;
pub mod crypto;
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
pub mod process_html;
pub mod runtime;
pub mod serde_helpers;
pub mod signature;
pub mod storage;
mod structured_header;
mod sxg;
pub mod utils;
#[cfg(feature = "wasm")]
mod wasm_worker;

use crate::http::{HeaderFields, HttpResponse};
use anyhow::{anyhow, Error, Result};
use config::Config;
use headers::{AcceptFilter, Headers};
use http_cache::HttpCache;
use runtime::Runtime;
use serde::Serialize;
use std::time::Duration;
use url::Url;

#[derive(Debug)]
pub struct SxgWorker {
    config: Config,
    cert_der: Vec<u8>,
    cert_sha256: Vec<u8>,
    issuer_der: Vec<u8>,
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

// To avoid issues with clock skew, backdate the start time by an hour. Don't backdate the
// expiration because it goes against the origin's cache-control header. (e.g. For max-age
// <1h, an SXG would be instantly invalid; this would be confusing.)
const BACKDATING: Duration = Duration::from_secs(60 * 60);

pub(crate) const MAX_PAYLOAD_SIZE: usize = 8_000_000;

impl SxgWorker {
    pub fn new(config_yaml: &str, cert_pem: &str, issuer_pem: &str) -> Result<Self> {
        let config = Config::new(config_yaml)?;
        let cert_der = crypto::get_der_from_pem(cert_pem, "CERTIFICATE")?;
        let issuer_der = crypto::get_der_from_pem(issuer_pem, "CERTIFICATE")?;
        Ok(Self::from_parsed(config, cert_der, issuer_der))
    }
    pub fn from_parsed(config: Config, cert_der: Vec<u8>, issuer_der: Vec<u8>) -> Self {
        SxgWorker {
            config,
            cert_sha256: crypto::HashAlgorithm::Sha256.digest(&cert_der),
            cert_der,
            issuer_der,
        }
    }
    pub fn set_cert_and_issuer(&mut self, cert_der: Vec<u8>, issuer_der: Vec<u8>) {
        self.cert_sha256 = crypto::HashAlgorithm::Sha256.digest(&cert_der);
        self.cert_der = cert_der;
        self.issuer_der = issuer_der;
    }
    pub fn config(&self) -> &Config {
        &self.config
    }
    // TODO: Make OCSP status as an internal state of SxgWorker, so that
    // SxgWorker is able to fetch OCSP. This will need a definition of a
    // Fetcher trait. Both js and rust callers need to implement this trait.
    pub async fn create_cert_cbor(&self, ocsp_der: &[u8]) -> Vec<u8> {
        use cbor::DataItem;
        let cert_cbor = DataItem::Array(vec![
            DataItem::TextString("📜⛓"),
            DataItem::Map(vec![
                (
                    DataItem::TextString("cert"),
                    DataItem::ByteString(&self.cert_der),
                ),
                (DataItem::TextString("ocsp"), DataItem::ByteString(ocsp_der)),
            ]),
            DataItem::Map(vec![(
                DataItem::TextString("cert"),
                DataItem::ByteString(&self.issuer_der),
            )]),
        ]);
        cert_cbor.serialize()
    }
    pub fn cert_basename(&self) -> String {
        base64::encode_config(&self.cert_sha256, base64::URL_SAFE_NO_PAD)
    }
    pub fn process_html(
        &self,
        input: HttpResponse,
        option: process_html::ProcessHtmlOption,
    ) -> Result<HttpResponse> {
        process_html::process_html(input, option)
    }
    pub async fn create_signed_exchange<C: HttpCache>(
        &self,
        runtime: &Runtime,
        params: CreateSignedExchangeParams<'_, C>,
    ) -> Result<HttpResponse> {
        let CreateSignedExchangeParams {
            fallback_url,
            cert_origin,
            payload_body,
            payload_headers,
            skip_process_link,
            status_code,
            header_integrity_cache,
        } = params;
        if payload_body.len() > MAX_PAYLOAD_SIZE {
            return Err(anyhow!(
                "Payload body size is {}, which exceeds the limit {}.",
                payload_body.len(),
                MAX_PAYLOAD_SIZE
            ));
        }

        let fallback_base = Url::parse(fallback_url)
            .map_err(|e| Error::new(e).context("Failed to parse fallback URL"))?;
        let cert_base = Url::parse(cert_origin)
            .map_err(|e| Error::new(e).context("Failed to parse cert origin"))?;
        let mut header_integrity_fetcher = header_integrity::new_fetcher(
            runtime.fetcher.as_ref(),
            header_integrity_cache,
            &self.config.strip_response_headers,
        );
        let (signed_headers, payload_body) = utils::signed_headers_and_payload(
            &fallback_base,
            status_code,
            &payload_headers,
            payload_body,
            &mut header_integrity_fetcher,
            skip_process_link,
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
        let date = runtime
            .now
            .checked_sub(BACKDATING)
            .ok_or_else(|| anyhow!("Failed to construct date"))?;
        let expires = runtime
            .now
            .checked_add(payload_headers.signature_duration()?);
        let signature = signature::Signature::new(signature::SignatureParams {
            cert_url: cert_url.as_str(),
            cert_sha256: &self.cert_sha256,
            date,
            expires,
            headers: &signed_headers,
            id: "sig",
            request_url: fallback_url,
            signer: runtime.sxg_signer.as_ref(),
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
    async fn get_unexpired_ocsp(&self, runtime: &Runtime) -> Result<Vec<u8>> {
        ocsp::read_and_update_ocsp_in_storage(
            &self.cert_der,
            &self.issuer_der,
            runtime,
            ocsp::OcspUpdateStrategy::LazyIfUnexpired,
        )
        .await
    }
    pub async fn update_oscp_in_storage(&self, runtime: &Runtime) -> Result<()> {
        ocsp::read_and_update_ocsp_in_storage(
            &self.cert_der,
            &self.issuer_der,
            runtime,
            ocsp::OcspUpdateStrategy::EarlyAsRecommended,
        )
        .await?;
        Ok(())
    }
    pub async fn serve_preset_content(
        &self,
        runtime: &Runtime,
        req_url: &str,
    ) -> Option<PresetContent> {
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
                let ocsp_der = self.get_unexpired_ocsp(runtime).await.ok()?;
                Some(PresetContent::Direct(HttpResponse {
                    body: self.create_cert_cbor(&ocsp_der).await,
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

pub struct CreateSignedExchangeParams<'a, C: HttpCache> {
    pub fallback_url: &'a str,
    pub cert_origin: &'a str,
    pub payload_body: &'a [u8],
    pub payload_headers: headers::Headers,
    pub skip_process_link: bool,
    pub status_code: u16,
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
    #[tokio::test]
    async fn serve_preset_content() {
        let worker = new_worker();
        let runtime = Runtime::default();
        assert_eq!(
            worker
                .serve_preset_content(&runtime, "https://my_domain.com/unknown",)
                .await,
            None
        );
        assert!(matches!(
            worker
                .serve_preset_content(&runtime, "https://my_domain.com/.sxg/test.html",)
                .await,
            Some(PresetContent::Direct(HttpResponse { status: 200, .. }))
        ));
        assert!(matches!(
            worker
                .serve_preset_content(&runtime, "https://my_domain.com/.sxg/test.sxg",)
                .await,
            Some(PresetContent::ToBeSigned { .. })
        ));
        assert!(matches!(
            worker
                .serve_preset_content(
                    &runtime,
                    &format!(
                        "https://my_domain.com/.well-known/sxg-certs/{}",
                        util::SELF_SIGNED_CERT_SHA256
                    ),
                )
                .await,
            Some(PresetContent::Direct(HttpResponse { status: 200, .. }))
        ));
        assert!(matches!(
            worker
                .serve_preset_content(
                    &runtime,
                    "https://my_domain.com/.well-known/sxg-certs/unknown",
                )
                .await,
            Some(PresetContent::Direct(HttpResponse { status: 404, .. }))
        ));
        assert!(matches!(
            worker
                .serve_preset_content(
                    &runtime,
                    "https://my_domain.com/.well-known/sxg-validity/validity",
                )
                .await,
            Some(PresetContent::Direct(HttpResponse { status: 200, .. }))
        ));
        assert!(matches!(
            worker
                .serve_preset_content(
                    &runtime,
                    "https://my_domain.com/.well-known/sxg-validity/unknown",
                )
                .await,
            Some(PresetContent::Direct(HttpResponse { status: 404, .. }))
        ));
    }
}
