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
pub mod header_integrity;
pub mod headers;
pub mod http;
pub mod http_cache;
pub mod http_parser;
mod id_headers;
mod link;
mod mice;
pub mod ocsp;
pub mod process_html;
pub mod runtime;
pub mod serde_helpers;
pub mod signature;
pub mod storage;
pub mod structured_header;
pub mod sxg;
pub mod utils;
#[cfg(feature = "wasm")]
mod wasm_worker;

use crate::http::{HeaderFields, HttpResponse};
use crate::utils::console_log;
use anyhow::{anyhow, Error, Result};
use config::Config;
use crypto::CertificateChain;
use headers::{AcceptLevel, Headers};
use http_cache::HttpCache;
use runtime::Runtime;
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;
use url::{Origin, Url};

#[derive(Debug)]
pub struct SxgWorker {
    config: Config,
    /// Each new certificate is pushed to the back of the deque.
    /// The back certificate the the latest one.
    certificates: VecDeque<CertificateChain>,
}

#[derive(Serialize, Debug, Eq, PartialEq)]
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

pub const MAX_PAYLOAD_SIZE: usize = 8_000_000;

impl SxgWorker {
    pub fn new(config_yaml: &str) -> Result<Self> {
        let config = Config::new(config_yaml)?;
        Ok(Self::from_parsed(config))
    }
    pub fn from_parsed(config: Config) -> Self {
        SxgWorker {
            config,
            certificates: VecDeque::new(),
        }
    }
    pub fn add_certificate(&mut self, certificate: CertificateChain) {
        self.certificates.push_back(certificate);
    }
    /// Reads ACME storage, and adds all ACME certificates to worker.
    pub async fn add_acme_certificates_from_storage(&mut self, runtime: &Runtime) -> Result<()> {
        let acme_state = acme::state_machine::read_current_state(runtime).await?;
        for certificate_pem in acme_state.certificates {
            let certificate = CertificateChain::from_pem_files(&[&certificate_pem])?;
            self.add_certificate(certificate);
        }
        Ok(())
    }
    pub fn config(&self) -> &Config {
        &self.config
    }
    fn find_certificate_by_basename(&self, basename: &str) -> Option<&CertificateChain> {
        self.certificates
            .iter()
            .find(|cert| cert.basename == basename)
    }
    pub fn latest_certificate_basename(&self) -> Option<&str> {
        Some(&self.certificates.back()?.basename)
    }
    pub fn create_cert_cbor(&self, cert_basename: &str, ocsp_der: &[u8]) -> Vec<u8> {
        if let Some(certificate) = self.find_certificate_by_basename(cert_basename) {
            certificate.create_cert_cbor(ocsp_der)
        } else {
            cbor::DataItem::Array(vec![]).serialize()
        }
    }
    pub fn process_html(
        &self,
        input: Arc<HttpResponse>,
        option: process_html::ProcessHtmlOption,
    ) -> Arc<HttpResponse> {
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

        let latest_certificate = self
            .certificates
            .back()
            .ok_or_else(|| Error::msg("Can't create signed exchange without certificate chain."))?;

        let fallback_base = Url::parse(fallback_url)
            .map_err(|e| Error::new(e).context("Failed to parse fallback URL"))?;
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
        let cert_url = match Url::parse(cert_origin) {
            Ok(cert_base) => {
                let cert_url = cert_base
                    .join(&format!(
                        "{}{}",
                        &self.config.cert_url_dirname, &latest_certificate.basename
                    ))
                    .map_err(|e| Error::new(e).context("Failed to parse cert_url_dirname"))?;
                cert_url.into()
            }
            // In the case that `cert_origin` is invalid, it fallbacks to use data-url.
            Err(_) => {
                let ocsp_der = self.get_unexpired_ocsp(runtime, latest_certificate).await?;
                let cert_body = latest_certificate.create_cert_cbor(&ocsp_der);
                format!(
                    "data:application/cert-chain+cbor;base64,{}",
                    base64::encode(&cert_body)
                )
            }
        };
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
        let max_age = payload_headers.signature_duration()?;
        let expires = runtime.now.checked_add(max_age);
        let signature = signature::Signature::new(signature::SignatureParams {
            cert_url: cert_url.as_str(),
            cert_sha256: &latest_certificate.end_entity_sha256,
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
                (
                    "cache-control".into(),
                    format!(
                        "public, max-age={}",
                        // The outer max-age is set smaller, hence the downstream CDNs are able to
                        // refetch SXG before the SXG signature expires.
                        max_age.as_secs() / 4,
                    ),
                ),
            ],
            status: 200,
        })
    }
    fn create_validity(&self) -> Vec<u8> {
        let validity = cbor::DataItem::Map(vec![]);
        validity.serialize()
    }
    pub async fn get_unexpired_ocsp(
        &self,
        runtime: &Runtime,
        certificate: &CertificateChain,
    ) -> Result<Vec<u8>> {
        ocsp::read_and_update_ocsp_in_storage(
            certificate,
            runtime,
            ocsp::OcspUpdateStrategy::LazyIfUnexpired,
        )
        .await
    }
    pub async fn update_oscp_in_storage(&self, runtime: &Runtime) -> Result<()> {
        if let Some(certificate) = &self.certificates.back() {
            ocsp::read_and_update_ocsp_in_storage(
                certificate,
                runtime,
                ocsp::OcspUpdateStrategy::EarlyAsRecommended,
            )
            .await?;
        }
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
                    let (fallback_url, _) =
                        self.get_fallback_url_and_cert_origin(&fallback_url).ok()?;
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
            if let Some(certificate) = self.find_certificate_by_basename(cert_name) {
                let ocsp_der = self.get_unexpired_ocsp(runtime, certificate).await.ok()?;
                Some(PresetContent::Direct(HttpResponse {
                    body: certificate.create_cert_cbor(&ocsp_der),
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
        } else if let Some(actual_token) = path.strip_prefix("/.well-known/acme-challenge/") {
            match crate::acme::state_machine::get_challenge_token_and_answer(runtime).await {
                Ok(Some((expected_token, answer))) => {
                    if actual_token == expected_token {
                        Some(PresetContent::Direct(HttpResponse {
                            status: 200,
                            headers: vec![(
                                String::from("content-type"),
                                String::from("application/octet-stream"),
                            )],
                            body: answer.into_bytes(),
                        }))
                    } else {
                        console_log(&format!(
                            "Received ACME challenge {actual_token}, expected {expected_token}."
                        ));
                        None
                    }
                }
                Ok(None) => {
                    console_log("Unexpected ACME challenge; no ACME state in storage.");
                    None
                }
                Err(e) => {
                    console_log(&format!("ACME challenge error: {e}"));
                    None
                }
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
        required_accept_level: AcceptLevel,
    ) -> Result<HeaderFields> {
        let headers = Headers::new(fields, &self.config.strip_request_headers);
        headers
            .forward_to_origin_server(required_accept_level, &self.config.forward_request_headers)
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
    /// Given an original SXG URL (SXG outer URL),
    /// returns the fallback URL (SXG inner URL) and certificate origin.
    /// The certificate origin is the worker origin, which is taken from outer URL.
    /// The inner URL is created by
    /// replacing the host name to be the `html_host` in the config.
    pub fn get_fallback_url_and_cert_origin(&self, original_url: &Url) -> Result<(Url, Origin)> {
        let mut fallback = original_url.clone();
        let html_host = &self.config.html_host;
        if !html_host.is_empty() {
            fallback
                .set_scheme("https")
                .map_err(|_| anyhow!("invalid scheme https"))?;
            fallback.set_host(Some(html_host)).map_err(Error::new)?;
        }
        let cert_origin = original_url.origin();
        Ok((fallback, cert_origin))
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

        let mut worker = SxgWorker::new(yaml).unwrap();
        worker.add_certificate(
            CertificateChain::from_pem_files(&[
                util::SELF_SIGNED_CERT_PEM,
                util::SELF_SIGNED_CERT_PEM,
            ])
            .unwrap(),
        );
        worker
    }
    #[test]
    fn cert_basename() {
        assert_eq!(
            new_worker().latest_certificate_basename().unwrap(),
            util::SELF_SIGNED_CERT_SHA256
        );
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
    #[cfg(not(feature = "wasm"))]
    #[test]
    fn require_send() {
        use std::collections::BTreeSet;
        // Require async fns to implement Send, so they can be shared across
        // threads. This is required by hyper, as used in http_server. See
        // https://blog.rust-lang.org/inside-rust/2019/10/11/AsyncAwait-Not-Send-Error-Improvements.html.
        // Adding the requirement directly in this test makes it easier to
        // diagnose; compiler errors are more specific than when the
        // requirement is indirect via hyper. Values don't matter in this test;
        // we're only verifying types.
        let worker = new_worker();
        let runtime = Runtime::default();
        fn is_send<T: Send>(_: T) {}
        is_send(worker.serve_preset_content(&runtime, "https://my_domain.com/unknown"));
        is_send(worker.create_signed_exchange(
            &runtime,
            CreateSignedExchangeParams {
                fallback_url: "",
                cert_origin: "",
                payload_body: b"",
                payload_headers: Headers::new(vec![], &BTreeSet::new()),
                skip_process_link: false,
                status_code: 200,
                header_integrity_cache: http_cache::NullCache {},
            },
        ));
    }
}
