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

mod fetcher;
mod storage;

use anyhow::{Error, Result};
use fastly::{http::Url, Error as FastlyError, Request, Response};
use fetcher::FastlyFetcher;
use std::convert::TryInto;
use sxg_rs::{
    crypto::CertificateChain,
    headers::{AcceptLevel, Headers, VIA_SXGRS},
    http::HeaderFields,
    PresetContent, SxgWorker,
};
use url::Origin;

/// The name of Fastly dictionary to be used as worker's runtime storage.
const DICTIONARY_NAME: &str = "config";

async fn create_worker() -> SxgWorker {
    let dict = fastly::ConfigStore::open(DICTIONARY_NAME);
    let mut worker = ::sxg_rs::SxgWorker::new(&dict.get("sxg-config-input").unwrap()).unwrap();
    let preissued = (dict.get("cert-pem"), dict.get("issuer-pem"));
    if let (Some(cert_pem), Some(issuer_pem)) = preissued {
        let certificate = CertificateChain::from_pem_files(&[&cert_pem, &issuer_pem]).unwrap();
        worker.add_certificate(certificate);
    }
    let runtime = sxg_rs::runtime::Runtime {
        storage: Box::new(storage::FastlyStorage::new("config")),
        ..Default::default()
    };
    worker
        .add_acme_certificates_from_storage(&runtime)
        .await
        .unwrap();
    worker
}

async fn get_req_header_fields(
    worker: &SxgWorker,
    req: &Request,
    accept_filter: AcceptLevel,
) -> Result<HeaderFields> {
    let mut fields: Vec<(String, String)> = vec![];
    for name in req.get_header_names() {
        for value in req.get_header_all(name) {
            let value = value.to_str().map_err(|_| {
                Error::msg(format!(r#"Header "{}" contains non-ASCII value."#, name))
            })?;
            fields.push((name.as_str().to_string(), value.to_string()))
        }
    }
    worker.transform_request_headers(fields, accept_filter)
}

async fn get_rsp_header_fields(worker: &SxgWorker, rsp: &Response) -> Result<Headers> {
    let mut fields: Vec<(String, String)> = vec![];
    for name in rsp.get_header_names() {
        for value in rsp.get_header_all(name) {
            let value = value.to_str().map_err(|_| {
                Error::msg(format!(r#"Header "{}" contains non-ASCII value."#, name))
            })?;
            fields.push((name.as_str().to_string(), value.to_string()))
        }
    }
    worker.transform_payload_headers(fields)
}

pub fn sxg_rs_response_to_fastly_response(
    rsp: sxg_rs::http::HttpResponse,
) -> anyhow::Result<fastly::Response> {
    let rsp: ::http::response::Response<Vec<u8>> = rsp.try_into()?;
    let rsp: ::http::response::Response<fastly::Body> = rsp.map(From::<Vec<u8>>::from);
    Ok(rsp.into())
}

/// The *name* of the host in Fastly service configuration.
/// https://docs.fastly.com/en/guides/working-with-hosts
const HTML_BACKEND_NAME: &str = "Origin HTML server";

fn fetch_from_html_server(url: &Url, req_headers: Vec<(String, String)>) -> Result<Response> {
    let mut req = Request::new("GET", url);
    for (name, value) in req_headers {
        req.append_header(name, value);
    }
    req.send(HTML_BACKEND_NAME)
        .map_err(|err| Error::msg(format!(r#"Fetching "{}" leads to error "{}""#, url, err)))
}

async fn generate_sxg_response(
    worker: &SxgWorker,
    fallback_url: &Url,
    cert_origin: Origin,
    payload: Response,
) -> Result<Response> {
    let payload_headers = get_rsp_header_fields(worker, &payload).await?;
    let payload_body = payload.into_body_bytes();
    let cert_origin = cert_origin.ascii_serialization();
    let runtime = sxg_rs::runtime::Runtime {
        now: std::time::SystemTime::now(),
        fetcher: Box::new(FastlyFetcher::new("subresources")),
        storage: Box::new(storage::FastlyStorage::new("config")),
        sxg_signer: Box::new(worker.create_rust_signer().unwrap()),
        ..Default::default()
    };
    let sxg = worker.create_signed_exchange(
        &runtime,
        sxg_rs::CreateSignedExchangeParams {
            payload_body: &payload_body,
            payload_headers,
            skip_process_link: false,
            status_code: 200,
            fallback_url: fallback_url.as_str(),
            cert_origin: &cert_origin,
            // The fastly crate provides only read access to dictionaries, so
            // header integrities cannot be cached. However, I believe the
            // subresource_fetcher will go through the cache.
            header_integrity_cache: sxg_rs::http_cache::NullCache {},
        },
    );
    let sxg = sxg.await?;
    sxg_rs_response_to_fastly_response(sxg)
}

async fn handle_request(worker: &SxgWorker, req: &Request) -> Result<Response> {
    let runtime = sxg_rs::runtime::Runtime {
        now: std::time::SystemTime::now(),
        fetcher: Box::new(FastlyFetcher::new("OCSP server")),
        storage: Box::new(storage::FastlyStorage::new("config")),
        ..Default::default()
    };
    let fallback_url: Url;
    let cert_origin: Origin;
    let sxg_payload;
    let preset_content = worker
        .serve_preset_content(&runtime, req.get_url_str())
        .await;
    match preset_content {
        Some(PresetContent::Direct(response)) => {
            return sxg_rs_response_to_fastly_response(response)
        }
        Some(PresetContent::ToBeSigned { url, payload, .. }) => {
            fallback_url = Url::parse(&url).map_err(Error::new)?;
            (_, cert_origin) = worker.get_fallback_url_and_cert_origin(req.get_url())?;
            sxg_payload = sxg_rs_response_to_fastly_response(payload)?;
            get_req_header_fields(worker, req, AcceptLevel::AcceptsSxg).await?;
        }
        None => {
            (fallback_url, cert_origin) = worker.get_fallback_url_and_cert_origin(req.get_url())?;
            let req_headers = get_req_header_fields(worker, req, AcceptLevel::PrefersSxg).await?;
            sxg_payload = fetch_from_html_server(&fallback_url, req_headers)?;
        }
    };
    generate_sxg_response(worker, &fallback_url, cert_origin, sxg_payload).await
}

#[fastly::main]
fn main(req: Request) -> Result<Response, FastlyError> {
    let has_network_loop = req
        .get_header_all_str("via")
        .iter()
        .any(|v| v.contains(VIA_SXGRS));
    if has_network_loop {
        return Err(FastlyError::msg("Network loop detected."));
    }
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let worker = create_worker().await;
            match handle_request(&worker, &req).await {
                Ok(sxg_response) => Ok(sxg_response),
                Err(_) => {
                    let mut req = req;
                    let (fallback_url, _) = worker
                        .get_fallback_url_and_cert_origin(req.get_url())
                        .map_err(|_| FastlyError::msg("Failed to construct fallback URL"))?;
                    req.set_url(fallback_url);
                    req.append_header("via", VIA_SXGRS);
                    req.send(HTML_BACKEND_NAME)
                        .map_err(|_| FastlyError::msg("Failed to fetch from fallback URL"))
                }
            }
        })
}
