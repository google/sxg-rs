// Copyright 2022 Google LLC
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

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use clap::Parser;
use fs2::FileExt;
use futures::{stream, StreamExt};
use hyper::{
    body::{Bytes, HttpBody},
    server::{conn::AddrStream, Server},
    service::{make_service_fn, service_fn},
    Body, Request, Response, StatusCode,
};
use hyper_reverse_proxy::ReverseProxy;
use hyper_trust_dns::{RustlsHttpsConnector, TrustDnsResolver};
use lru::LruCache;
use std::boxed::Box;
use std::convert::TryInto;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use sxg_rs::{
    crypto::CertificateChain,
    fetcher::Fetcher,
    headers::AcceptFilter,
    http::{HttpRequest, HttpResponse, Method},
    http_cache::HttpCache,
    process_html::ProcessHtmlOption,
    storage::Storage,
    PresetContent, MAX_PAYLOAD_SIZE,
};
use tokio::sync::Mutex;
use url::Url;

// TODO: Add readme, explaining how to create credentials & config.yaml and how to run.

/// HTTP server that acts as a reverse proxy, generating signed exchanges of
/// responses received from the backend. Compare to Web Packager Server.
#[derive(Parser)]
struct Args {
    /// The origin (scheme://host[:port]) of the backend to fetch from, such as
    /// 'https://backend'. To configure the signed domain that appears in the
    /// resultant SXGs, set html_host in config.yaml.
    #[clap(short, long)]
    backend: String,

    /// The bind address (ip:port), such as 0.0.0.0:8080.
    #[clap(short = 'a', long, default_value = "127.0.0.1:8080")]
    bind_addr: String,

    /// Path to the directory where ACME and OCSP files will be / created to
    /// manage state. Will create the directory (but not its parents) if
    /// needed.
    #[clap(short, long, default_value = "/tmp/sxg-rs")]
    directory: PathBuf,

    /// Path to config.yaml.
    #[clap(short, long, default_value = "http_server/config.yaml")]
    config: PathBuf,

    /// Path to the cert PEM for the html_host specified in config.yaml.
    #[clap(short = 'e', long, default_value = "credentials/cert.pem")]
    cert: PathBuf,

    /// Path to the cert PEM for the CA that issued the html_host cert.
    #[clap(short, long, default_value = "credentials/issuer.pem")]
    issuer: PathBuf,

    /// Maximum number of entries in the header integrity cache. Each entry will be about 1KB.
    #[clap(long, default_value = "2000")]
    header_integrity_cache_size: usize,
}

type HttpsClient = hyper::Client<
    hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector<TrustDnsResolver>>,
>;

lazy_static::lazy_static! {
    static ref ARGS: Args = Args::parse();

    static ref HTTPS_CLIENT: HttpsClient =
        hyper::Client::builder().build::<_, hyper::Body>(TrustDnsResolver::default().into_rustls_webpki_https_connector());

    static ref PROXY_CLIENT: ReverseProxy<RustlsHttpsConnector> =
        ReverseProxy::new(
            hyper::Client::builder().build::<_, hyper::Body>(TrustDnsResolver::default().into_rustls_webpki_https_connector()));

    static ref WORKER: sxg_rs::SxgWorker = {
        let mut worker = sxg_rs::SxgWorker::new(&fs::read_to_string(&ARGS.config).unwrap()).unwrap();
        worker.add_certificate(CertificateChain::from_pem_files(&[
              &fs::read_to_string(&ARGS.cert).unwrap(),
              &fs::read_to_string(&ARGS.issuer).unwrap(),
        ]).unwrap());
        worker
    };

    static ref HEADER_INTEGRITY: LruHttpCache = LruHttpCache(Mutex::new(LruCache::new(ARGS.header_integrity_cache_size)));
}

async fn req_to_vec_body(request: Request<Body>) -> Result<Request<Vec<u8>>> {
    let (parts, body) = request.into_parts();
    let body = hyper::body::to_bytes(body).await?.to_vec();
    Ok(Request::from_parts(parts, body))
}

#[derive(Debug)]
enum Payload {
    InMemory(Response<Vec<u8>>),
    Streamed(Response<Body>),
}

// If body length is <= MAX_PAYLOAD_SIZE, returns it buffered in memory. Else,
// returns a Body that streams the full response.
async fn resp_to_vec_body(response: Response<Body>) -> Result<Payload> {
    let (parts, mut body) = response.into_parts();
    if matches!(body.size_hint().upper(), Some(size) if size <= MAX_PAYLOAD_SIZE.try_into().unwrap_or(u64::MAX))
    {
        Ok(Payload::InMemory(Response::from_parts(
            parts,
            hyper::body::to_bytes(body).await?.to_vec(),
        )))
    } else {
        let mut buf = Vec::with_capacity(
            body.size_hint()
                .lower()
                .try_into()
                .unwrap_or(MAX_PAYLOAD_SIZE),
        );
        let mut extra = vec![];
        while buf.len() <= MAX_PAYLOAD_SIZE {
            if let Some(data) = body.data().await {
                // Not yet MAX_PAYLOAD_SIZE and more data available.
                let data = data?;
                let needed = std::cmp::min(data.len(), MAX_PAYLOAD_SIZE - buf.len());
                buf.extend_from_slice(&data[..needed]);
                extra.extend_from_slice(&data[needed..]);
            } else if !extra.is_empty() {
                // No more data, but the final chunk pushed us over MAX_PAYLOAD_SIZE.
                break;
            } else {
                // No more data and we're within MAX_PAYLOAD_SIZE.
                return Ok(Payload::InMemory(Response::from_parts(parts, buf)));
            }
        }
        // We're over MAX_PAYLOAD_SIZE. Additional data may be available in
        // body, depending on how the while loop exited.
        Ok(Payload::Streamed(Response::from_parts(
            parts,
            Body::wrap_stream(
                stream::once(async move { Ok(Bytes::copy_from_slice(&buf)) })
                    .chain(stream::once(
                        async move { Ok(Bytes::copy_from_slice(&extra)) },
                    ))
                    .chain(body),
            ),
        )))
    }
}

struct HttpsFetcher<'a>(&'a HttpsClient);

#[async_trait]
impl Fetcher for HttpsFetcher<'_> {
    async fn fetch(&self, request: HttpRequest) -> Result<HttpResponse> {
        let request: Request<Vec<u8>> = request.try_into()?;
        let request: Request<Body> = request.map(|b| b.into());

        let response: Response<Body> = self.0.request(request).await?;
        match resp_to_vec_body(response).await? {
            Payload::InMemory(payload) => payload.try_into(),
            _ => Err(anyhow!("Response too large")),
        }
    }
}

struct SelfFetcher {
    client_ip: IpAddr,
}

// Fetches without `Accept: application/signed-exchange;v=b3`, because the
// HeaderIntegrityFetcher expects unsigned responses.
#[async_trait]
impl Fetcher for SelfFetcher {
    async fn fetch(&self, request: HttpRequest) -> Result<HttpResponse> {
        let (response, _) = handle(self.client_ip, request).await;
        match resp_to_vec_body(response).await? {
            Payload::InMemory(payload) => payload.try_into(),
            _ => Err(anyhow!("Response too large")),
        }
    }
}

struct LruHttpCache(Mutex<LruCache<String, HttpResponse>>);

#[async_trait]
impl HttpCache for &LruHttpCache {
    async fn get(&self, url: &str) -> Result<HttpResponse> {
        match self.0.lock().await.get(url) {
            Some(resp) => Ok(resp.clone()),
            None => Err(anyhow!("No cache entry found for {}", url)),
        }
    }
    async fn put(&self, url: &str, response: &HttpResponse) -> Result<()> {
        match self.0.lock().await.put(url.into(), response.clone()) {
            Some(_) => Ok(()),
            None => Err(anyhow!("Error storing cache entry for {}", url)),
        }
    }
}

async fn generate_sxg_response(
    client_ip: IpAddr,
    fallback_url: &str,
    payload: Arc<HttpResponse>,
) -> Result<Response<Body>> {
    let payload = WORKER.process_html(payload, ProcessHtmlOption { is_sxg: true });

    let cert_origin = Url::parse(fallback_url)?.origin().ascii_serialization();
    let subresource_fetcher = SelfFetcher { client_ip };
    let runtime = sxg_rs::runtime::Runtime {
        now: std::time::SystemTime::now(),
        fetcher: Box::new(subresource_fetcher),
        sxg_signer: Box::new(WORKER.create_rust_signer()?),
        ..Default::default()
    };
    let sxg = WORKER
        .create_signed_exchange(
            &runtime,
            sxg_rs::CreateSignedExchangeParams {
                payload_body: &payload.body,
                payload_headers: WORKER.transform_payload_headers(payload.headers.clone())?,
                skip_process_link: false,
                status_code: 200,
                fallback_url,
                cert_origin: &cert_origin,
                header_integrity_cache: &*HEADER_INTEGRITY,
            },
        )
        .await?;
    let sxg: Response<Vec<u8>> = sxg.try_into()?;
    Ok(sxg.map(Body::from))
}

/// Persistent storage mechanism for OCSP responses & ACME certs. Takes a path
/// to a directory where it will create files for them.
pub struct FileStorage(PathBuf);

// TODO: Consider switching to a lightweight database so that we don't have to
// deal with low-level filesystem quirks. e.g. https://crates.io/crates/sled is
// lock-free, which could make this more portable.
#[async_trait]
impl Storage for FileStorage {
    async fn read(&self, k: &str) -> Result<Option<String>> {
        let path = self.0.join(k);
        // This is vulnerable to a TOCTOU bug, where the file is created by
        // some current process in between this check and the establishment of
        // the lock below. We can't do better, because lock_shared requires the
        // file be open in the first place. However, this seems OK. OCSP/ACME
        // storage don't require perfect synchronization.
        if path.exists() {
            let mut f = File::open(path)?;
            // Don't do any early returns (e.g. `?`) between lock and unlock.
            f.lock_shared()?;
            let mut v = String::new();
            let ok = f.read_to_string(&mut v);
            let _ = f.unlock();
            match ok {
                Ok(_) => Ok(Some(v)),
                Err(e) => Err(anyhow!("error reading file {k}: {e}")),
            }
        } else {
            Ok(None)
        }
    }
    async fn write(&self, k: &str, v: &str) -> Result<()> {
        let path = self.0.join(k);
        let mut f = File::create(path)?;
        // Don't do any early returns (e.g. `?`) between lock and unlock.
        f.lock_exclusive()?;
        let ret = write!(f, "{}", v);
        let _ = f.unlock();
        ret.map_err(|e| anyhow!("error writing file {k}: {e}"))
    }
}

async fn serve_preset_content(url: &str) -> Option<PresetContent> {
    let ocsp_fetcher = HttpsFetcher(&HTTPS_CLIENT);
    // Using a Storage impl that persists across restarts (and between
    // replicas, if using a networked filesystem), per
    // https://gist.github.com/sleevi/5efe9ef98961ecfb4da8 rule #1.
    let runtime = sxg_rs::runtime::Runtime {
        now: std::time::SystemTime::now(),
        fetcher: Box::new(ocsp_fetcher),
        storage: Box::new(FileStorage(ARGS.directory.clone())),
        sxg_signer: Box::new(WORKER.create_rust_signer().ok()?),
        ..Default::default()
    };
    WORKER.serve_preset_content(&runtime, url).await
}

// TODO: Dedupe with PresetContent.
enum HandleAction {
    Respond(Response<Body>),
    Sign { url: String, payload: HttpResponse },
}

// TODO: Figure out how to enable http2 client support.  It's disabled
// currently, because when testing on https://www.google.com with http2
// enabled, I got a 400. My guess why:
// https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-http2bis-07#section-8.3.1
// requires that a request's :authority pseudo-header equals its Host header.
// I guess hyper::Client doesn't synthesize :authority from the Host header.
// We can't work around this because http::header::HeaderMap panics with
// InvalidHeaderName when given ":authority" as a key.
async fn handle_impl(client_ip: IpAddr, req: HttpRequest) -> Result<HandleAction> {
    // TODO: Additional work necessary for ACME support?
    let fallback_url: String;
    let sxg_payload;
    let req_url =
        url::Url::parse(&format!("https://{}/", WORKER.config().html_host))?.join(&req.url)?;
    match serve_preset_content(&format!("{}", req_url)).await {
        Some(PresetContent::Direct(response)) => {
            let response: Response<Vec<u8>> = response.try_into()?;
            return Ok(HandleAction::Respond(response.map(Body::from)));
        }
        Some(PresetContent::ToBeSigned { url, payload, .. }) => {
            fallback_url = url;
            let payload: Response<Vec<u8>> = payload.try_into()?;
            sxg_payload = payload.map(Body::from);
            WORKER.transform_request_headers(req.headers, AcceptFilter::AcceptsSxg)?;
        }
        None => {
            // TODO: Reduce the amount of conversion needed between request/response/header types.
            let backend_url = url::Url::parse(&ARGS.backend)?.join(&req.url)?;
            fallback_url = WORKER.get_fallback_url(&backend_url)?.into();
            let req_headers =
                WORKER.transform_request_headers(req.headers, AcceptFilter::PrefersSxg)?;
            let mut request = Request::builder()
                .method(match req.method {
                    Method::Get => "GET",
                    Method::Post => "POST",
                })
                .uri(req.url);
            for (key, value) in req_headers {
                request = request.header(key, value);
            }
            let request = request.body(req.body.into())?;
            sxg_payload = PROXY_CLIENT
                .call(client_ip, &ARGS.backend, request)
                .await
                .map_err(|e| anyhow!("{:?}", e))?;
        }
    }
    let sxg_payload = resp_to_vec_body(sxg_payload).await?;
    Ok(match sxg_payload {
        Payload::InMemory(payload) => HandleAction::Sign {
            url: fallback_url,
            payload: payload.try_into()?,
        },
        Payload::Streamed(payload) => HandleAction::Respond(payload),
    })
}

async fn proxy_unsigned(client_ip: IpAddr, req: HttpRequest) -> Result<Response<Body>> {
    let req: Request<Vec<u8>> = req.try_into()?;
    let req = req.map(Body::from);
    let payload = PROXY_CLIENT
        .call(client_ip, &ARGS.backend, req)
        .await
        .map_err(|e| anyhow!("{:?}", e))?;
    Ok(match resp_to_vec_body(payload).await? {
        Payload::InMemory(payload) => {
            let payload: HttpResponse = payload.try_into()?;
            let payload =
                WORKER.process_html(Arc::new(payload), ProcessHtmlOption { is_sxg: false });
            let payload = Arc::try_unwrap(payload).unwrap_or_else(|p| (*p).clone());
            let payload: Response<Vec<u8>> = payload.try_into()?;
            payload.map(Body::from)
        }
        Payload::Streamed(payload) => payload,
    })
}

fn set_error_header(err: impl core::fmt::Display, mut resp: Response<Body>) -> Response<Body> {
    if let Ok(val) = format!("{err}").try_into() {
        resp.headers_mut().insert("sxg-rs-error", val);
    }
    resp
}

fn error_body(err: impl core::fmt::Display) -> Response<Body> {
    let mut resp = Response::new(Body::from(format!("{err}")));
    *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    resp
}

// Returns the maybe-signed response, plus an optional string containing an
// error message for why it wasn't signed.
async fn handle(client_ip: IpAddr, req: HttpRequest) -> (Response<Body>, Option<String>) {
    match handle_impl(client_ip, req.clone()).await {
        Ok(HandleAction::Respond(resp)) => (resp, None),
        Ok(HandleAction::Sign { url, payload }) => {
            let payload = Arc::new(payload);
            match generate_sxg_response(client_ip, &url, payload.clone()).await {
                Ok(resp) => (resp, None),
                Err(e) => {
                    let payload = Arc::try_unwrap(payload).unwrap_or_else(|p| (*p).clone());
                    // TODO: Run process_html(is_sxg=false).
                    let payload: Result<Response<Vec<u8>>> = payload.try_into();
                    match payload {
                        Ok(payload) => (payload.map(Body::from), Some(format!("{e}"))),
                        Err(e) => (error_body(e), None),
                    }
                }
            }
        }
        Err(e) => match proxy_unsigned(client_ip, req).await {
            Ok(resp) => (resp, Some(format!("{e}"))),
            Err(e) => (error_body(e), None),
        },
    }
}

async fn handle_or_error(
    client_ip: IpAddr,
    req: Request<Body>,
) -> Result<Response<Body>, http::Error> {
    let req: Result<Request<Vec<u8>>> = req_to_vec_body(req).await;
    let req: Result<HttpRequest> = req.and_then(|r| r.try_into());
    let req: HttpRequest = match req {
        Ok(req) => req,
        Err(e) => {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from(format!("{:?}", e)));
        }
    };
    let (resp, e) = handle(client_ip, req).await;
    Ok(match e {
        Some(e) => set_error_header(e, resp),
        None => resp,
    })
}

#[tokio::main]
async fn main() {
    let _ = fs::create_dir(&ARGS.directory);
    let addr: SocketAddr = ARGS.bind_addr.parse().expect("Could not parse ip:port.");

    let make_svc = make_service_fn(|conn: &AddrStream| {
        let remote_addr = conn.remote_addr().ip();
        async move { Ok::<_, http::Error>(service_fn(move |req| handle_or_error(remote_addr, req))) }
    });

    let server = Server::bind(&addr).serve(make_svc);

    println!("Listening on http://{}", addr);

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use hyper::{body::Bytes, Body, Response};

    #[tokio::test]
    async fn resp_to_vec_body_one_chunk() {
        let (sender, body) = Body::channel();
        let handler = tokio::spawn(async {
            let mut sender = sender;
            let _ = sender.send_data(Bytes::from_static(b"hello")).await;
        });

        let resp = Response::new(body);
        assert_matches!(
            resp_to_vec_body(resp).await,
            Ok(Payload::InMemory(r)) if r.body() == b"hello");
        handler.await.unwrap();
    }
    #[tokio::test]
    async fn resp_to_vec_body_two_chunks() {
        let (sender, body) = Body::channel();
        let handler = tokio::spawn(async {
            let mut sender = sender;
            let _ = sender.send_data(Bytes::from_static(b"hello")).await;
            let _ = sender.send_data(Bytes::from_static(b"bye")).await;
        });

        let resp = Response::new(body);
        assert_matches!(
            resp_to_vec_body(resp).await,
            Ok(Payload::InMemory(r)) if r.body() == b"hellobye");
        handler.await.unwrap();
    }
    #[tokio::test]
    async fn resp_to_vec_body_exactly_max() {
        let (sender, body) = Body::channel();
        let handler = tokio::spawn(async {
            let mut sender = sender;
            let _ = sender.send_data(Bytes::from_static(b"hello")).await;
            let _ = sender
                .send_data(Bytes::copy_from_slice(
                    vec![0; MAX_PAYLOAD_SIZE - 5].as_slice(),
                ))
                .await;
        });

        let resp = Response::new(body);
        assert_matches!(
            resp_to_vec_body(resp).await,
            Ok(Payload::InMemory(r)) if r.body().len() == MAX_PAYLOAD_SIZE);
        handler.await.unwrap();
    }
    #[tokio::test]
    async fn resp_to_vec_body_over_max() {
        let (sender, body) = Body::channel();
        let handler = tokio::spawn(async {
            let mut sender = sender;
            let _ = sender.send_data(Bytes::from_static(b"hello")).await;
            let _ = sender
                .send_data(Bytes::copy_from_slice(vec![0; MAX_PAYLOAD_SIZE].as_slice()))
                .await;
        });

        let resp = Response::new(body);
        match resp_to_vec_body(resp).await {
            Ok(Payload::Streamed(mut r)) => {
                assert_eq!(
                    hyper::body::to_bytes(r.body_mut()).await.unwrap().len(),
                    MAX_PAYLOAD_SIZE + 5
                );
            }
            _ => panic!("resp does not match Payload::Streamed"),
        }
        handler.await.unwrap();
    }
}
