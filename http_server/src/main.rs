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
use hyper::{
    server::{conn::AddrStream, Server},
    service::{make_service_fn, service_fn},
    Body, Request, Response, StatusCode,
};
use hyper_reverse_proxy::ReverseProxy;
use hyper_trust_dns::{RustlsHttpsConnector, TrustDnsResolver};
use std::boxed::Box;
use std::convert::TryInto;
use std::net::IpAddr;
use std::net::SocketAddr;
use sxg_rs::{
    crypto::CertificateChain,
    fetcher::Fetcher,
    headers::AcceptFilter,
    http::{HttpRequest, HttpResponse, Method},
    process_html::ProcessHtmlOption,
    PresetContent,
};
use url::Url;

// TODO: Add readme, explaining how to create credentials & config.yaml and how to run.

/// HTTP server that acts as a reverse proxy, generating signed exchanges of
/// responses received from the backend. Compare to Web Packager Server.
#[derive(Parser)]
struct Args {
    /// The origin (scheme://host[:port]) of the backend to fetch from, such as
    /// 'https://backend'. To configure the signed domain that appears in the
    /// resultant SXGs, set html_host in http_server/config.yaml.
    #[clap(short, long)]
    backend: String,

    /// The bind address (ip:port), such as 0.0.0.0:8080.
    #[clap(short = 'a', long, default_value = "127.0.0.1:8080")]
    bind_addr: String,
}

type HttpsClient = hyper::Client<
    hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector<TrustDnsResolver>>,
>;

lazy_static::lazy_static! {
    static ref HTTPS_CLIENT: HttpsClient =
        hyper::Client::builder().build::<_, hyper::Body>(TrustDnsResolver::default().into_rustls_webpki_https_connector());

    static ref PROXY_CLIENT: ReverseProxy<RustlsHttpsConnector> =
        ReverseProxy::new(
            hyper::Client::builder().build::<_, hyper::Body>(TrustDnsResolver::default().into_rustls_webpki_https_connector()));

    static ref WORKER: sxg_rs::SxgWorker = {
        // TODO: Make flags for the locations of these files.
        let mut worker = sxg_rs::SxgWorker::new(include_str!("../config.yaml")).unwrap();
        worker.add_certificate(CertificateChain::from_pem_files(&[
              include_str!("../../credentials/cert.pem"),
              include_str!("../../credentials/issuer.pem"),
        ]).unwrap());
        worker
    };
}

async fn req_to_vec_body(request: Request<Body>) -> Result<Request<Vec<u8>>> {
    let (parts, body) = request.into_parts();
    let body = hyper::body::to_bytes(body).await?.to_vec();
    Ok(Request::from_parts(parts, body))
}

async fn resp_to_vec_body(response: Response<Body>) -> Result<Response<Vec<u8>>> {
    let (parts, body) = response.into_parts();
    let body = hyper::body::to_bytes(body).await?.to_vec();
    Ok(Response::from_parts(parts, body))
}

struct HttpsFetcher<'a>(&'a HttpsClient);

#[async_trait]
impl Fetcher for HttpsFetcher<'_> {
    async fn fetch(&self, request: HttpRequest) -> Result<HttpResponse> {
        let request: Request<Vec<u8>> = request.try_into()?;
        let request: Request<Body> = request.map(|b| b.into());

        let response: Response<Body> = self.0.request(request).await?;
        // TODO: Do something streaming.
        resp_to_vec_body(response).await?.try_into()
    }
}

struct SelfFetcher {
    client_ip: IpAddr,
    backend: String,
}

// Fetches without `Accept: application/signed-exchange;v=b3`, because the
// HeaderIntegrityFetcher expects unsigned responses.
#[async_trait]
impl Fetcher for SelfFetcher {
    async fn fetch(&self, request: HttpRequest) -> Result<HttpResponse> {
        let response: Response<Body> = handle(self.client_ip, request, &self.backend).await?;
        // TODO: Do something streaming.
        resp_to_vec_body(response).await?.try_into()
    }
}

async fn generate_sxg_response(
    client_ip: IpAddr,
    backend: &str,
    fallback_url: &str,
    payload: HttpResponse,
) -> Result<Response<Body>> {
    // TODO: Also transform with is_sxg=false on fallback.
    let payload = WORKER.process_html(payload, ProcessHtmlOption { is_sxg: true });

    let cert_origin = Url::parse(fallback_url)?.origin().ascii_serialization();
    // TODO: Instead of SelfFetcher, make the HeaderIntegrityFetcher a param of
    // create_signed_exchange, then make an impl that fetches SXGs (from any
    // domain) and computes their header-integrity.
    let subresource_fetcher = SelfFetcher {
        client_ip,
        backend: backend.into(),
    };
    let runtime = sxg_rs::runtime::Runtime {
        now: std::time::SystemTime::now(),
        sxg_signer: Box::new(WORKER.create_rust_signer()?),
        fetcher: Box::new(subresource_fetcher),
        ..Default::default()
    };
    let sxg = WORKER
        .create_signed_exchange(
            &runtime,
            sxg_rs::CreateSignedExchangeParams {
                payload_body: &payload.body,
                payload_headers: WORKER.transform_payload_headers(payload.headers)?,
                skip_process_link: false,
                status_code: 200,
                fallback_url,
                cert_origin: &cert_origin,
                // TODO: Specify a non-null header_integrity_cache.
                header_integrity_cache: sxg_rs::http_cache::NullCache {},
            },
        )
        .await?;
    let sxg: Response<Vec<u8>> = sxg.try_into()?;
    Ok(sxg.map(Body::from))
}

async fn serve_preset_content(url: &str) -> Option<PresetContent> {
    let ocsp_fetcher = HttpsFetcher(&HTTPS_CLIENT);
    // TODO: Create a Storage impl that persists across restarts (and maybe
    // also between replicas), per
    // https://gist.github.com/sleevi/5efe9ef98961ecfb4da8 rule #1. Filesystem
    // support should be sufficient.
    let runtime = sxg_rs::runtime::Runtime {
        now: std::time::SystemTime::now(),
        sxg_signer: Box::new(WORKER.create_rust_signer().ok()?),
        fetcher: Box::new(ocsp_fetcher),
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
async fn handle_impl(client_ip: IpAddr, req: HttpRequest, backend: &str) -> Result<HandleAction> {
    // TODO: Proxy unsigned if SXG fails.
    // TODO: If over 8MB or MICE fails midstream, send the consumed portion and stream the rest.
    // TODO: Wrap errors with additional context before returning.
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
            let backend_url = url::Url::parse(backend)?.join(&req.url)?;
            fallback_url = WORKER.get_fallback_url(&backend_url)?.into();
            let req_headers =
                WORKER.transform_request_headers(req.headers.clone(), AcceptFilter::PrefersSxg)?;
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
                .call(client_ip, backend, request)
                .await
                .map_err(|e| anyhow!("{:?}", e))?;
        }
    }
    // TODO: Change body to a Cow so cloning is cheap?
    let sxg_payload: HttpResponse = resp_to_vec_body(sxg_payload).await?.try_into()?;
    Ok(HandleAction::Sign {
        url: fallback_url,
        payload: sxg_payload,
    })
}

async fn proxy_unsigned(
    client_ip: IpAddr,
    req: HttpRequest,
    backend: &str,
) -> Result<Response<Body>> {
    let req: Request<Vec<u8>> = req.try_into()?;
    let req = req.map(Body::from);
    let payload = PROXY_CLIENT
        .call(client_ip, &backend, req)
        .await
        .map_err(|e| anyhow!("{:?}", e))?;
    let payload: HttpResponse = resp_to_vec_body(payload).await?.try_into()?;
    let payload = WORKER.process_html(payload, ProcessHtmlOption { is_sxg: false });
    let payload: Response<Vec<u8>> = payload.try_into()?;
    Ok(payload.map(Body::from))
}

async fn handle(
    client_ip: IpAddr,
    req: HttpRequest,
    backend: &str,
) -> Result<Response<Body>, http::Error> {
    match handle_impl(client_ip, req.clone(), &backend).await {
        Ok(HandleAction::Respond(resp)) => Ok(resp),
        Ok(HandleAction::Sign { url, payload }) => {
            generate_sxg_response(client_ip, &backend, &url, payload.clone())
                .await
                .or_else(|_| {
                    // TODO: Annotate response with error as header.
                    let sxg: Result<Response<Vec<u8>>> = payload.try_into();
                    match sxg {
                        Ok(sxg) => Ok(sxg.map(Body::from)),
                        Err(e) => Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Body::from(format!("{:?}", e))),
                    }
                })
        }
        Err(_) => {
            // TODO: Annotate response with error as header.
            proxy_unsigned(client_ip, req, &backend).await.or_else(|e| {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from(format!("{:?}", e)))
            })
        }
    }
}

async fn handle_or_error(
    client_ip: IpAddr,
    req: Request<Body>,
    backend: String,
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
    handle(client_ip, req.clone(), &backend).await
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let addr: SocketAddr = args.bind_addr.parse().expect("Could not parse ip:port.");

    let make_svc = make_service_fn(|conn: &AddrStream| {
        let remote_addr = conn.remote_addr().ip();
        let backend = args.backend.clone();
        async move {
            Ok::<_, http::Error>(service_fn(move |req| {
                handle_or_error(remote_addr, req, backend.to_owned())
            }))
        }
    });

    let server = Server::bind(&addr).serve(make_svc);

    println!("Listening on http://{}", addr);

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}
