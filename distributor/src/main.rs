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

mod parse_signature;
mod parse_sxg;
mod validate_cert;
mod validate_sxg;

use crate::validate_sxg::Preload;
use anyhow::{anyhow, ensure, Result};
use byte_strings::const_concat_bytes;
use clap::Parser;
use futures::StreamExt;
use http::{
    header::{AsHeaderName, HeaderMap},
    Uri,
};
use hyper::{
    server::{accept, conn::AddrIncoming, Server},
    service::{make_service_fn, service_fn},
    Body, Request, Response, StatusCode,
};
use hyper_trust_dns::{RustlsHttpsConnector, TrustDnsResolver};
use regex::{Captures, Regex};
use rustls::{server::ServerConfig, Certificate, PrivateKey};
use rustls_pemfile::Item as PemItem;
use std::borrow::Cow;
use std::fs::File;
use std::future::ready;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use sxg_rs::{
    headers::{parse_accept_level, AcceptLevel::AcceptsSxg},
    http_parser::{link::Link, parse_content_type_header},
    sxg,
};
use tls_listener::TlsListener;
use tokio_rustls::TlsAcceptor;

/// Server that forward-proxies SXGs from the origin, in support of
/// privacy-preserving prefetch
/// (https://datatracker.ietf.org/doc/html/draft-yasskin-wpack-use-cases-02#section-2.1.4).
/// Similar to Google's webpkgcache.com. Does not cache SXGs, but downstream
/// intermediaries may do so.
#[derive(Parser)]
struct Args {
    /// The bind address (ip:port), such as 0.0.0.0:8080.
    #[clap(short = 'a', long, default_value = "127.0.0.1:8080")]
    bind_addr: String,

    /// Path to the cert PEM; if specified, serves HTTPS instead of HTTP.
    #[clap(short = 'e', long)]
    cert: Option<PathBuf>,

    /// Path to the private key PEM corresponding to the --cert.
    #[clap(short, long)]
    key: Option<PathBuf>,

    /// Web origin (https://foo.example) of the distributor; will be used in cert-url and outer Link headers.
    // TODO: Infer ARGS.origin from request and/or make it gate the multidomain feature.
    #[clap(short, long)]
    origin: String,

    /// User-Agent to send to origins. Should be identifying, to allow them to block or throttle.
    #[clap(short, long)]
    user_agent: String,
}

lazy_static::lazy_static! {
    static ref ARGS: Args = Args::parse();

    static ref CLIENT: hyper::Client<RustlsHttpsConnector> =
        hyper::Client::builder().build(TrustDnsResolver::default().into_rustls_webpki_https_connector());
}

#[derive(PartialEq, Debug)]
enum ResourceType {
    Doc,
    Cert,
    Sub,
}

impl std::str::FromStr for ResourceType {
    type Err = anyhow::Error;
    fn from_str(rtype: &str) -> Result<Self> {
        match rtype {
            "doc" => Ok(ResourceType::Doc),
            "crt" => Ok(ResourceType::Cert),
            "sub" => Ok(ResourceType::Sub),
            _ => Err(anyhow!("Error parsing prefix: {rtype}")),
        }
    }
}

#[derive(PartialEq, Debug)]
struct ParsedRequest<'a> {
    cache_origin: String,
    resource_type: ResourceType,
    integrity: Option<&'a str>,
    origin_url: Uri,
}

fn parse_request(req: &Request<Body>) -> Result<ParsedRequest> {
    let cache_origin = format!(
        "https://{}",
        req.headers()
            .get("host")
            .ok_or_else(|| anyhow!("request missing host"))?
            .to_str()?,
    );
    let path = req
        .uri()
        .path_and_query()
        .ok_or_else(|| anyhow!("Error parsing uri: {}", req.uri()))?;
    let components: Vec<&str> = path.as_str().splitn(4, '/').collect();
    if let [empty, resource_type, integrity, url] = components[..] {
        if !empty.is_empty() {
            return Err(anyhow!("Error parsing path: {path}"));
        }
        let resource_type = resource_type.parse()?;
        let integrity = if integrity == "-" {
            None
        } else {
            Some(integrity)
        };
        let (prefix, url) = match url.strip_prefix("s/") {
            Some(url) => ("https://", url),
            None => ("http://", url),
        };
        Ok(ParsedRequest {
            cache_origin,
            resource_type,
            integrity,
            origin_url: (prefix.to_string() + url).parse()?,
        })
    } else {
        Err(anyhow!("Error parsing path: {path}"))
    }
}

fn get_header(headers: &HeaderMap, name: impl AsHeaderName) -> Vec<&[u8]> {
    headers
        .get_all(name)
        .into_iter()
        .map(|v| v.as_bytes())
        .collect()
}

// True if the header has only one value and pred(value) is true.
fn header_is(headers: &HeaderMap, name: impl AsHeaderName, pred: impl Fn(&[u8]) -> bool) -> bool {
    matches!(get_header(headers, name)[..], [value] if pred(value))
}

fn accepts_sxg(headers: &HeaderMap) -> bool {
    header_is(headers, "accept", |value| {
        matches!(std::str::from_utf8(value),
                 Ok(value_str) if value_str == "application/cert-chain+cbor"
                     || parse_accept_level(value_str) >= AcceptsSxg)
    })
}

fn is_nosniff(headers: &HeaderMap) -> bool {
    header_is(headers, "x-content-type-options", |value| {
        value == b"nosniff"
    })
}

fn is_sxg(headers: &HeaderMap) -> bool {
    header_is(headers, "content-type", |value| {
        if let Ok(value_str) = std::str::from_utf8(value) {
            if let Ok(t) = parse_content_type_header(value_str) {
                return t.primary_type.eq_ignore_ascii_case("application")
                    && t.sub_type.eq_ignore_ascii_case("signed-exchange")
                    && t.parameters
                        .iter()
                        .any(|p| p.name.eq_ignore_ascii_case("v") && p.value == "b3");
            }
        }
        false
    })
}

fn is_cert_chain(headers: &HeaderMap) -> bool {
    header_is(headers, "content-type", |value| {
        if let Ok(value_str) = std::str::from_utf8(value) {
            if let Ok(t) = parse_content_type_header(value_str) {
                return t.primary_type.eq_ignore_ascii_case("application")
                    && t.sub_type.eq_ignore_ascii_case("cert-chain+cbor");
            }
        }
        false
    })
}

fn html_escape(msg: &str) -> Cow<'_, str> {
    lazy_static::lazy_static! {
        static ref HTML_ESCAPE_CHARS: Regex = Regex::new(r#"[&<>"']"#).unwrap();
    }
    HTML_ESCAPE_CHARS.replace_all(msg, |captures: &regex::Captures| {
        match &captures[0] {
            "&" => "&amp;",
            "<" => "&lt;",
            ">" => "&gt;",
            "\"" => "&quot;",
            "'" => "&#39;",
            c => c, // Should not happen.
        }
        .to_owned()
    })
}

// An Accept header where SXG's q-score is 1, to signal preference for it. This
// one is the Chromium document Accept header with ";q=0.9" removed from the
// end.
const ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3";

// TODO: Export success/failure counters if configured (e.g. to Prometheus).

fn alternates(preloads: Vec<Preload>) -> Result<Vec<String>> {
    let mut alternates: Vec<String> = vec![];
    lazy_static::lazy_static! {
        static ref BASE64_STD_CHARS: Regex = Regex::new("[+/]").unwrap();
    }
    for Preload { url, integrity } in preloads {
        let integrity = integrity
            .strip_prefix("sha256-")
            .and_then(|i| i.get(..12))
            .map(|i| {
                BASE64_STD_CHARS.replace_all(i, |caps: &Captures| match caps.get(0) {
                    Some(m) if m.as_str() == "+" => "-",
                    Some(m) if m.as_str() == "/" => "_",
                    _ => "",
                })
            })
            .ok_or_else(|| anyhow!("invalid header-integrity"))?;
        let suffix = url
            .strip_prefix("https://")
            .ok_or_else(|| anyhow!("invalid preload url"))?;
        alternates.push(
            Link {
                uri: format!("{}/sub/{integrity}/s/{suffix}", &ARGS.origin),
                params: vec![
                    ("rel".into(), Some("alternate".into())),
                    (
                        "type".into(),
                        Some("application/signed-exchange;v=b3".into()),
                    ),
                    ("anchor".into(), Some(url)),
                ],
            }
            .serialize(),
        );
    }
    Ok(alternates)
}

// Fetches the SXG, validates it, and rewrites its unsigned URI refs (cert-urls
// and allowed-alt-sxg links) for privacy-preserving prefetch.
async fn handle(parsed: &ParsedRequest<'_>) -> Result<Response<Body>> {
    // TODO: Signature for off-origin subresources if multidomain enabled.
    // Supply a bare request with no customizations derived from the incoming
    // request, so that it remains anonymous.
    let backend_request = hyper::Request::builder()
        .uri(&parsed.origin_url)
        .header("accept", ACCEPT)
        .header("user-agent", &ARGS.user_agent)
        .body(Body::empty())?;
    // TODO: Add a timeout.
    match (&parsed.resource_type, CLIENT.request(backend_request).await) {
        (ResourceType::Cert, Ok(resp)) => {
            let (parts, body) = resp.into_parts();
            ensure!(parts.status == StatusCode::OK && is_cert_chain(&parts.headers));
            let body = validate_cert::validate(&parsed.integrity, body).await?;
            // TODO: Override cache-control headers (short max-age).
            Ok(Response::from_parts(parts, body))
        }
        (_, Ok(resp)) => {
            let (parts, body) = resp.into_parts();
            // TODO: Validate any other outer headers?
            ensure!(parts.status == StatusCode::OK);
            ensure!(is_nosniff(&parts.headers));
            ensure!(is_sxg(&parts.headers));
            let parse_sxg::Parts {
                fallback_url,
                signature,
                signed_headers,
                payload_body,
            } = parse_sxg::parse(body).await?;
            // TODO: Separate "Unwrap" step that can save bool to storage, if specified.
            let (rewritten_signature, preloads) = validate_sxg::validate(
                &ARGS.origin,
                &parsed.origin_url,
                &parsed.integrity,
                &SystemTime::now(),
                &fallback_url,
                &signature,
                &signed_headers,
            )?;
            let rewritten_prologue =
                sxg::build(&fallback_url, &rewritten_signature, &signed_headers, &[])?;
            // TODO: Construct outer Link header.
            // TODO: Set outer cache-control headers (short max-age, middling s-maxage).
            // TODO: Validate MICE proofs as we stream the response? 8MB limit?
            // We couldn't cancel sending the SXG midstream; the browser would
            // display a truncated response. We could buffer the entire
            // response before validating, but that seems like a significant
            // performance pessimization. Instead, we'll just log to stderr.
            // This shouldn't occur frequently because most publishers are
            // using sxg-rs, which guarantees these properties. If it does
            // occur frequently, we could add some mechanism to cache the
            // validation failure and refuse to serve the SXG next time the
            // same URL is requested. (Or the same domain, if the problem
            // occurs on a significant fraction of requests for that domain.)
            // I wonder if we can use Trailer for this?
            // TODO: Debug truncated body.
            let mut resp = Response::builder()
                .status(200)
                .header("content-type", "application/signed-exchange;v=b3")
                .header("x-content-type-options", "nosniff")
                // Needed for subresource substitution:
                .header("access-control-allow-origin", "*");
            let link: Vec<String> = alternates(preloads)?;
            if !link.is_empty() {
                resp = resp.header("link", link.join(","));
            }
            resp.body(Body::wrap_stream(
                Body::from(rewritten_prologue).chain(payload_body),
            ))
            .map_err(|e| anyhow!(e))
        }
        (_, Err(e)) => Err(anyhow!(e)),
    }
}

// Well-formed signature for invalid SXG redirect.
#[allow(clippy::transmute_ptr_to_ref)]
const INVALID_SIGNATURE: &[u8] = const_concat_bytes!(
    b"sig;",
    b"cert-sha256=*AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=*;",
    b"cert-url=\"data:application/cert-chain+cbor,\";",
    b"date=1551139227;",
    b"expires=1551744027;",
    b"integrity=\"digest/mi-sha256-03\";",
    b"sig=*",
    b"MEQCIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAiAAAAAAAAAAAAAAAAAAAAAAAA",
    b"AAAAAAAAAAAAAAAAAAAA==*;",
    b"validity-url=\"data:application/cbor,\"",
);

// Well-formed signed headers for invalid SXG redirect.
#[allow(clippy::transmute_ptr_to_ref)]
const INVALID_SIGNED_HEADERS: &[u8] = const_concat_bytes!(
    b"\xa4",
    b"FdigestX9mi-sha256-03=hp8d+5maRS9Jekz39E2y1u5mH3Sp5+BSUbwUIOUGctQ=",
    b"G:statusC200",
    b"Lcontent-typeItext/html",
    b"Pcontent-encodingLmi-sha256-03",
);

// An invalid SXG that redirects to the given fallback_url. Like <meta>
// redirect, it is only followed on navigation, and not during prefetch
// processing. Unlike <meta> redirect, it doesn't result in a flash of blank
// page or distributor URL, or added latency from browser HTML processing.
fn invalid_sxg(url: &str) -> Result<Vec<u8>> {
    sxg::build(url, INVALID_SIGNATURE, INVALID_SIGNED_HEADERS, &[])
}

// Use <meta> redirect for browsers that don't accept SXG. Unlike 30x,
// it is not followed during processing of <link rel=prefetch>, so
// origins will not receive the request until the user navigates.
fn meta_redirect(url: &str, err: Option<String>) -> Result<Response<Body>, http::Error> {
    let mut resp = Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header("location", url);
    if let Some(err) = err {
        resp = resp.header("invalid-sxg-error", err);
    }
    resp.body(Body::from(format!(
        r#"<!DOCTYPE html><meta charset=utf-8><meta http-equiv=refresh content="0; url={}">"#,
        html_escape(url)
    )))
}

// Wraps handle() with the appropriate error-handling mechanism, depending on
// whether we have successfully parsed the origin URI and whether the client
// supports SXG.
async fn handle_or_error(req: Request<Body>) -> Result<Response<Body>, http::Error> {
    // TODO: Set outer cache-control headers on error responses (short max-age).
    match parse_request(&req) {
        Ok(parsed) => {
            let origin_url = format!("{}", &parsed.origin_url);
            if accepts_sxg(req.headers()) {
                // TODO: Redirect to backend subdomain if multidomain enabled.
                handle(&parsed).await.or_else(|e| {
                    // TODO: Use a logging library.
                    eprintln!("{e:?}");
                    if let Ok(sxg) = invalid_sxg(&origin_url) {
                        Response::builder()
                            .status(StatusCode::NOT_FOUND)
                            .header("content-type", "application/signed-exchange;v=b3")
                            .header("x-content-type-options", "nosniff")
                            .header(
                                "invalid-sxg-error",
                                format!("{e}").escape_default().to_string(),
                            )
                            .body(Body::from(sxg))
                    } else {
                        meta_redirect(&origin_url, Some(format!("{e}")))
                    }
                })
            } else {
                meta_redirect(&origin_url, None)
            }
        }
        Err(e) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from(format!("{:?}", e))),
    }
}

fn tls_listener(
    bind_addr: &SocketAddr,
    cert: &Path,
    key: &Path,
) -> Result<TlsListener<AddrIncoming, TlsAcceptor>> {
    let cert_chain: Vec<Certificate> =
        rustls_pemfile::certs(&mut BufReader::new(File::open(cert)?))?
            .iter()
            .map(|der| Certificate(der.clone()))
            .collect();
    let keys: Vec<PrivateKey> = rustls_pemfile::read_all(&mut BufReader::new(File::open(key)?))?
        .iter()
        .filter_map(|item| match item {
            PemItem::RSAKey(der) => Some(PrivateKey(der.clone())),
            PemItem::PKCS8Key(der) => Some(PrivateKey(der.clone())),
            PemItem::ECKey(der) => Some(PrivateKey(der.clone())),
            _ => None,
        })
        .collect();
    if let [key, ..] = &keys[..] {
        // TODO: Eliminate key.clone().
        let tls_acceptor: TlsAcceptor = Arc::new(
            ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth()
                .with_single_cert(cert_chain, key.clone())?,
        )
        .into();
        Ok(TlsListener::new(
            tls_acceptor,
            AddrIncoming::bind(bind_addr)?,
        ))
    } else {
        Err(anyhow!("Unable to parse private key file"))
    }
}

#[tokio::main]
async fn main() {
    let addr: SocketAddr = ARGS.bind_addr.parse().expect("Could not parse ip:port.");

    if let (Some(cert), Some(key)) = (&ARGS.cert, &ARGS.key) {
        let make_svc =
            make_service_fn(
                |_conn| async move { Ok::<_, http::Error>(service_fn(handle_or_error)) },
            );

        // Filter out TLS errors or the server may stop accepting connections, per
        // https://docs.rs/tls-listener/latest/tls_listener/struct.TlsListener.html.
        let listener = tls_listener(&addr, cert, key)
            .expect("TLS setup")
            .filter(|conn| ready(matches!(conn, Ok(_))));
        let server = Server::builder(accept::from_stream(listener)).serve(make_svc);

        println!("Listening on https://{}", addr);

        if let Err(e) = server.await {
            println!("server error: {}", e);
        }
    } else {
        // TODO: Deduplicate with TLS code, using some type-level chicanery.
        let make_svc =
            make_service_fn(
                |_conn| async move { Ok::<_, http::Error>(service_fn(handle_or_error)) },
            );

        let server = Server::bind(&addr).serve(make_svc);

        println!("Listening on http://{}", addr);

        if let Err(e) = server.await {
            println!("server error: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_path() {
        let req = Request::builder()
            .uri("/doc/-/s/foo.com/bar")
            .header("host", "cache.example")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            parse_request(&req).unwrap(),
            ParsedRequest {
                cache_origin: "https://cache.example".into(),
                resource_type: ResourceType::Doc,
                integrity: None,
                origin_url: "https://foo.com/bar".parse().unwrap(),
            }
        );
        let req = Request::builder()
            .uri("https://cache.example/")
            .body(Body::empty())
            .unwrap();
        assert!(matches!(parse_request(&req), Err(_)));
    }
}
