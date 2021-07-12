mod config;

use fastly::{Error, Request, Response, http::{StatusCode, Url}, mime::Mime};
use futures::executor::block_on;
use once_cell::sync::Lazy;
use sxg_rs::headers::Headers;

use config::{ASSET, CONFIG};

fn binary_response(status_code: StatusCode, content_type: Mime, body: &[u8]) -> Response {
    let mut response = Response::new();
    response.set_status(status_code);
    response.set_content_type(content_type);
    response.set_body(body);
    response
}

fn text_response(body: &str) -> Response {
    binary_response(StatusCode::OK, fastly::mime::TEXT_PLAIN, body.as_bytes())
}

fn get_fallback_url(req: &Request) -> Url {
    let mut url = req.get_url().clone();
    url.set_host(Some(&CONFIG.html_host)).unwrap();
    url
}

fn get_req_header_fields(req: &Request) -> Result<Headers, String> {
    let mut fields: Vec<(String, String)> = vec![];
    for name in req.get_header_names() {
        for value in req.get_header_all(name) {
            let value = value.to_str().map_err(|_| {
                format!(r#"Header "{}" contains non-ASCII value."#, name)
            })?;
            fields.push((name.as_str().to_string(), value.to_string()))
        }
    }
    Ok(Headers::new(fields))
}

fn get_rsp_header_fields(rsp: &Response) -> Result<Headers, String> {
    let mut fields: Vec<(String, String)> = vec![];
    for name in rsp.get_header_names() {
        for value in rsp.get_header_all(name) {
            let value = value.to_str().map_err(|_| {
                format!(r#"Header "{}" contains non-ASCII value."#, name)
            })?;
            fields.push((name.as_str().to_string(), value.to_string()))
        }
    }
    Ok(Headers::new(fields))
}

fn fetch_from_html_server(url: &Url, req_headers: Vec<(String, String)>) -> Result<Response, String> {
    let mut req = Request::new("GET", url);
    for (name, value) in req_headers {
        req.append_header(name, value);
    }
    req.send("Origin HTML server").map_err(|err| {
        format!(r#"Fetching "{}" leads to error "{}""#, url, err)
    })
}

// TODO: store OCSP in database
fn fetch_ocsp_from_digicert() -> Result<Vec<u8>, String> {
    let req_body = sxg_rs::ocsp::create_ocsp_request(&ASSET.cert_der, &ASSET.issuer_der);
    let mut req = Request::new("POST", "http://ocsp.digicert.com");
    static CONTENT_TYPE: Lazy<Mime> = Lazy::new(|| {
        "application/ocsp-request".parse().unwrap()
    });
    req.set_content_type(CONTENT_TYPE.clone());
    req.set_body_bytes(&req_body);
    let rsp = req.send("OCSP server").map_err(|err| {
        format!(r#"Fetching OCSP leads to error "{}""#, err)
    })?;
    let rsp_body = rsp.into_body_bytes();
    Ok(rsp_body)
}

fn generate_sxg_response(fallback_url: &Url, payload: Response) -> Result<Response, String> {
    let private_key_der = base64::decode(&CONFIG.private_key_base64).unwrap();
    let signer = Box::new(::sxg_rs::signature::rust_signer::RustSigner::new(&private_key_der));
    let cert_url = CONFIG.cert_url();
    let validity_url = CONFIG.validity_url();
    let payload_headers = get_rsp_header_fields(&payload)?;
    payload_headers.validate_as_sxg_payload(CONFIG.reject_stateful_headers)?;
    let payload_body = payload.into_body_bytes();
    let sxg_body = sxg_rs::create_signed_exchange(sxg_rs::CreateSignedExchangeParams {
        cert_url: &cert_url,
        cert_der: &ASSET.cert_der,
        now: std::time::SystemTime::now(),
        payload_body: &payload_body,
        payload_headers: payload_headers,
        signer,
        status_code: 200,
        fallback_url: fallback_url.as_str(),
        validity_url: &validity_url,
    });
    let sxg_body = block_on(sxg_body);
    static CONTENT_TYPE: Lazy<Mime> = Lazy::new(|| {
        "application/signed-exchange;v=b3".parse().unwrap()
    });
    let mut response = binary_response(StatusCode::OK, CONTENT_TYPE.clone(), &sxg_body);
    response.set_header("X-Content-Type-Options", "nosniff");
    Ok(response)
}

fn handle_request(req: Request) -> Result<Response, String> {
    let path = req.get_path();
    if let Some(basename) = path.strip_prefix(&CONFIG.reserved_path) {
        if basename == CONFIG.cert_url_basename {
            static CONTENT_TYPE: Lazy<Mime> = Lazy::new(|| {
                "application/cert-chain+cbor".parse().unwrap()
            });
            let ocsp = fetch_ocsp_from_digicert()?;
            let body = sxg_rs::create_cert_cbor(&ASSET.cert_der, &ASSET.issuer_der, &ocsp);
            Ok(binary_response(StatusCode::OK, CONTENT_TYPE.clone(), &body))
        } else if basename == CONFIG.validity_url_basename {
            static CONTENT_TYPE: Lazy<Mime> = Lazy::new(|| {
                "application/cbor".parse().unwrap()
            });
            let validity = sxg_rs::create_validity();
            Ok(binary_response(StatusCode::OK, CONTENT_TYPE.clone(), &validity))
        } else {
            return Err(format!("Unknown path {}", path))
        }
    } else {
        let fallback_url = get_fallback_url(&req);
        let req_headers = get_req_header_fields(&req)?;
        let sxg_payload = fetch_from_html_server(
            &fallback_url,
            req_headers.forward_to_origin_server(&CONFIG.forward_request_headers)?,
        )?;
        generate_sxg_response(&fallback_url, sxg_payload)
    }
}

#[fastly::main]
fn main(req: Request) -> Result<Response, Error> {
    let response = handle_request(req).unwrap_or_else(|msg| {
        text_response(&format!("A message is gracefully thrown.\n{}", msg))
    });
    Ok(response)
}