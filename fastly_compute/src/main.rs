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

use fastly::{Error, Request, Response, http::{StatusCode, Url}, mime::Mime};
use futures::executor::block_on;
use once_cell::sync::Lazy;
use sxg_rs::headers::Headers;

pub static WORKER: Lazy<::sxg_rs::SxgWorker> = Lazy::new(|| {
    ::sxg_rs::SxgWorker::new(
        include_str!("../config.yaml"),
        include_str!("../../credentials/cert.pem"),
        include_str!("../../credentials/issuer.pem"),
    )
});

fn transform_response(input: sxg_rs::HttpResponse) -> Response {
    let mut output = Response::new();
    output.set_status(input.status);
    for (name, value) in input.headers {
        output.append_header(name, value)
    }
    output.set_body(input.body);
    output
}

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
    url.set_host(Some(&WORKER.config.html_host)).unwrap();
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
    let req_body = WORKER.create_ocsp_request();
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
    let private_key_der = base64::decode(&WORKER.config.private_key_base64).unwrap();
    let signer = Box::new(::sxg_rs::signature::rust_signer::RustSigner::new(&private_key_der));
    let payload_headers = get_rsp_header_fields(&payload)?;
    payload_headers.validate_as_sxg_payload(WORKER.config.reject_stateful_headers)?;
    let payload_body = payload.into_body_bytes();
    let sxg = WORKER.create_signed_exchange(sxg_rs::CreateSignedExchangeParams {
        now: std::time::SystemTime::now(),
        payload_body: &payload_body,
        payload_headers: payload_headers,
        signer,
        status_code: 200,
        fallback_url: fallback_url.as_str(),
    });
    let sxg = block_on(sxg);
    Ok(transform_response(sxg))
}

fn handle_request(req: Request) -> Result<Response, String> {
    let path = req.get_path();
    let ocsp_der = fetch_ocsp_from_digicert()?;
    if let Some(preset_content) = WORKER.serve_preset_content(path, &ocsp_der) {
        Ok(transform_response(preset_content))
    } else {
        let fallback_url = get_fallback_url(&req);
        let req_headers = get_req_header_fields(&req)?;
        let sxg_payload = fetch_from_html_server(
            &fallback_url,
            req_headers.forward_to_origin_server(&WORKER.config.forward_request_headers)?,
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        &*WORKER;
        let private_key_der = base64::decode(&WORKER.config.private_key_base64).unwrap();
        assert_eq!(private_key_der.len(), 32);
    }
}
