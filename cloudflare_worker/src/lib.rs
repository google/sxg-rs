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

mod config;
mod utils;

use js_sys::{Function, Uint8Array};
use serde::Serialize;
use wasm_bindgen::prelude::*;

use config::{ASSET, CONFIG};

#[derive(Serialize)]
struct HttpResponse {
    body: Vec<u8>,
    headers: Vec<(&'static str, &'static str)>,
    status: u16,
}

#[wasm_bindgen(js_name=init)]
pub fn init() {
    utils::init();
}

#[wasm_bindgen(js_name=getLastErrorMessage)]
pub fn get_last_error_message() -> JsValue {
    utils::get_last_error_message()
}

#[wasm_bindgen(js_name=createOcspRequest)]
pub fn create_ocsp_request() -> Uint8Array {
    let request = ::sxg_rs::ocsp::create_ocsp_request(&ASSET.cert_der, &ASSET.issuer_der);
    Uint8Array::from(request.as_slice())
}

#[wasm_bindgen(js_name=servePresetContent)]
pub fn serve_preset_content(url: &str, ocsp_base64: &str) -> JsValue {
    let response = if url == CONFIG.cert_url {
        let ocsp_der = ::base64::decode(ocsp_base64).unwrap();
        HttpResponse {
            body: ::sxg_rs::create_cert_cbor(&ASSET.cert_der, &ASSET.issuer_der, &ocsp_der),
            headers: vec![
                ("content-type", "application/cert-chain+cbor"),
            ],
            status: 200,
        }

    } else if url == CONFIG.validity_url {
        HttpResponse {
            body: ::sxg_rs::create_validity(),
            headers: vec![
                ("content-type", "application/cbor"),
            ],
            status: 200,
        }
    } else {
        return JsValue::UNDEFINED;
    };
    JsValue::from_serde(&response).unwrap()
}

#[wasm_bindgen(js_name=shouldRespondDebugInfo)]
pub fn should_respond_debug_info() -> bool {
    CONFIG.respond_debug_info
}

#[wasm_bindgen(js_name=createRequestHeaders)]
pub fn create_request_headers(requestor_headers: JsValue) -> Result<JsValue, JsValue> {
    let requestor_headers = ::sxg_rs::headers::Headers::new(requestor_headers.into_serde().unwrap());
    let result = requestor_headers.forward_to_origin_server(&CONFIG.forward_request_headers);
    match result {
        Ok(fields) => {
            Ok(JsValue::from_serde(&fields).unwrap())
        },
        Err(err) => {
            Err(JsValue::from_str(&err))
        },
    }
}

#[wasm_bindgen(js_name=validatePayloadHeaders)]
pub fn validate_payload_headers(headers: JsValue) -> Result<(), JsValue> {
    let headers = ::sxg_rs::headers::Headers::new(headers.into_serde().unwrap());
    let result = headers.validate_as_sxg_payload(CONFIG.reject_stateful_headers);
    result.map_err(|err| JsValue::from_str(&err))
}

#[wasm_bindgen(js_name=createSignedExchange)]
pub async fn create_signed_exchange(
    fallback_url: String,
    status_code: u16,
    payload_headers: JsValue,
    payload_body: Vec<u8>,
    now_in_seconds: u32,
    signer: Function,
) -> Result<JsValue, JsValue> {
    let payload_headers = ::sxg_rs::headers::Headers::new(payload_headers.into_serde().unwrap());
    let signer = Box::new(::sxg_rs::signature::js_signer::JsSigner::new(signer));
    let sxg_body = ::sxg_rs::create_signed_exchange(::sxg_rs::CreateSignedExchangeParams {
        cert_url: &CONFIG.cert_url,
        cert_der: &ASSET.cert_der,
        fallback_url: &fallback_url,
        now: std::time::UNIX_EPOCH + std::time::Duration::from_secs(now_in_seconds as u64),
        payload_body: &payload_body,
        payload_headers,
        signer,
        status_code,
        validity_url: &CONFIG.validity_url,
    }).await;
    let sxg = HttpResponse {
        body: sxg_body,
        headers: vec![
          ("content-type", "application/signed-exchange;v=b3"),
          ("x-content-type-options", "nosniff"),
        ],
        status: 200,
    };
    Ok(JsValue::from_serde(&sxg).unwrap())
}
