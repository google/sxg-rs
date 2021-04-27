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

extern crate console_error_panic_hook;

mod config;

use serde::Serialize;
use wasm_bindgen::prelude::*;

use config::CONFIG;

#[derive(Serialize)]
struct HttpResponse {
    body: Vec<u8>,
    headers: Vec<(&'static str, &'static str)>,
    status: u16,
}

#[wasm_bindgen(js_name=init)]
pub fn init() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen(js_name=servePresetContent)]
pub fn serve_preset_content(url: &str) -> JsValue {
    let response = if url == CONFIG.cert_url {
        HttpResponse {
            body: ::sxg_rs::create_cert_cbor(&CONFIG.cert_der, &CONFIG.issuer_der, &CONFIG.ocsp_der),
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

#[wasm_bindgen(js_name=validateRequestAcceptHeader)]
pub fn request_accepts_sxg(accept_header: &str) -> Result<(), JsValue> {
    let result = ::sxg_rs::media_type::validate_sxg_request_header(accept_header);
    result.map_err(|err| JsValue::from_str(&err))
}

#[wasm_bindgen(js_name=validatePayloadHeaders)]
pub fn validate_payload_headers(headers: JsValue) -> Result<(), JsValue> {
    let headers = ::sxg_rs::headers::Headers::new(headers.into_serde().unwrap());
    let result = headers.validate(CONFIG.reject_stateful_headers);
    result.map_err(|err| JsValue::from_str(&err))
}

#[wasm_bindgen(js_name=createSignedExchange)]
pub fn create_signed_exchange(
    fallback_url: &str,
    status_code: u16,
    payload_headers: JsValue,
    payload_body: &[u8],
    now_in_seconds: u32,
    encryption_password: &str,
) -> Vec<u8> {
    let payload_headers = ::sxg_rs::headers::Headers::new(payload_headers.into_serde().unwrap());
    let privkey = CONFIG.encrypted_privkey.decrypt(encryption_password).unwrap();
    // TODO: Add explanation why openssl puts private key is the [7:39] bytes.
    let privkey_der = &privkey.private_key_info().private_key[7..(7 + 32)];
    ::sxg_rs::create_signed_exchange(::sxg_rs::CreateSignedExchangeParams {
        cert_url: &CONFIG.cert_url,
        cert_der: &CONFIG.cert_der,
        fallback_url,
        now: std::time::UNIX_EPOCH + std::time::Duration::from_secs(now_in_seconds as u64),
        payload_body,
        payload_headers,
        privkey_der,
        status_code,
        validity_url: &CONFIG.validity_url,
    })
}
