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

mod utils;

use js_sys::{Function, Uint8Array};
use once_cell::sync::Lazy;
use wasm_bindgen::prelude::*;

pub static WORKER: Lazy<::sxg_rs::SxgWorker> = Lazy::new(|| {
    ::sxg_rs::SxgWorker::new(
        include_str!("../config.yaml"),
        include_str!("../../credentials/cert.pem"),
        include_str!("../../credentials/issuer.pem"),
    )
});

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
    let request = WORKER.create_ocsp_request();
    Uint8Array::from(request)
}

#[wasm_bindgen(js_name=servePresetContent)]
pub fn serve_preset_content(req_url: &str, ocsp_base64: &str) -> JsValue {
    let ocsp_der = ::base64::decode(ocsp_base64).unwrap();
    if let Some(preset_content) = WORKER.serve_preset_content(req_url, &ocsp_der) {
        JsValue::from_serde(&preset_content).unwrap()
    } else {
        JsValue::UNDEFINED
    }
}

#[wasm_bindgen(js_name=shouldRespondDebugInfo)]
pub fn should_respond_debug_info() -> bool {
    WORKER.config.respond_debug_info
}

#[wasm_bindgen(js_name=createRequestHeaders)]
pub fn create_request_headers(requestor_headers: JsValue) -> Result<JsValue, JsValue> {
    let fields = requestor_headers.into_serde().unwrap();
    let result = WORKER.transform_request_headers(fields);
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
pub fn validate_payload_headers(fields: JsValue) -> Result<(), JsValue> {
    let fields = fields.into_serde().unwrap();
    let result = WORKER.validate_payload_headers(fields);
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
    let sxg = WORKER.create_signed_exchange(::sxg_rs::CreateSignedExchangeParams {
        fallback_url: &fallback_url,
        now: std::time::UNIX_EPOCH + std::time::Duration::from_secs(now_in_seconds as u64),
        payload_body: &payload_body,
        payload_headers,
        signer,
        status_code,
    }).await;
    Ok(JsValue::from_serde(&sxg).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        &*WORKER;
        assert_eq!(WORKER.config.private_key_base64, "");
    }
}
