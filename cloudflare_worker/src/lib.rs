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
use once_cell::sync::OnceCell;
use sxg_rs::headers::AcceptFilter;
use sxg_rs::http::HttpResponse;
use sxg_rs::SxgWorker;
use utils::anyhow_error_to_js_value;
use wasm_bindgen::prelude::*;

static WORKER: OnceCell<SxgWorker> = OnceCell::new();

fn get_worker() -> Result<&'static SxgWorker, JsValue> {
    WORKER.get().ok_or_else(|| {
        JsValue::from_str("Please call the init function before all other functions.")
    })
}

#[wasm_bindgen(js_name=init)]
pub fn init(config_yaml: &str, cert_pem: &str, issuer_pem: &str) -> Result<(), JsValue> {
    utils::init();
    WORKER
        .set(SxgWorker::new(config_yaml, cert_pem, issuer_pem))
        .map_err(|_| JsValue::from_str("The init functional has already been called"))
}

#[wasm_bindgen(js_name=getLastErrorMessage)]
pub fn get_last_error_message() -> JsValue {
    utils::get_last_error_message()
}

#[wasm_bindgen(js_name=fetchOcspFromCa)]
pub async fn fetch_ocsp_from_ca(fetcher: Function) -> Result<Uint8Array, JsValue> {
    let fetcher = Box::new(sxg_rs::fetcher::js_fetcher::JsFetcher::new(fetcher));
    let request = get_worker()?.fetch_ocsp_from_ca(fetcher).await;
    Ok(Uint8Array::from(request.as_slice()))
}

#[wasm_bindgen(js_name=servePresetContent)]
pub fn serve_preset_content(req_url: &str, ocsp_base64: &str) -> Result<JsValue, JsValue> {
    let ocsp_der = ::base64::decode(ocsp_base64).unwrap();
    Ok(get_worker()?
        .serve_preset_content(req_url, &ocsp_der)
        .map_or(JsValue::UNDEFINED, |preset_content| {
            JsValue::from_serde(&preset_content).unwrap()
        }))
}

#[wasm_bindgen(js_name=shouldRespondDebugInfo)]
pub fn should_respond_debug_info() -> Result<bool, JsValue> {
    Ok(get_worker()?.config.respond_debug_info)
}

#[wasm_bindgen(js_name=createRequestHeaders)]
pub fn create_request_headers(
    accept_filter: JsValue,
    requestor_headers: JsValue,
) -> Result<JsValue, JsValue> {
    let fields = requestor_headers.into_serde().unwrap();
    let accept_filter: AcceptFilter = accept_filter.into_serde().unwrap();
    let result = get_worker()?.transform_request_headers(fields, accept_filter);
    match result {
        Ok(fields) => Ok(JsValue::from_serde(&fields).unwrap()),
        Err(err) => Err(anyhow_error_to_js_value(err)),
    }
}

#[wasm_bindgen(js_name=validatePayloadHeaders)]
pub fn validate_payload_headers(fields: JsValue) -> Result<(), JsValue> {
    let fields = fields.into_serde().unwrap();
    let result = get_worker()?.validate_payload_headers(fields);
    result.map_err(anyhow_error_to_js_value)
}

#[wasm_bindgen(js_name=createSignedExchange)]
pub async fn create_signed_exchange(
    fallback_url: String,
    cert_origin: String,
    status_code: u16,
    payload_headers: JsValue,
    payload_body: Vec<u8>,
    now_in_seconds: u32,
    signer: Function,
) -> Result<JsValue, JsValue> {
    let payload_headers = ::sxg_rs::headers::Headers::new(
        payload_headers.into_serde().unwrap(),
        &get_worker()?.config.strip_response_headers,
    );
    let signer = Box::new(::sxg_rs::signature::js_signer::JsSigner::from_raw_signer(
        signer,
    ));
    let sxg: HttpResponse = get_worker()?
        .create_signed_exchange(::sxg_rs::CreateSignedExchangeParams {
            fallback_url: &fallback_url,
            cert_origin: &cert_origin,
            now: std::time::UNIX_EPOCH + std::time::Duration::from_secs(now_in_seconds as u64),
            payload_body: &payload_body,
            payload_headers,
            signer,
            status_code,
        })
        .await
        .map_err(anyhow_error_to_js_value)?;
    Ok(JsValue::from_serde(&sxg).unwrap())
}
