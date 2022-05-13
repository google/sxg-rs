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

use crate::headers::AcceptFilter;
use crate::http::HttpResponse;
use crate::process_html::ProcessHtmlOption;
use crate::runtime::{js_runtime::JsRuntimeInitParams, Runtime};
use crate::utils::to_js_error;
use crate::SxgWorker;
use anyhow::Result;
use js_sys::Function as JsFunction;
use js_sys::Promise as JsPromise;
use std::convert::TryFrom;
use std::sync::Arc;
use wasm_bindgen::prelude::{wasm_bindgen, JsValue};
use wasm_bindgen_futures::future_to_promise;

#[wasm_bindgen]
pub struct WasmWorker(Arc<SxgWorker>);

#[wasm_bindgen]
extern "C" {
    pub type CreateSignedExchangedOptions;
    #[wasm_bindgen(method, getter, js_name = "fallbackUrl")]
    fn fallback_url(this: &CreateSignedExchangedOptions) -> String;
    #[wasm_bindgen(method, getter, js_name = "certOrigin")]
    fn cert_origin(this: &CreateSignedExchangedOptions) -> String;
    #[wasm_bindgen(method, getter, js_name = "statusCode")]
    fn status_code(this: &CreateSignedExchangedOptions) -> u16;
    #[wasm_bindgen(method, getter, js_name = "payloadHeaders")]
    fn payload_headers(this: &CreateSignedExchangedOptions) -> JsValue;
    #[wasm_bindgen(method, getter, js_name = "payloadBody")]
    fn payload_body(this: &CreateSignedExchangedOptions) -> Vec<u8>;
    #[wasm_bindgen(method, getter, js_name = "skipProcessLink")]
    fn skip_process_link(this: &CreateSignedExchangedOptions) -> bool;
    #[wasm_bindgen(method, getter, js_name = "headerIntegrityGet")]
    fn header_integrity_get(this: &CreateSignedExchangedOptions) -> JsFunction;
    #[wasm_bindgen(method, getter, js_name = "headerIntegrityPut")]
    fn header_integrity_put(this: &CreateSignedExchangedOptions) -> JsFunction;
}

#[wasm_bindgen]
impl WasmWorker {
    #[wasm_bindgen(constructor)]
    pub fn new(config_yaml: &str, cert_pem: &str, issuer_pem: &str) -> Result<WasmWorker, JsValue> {
        let sxg_worker = SxgWorker::new(config_yaml, cert_pem, issuer_pem).map_err(to_js_error)?;
        Ok(WasmWorker(Arc::new(sxg_worker)))
    }
    #[wasm_bindgen(js_name=updateOcspInStorage)]
    pub fn update_oscp_in_storage(&self, js_runtime: JsRuntimeInitParams) -> JsPromise {
        let worker = self.0.clone();
        future_to_promise(async move {
            let runtime = Runtime::try_from(js_runtime).map_err(to_js_error)?;
            worker
                .update_oscp_in_storage(&runtime)
                .await
                .map_err(to_js_error)?;
            Ok(JsValue::UNDEFINED)
        })
    }
    #[wasm_bindgen(js_name=servePresetContent)]
    pub fn serve_preset_content(
        &self,
        js_runtime: JsRuntimeInitParams,
        req_url: String,
    ) -> JsPromise {
        let worker = self.0.clone();
        future_to_promise(async move {
            let runtime = Runtime::try_from(js_runtime).map_err(to_js_error)?;
            Ok(worker
                .serve_preset_content(&runtime, &req_url)
                .await
                .map_or(JsValue::UNDEFINED, |preset_content| {
                    JsValue::from_serde(&preset_content).unwrap()
                }))
        })
    }

    #[wasm_bindgen(js_name=createRequestHeaders)]
    pub fn create_request_headers(
        &self,
        accept_filter: JsValue,
        requestor_headers: JsValue,
    ) -> Result<JsValue, JsValue> {
        let fields = requestor_headers.into_serde().unwrap();
        let accept_filter: AcceptFilter = accept_filter.into_serde().unwrap();
        let result = self.0.transform_request_headers(fields, accept_filter);
        match result {
            Ok(fields) => Ok(JsValue::from_serde(&fields).unwrap()),
            Err(err) => Err(to_js_error(err)),
        }
    }
    #[wasm_bindgen(js_name=validatePayloadHeaders)]
    pub fn validate_payload_headers(&self, fields: JsValue) -> Result<(), JsValue> {
        let fields: Vec<(String, String)> = fields.into_serde().map_err(to_js_error)?;
        self.0
            .transform_payload_headers(fields)
            .map_err(to_js_error)?;
        Ok(())
    }
    #[wasm_bindgen(js_name=processHtml)]
    pub fn process_html(&self, input: JsValue, option: JsValue) -> Result<JsValue, JsValue> {
        let input: HttpResponse = input.into_serde().map_err(to_js_error)?;
        let option: ProcessHtmlOption = option.into_serde().map_err(to_js_error)?;
        let output = self.0.process_html(input, option).map_err(to_js_error)?;
        JsValue::from_serde(&output).map_err(to_js_error)
    }
    #[wasm_bindgen(js_name=createSignedExchange)]
    pub fn create_signed_exchange(
        &self,
        js_runtime: JsRuntimeInitParams,
        options: CreateSignedExchangedOptions,
    ) -> JsPromise {
        let worker = self.0.clone();
        future_to_promise(async move {
            let runtime = Runtime::try_from(js_runtime).map_err(to_js_error)?;
            let payload_headers: Vec<(String, String)> = options
                .payload_headers()
                .into_serde()
                .map_err(to_js_error)?;
            let payload_headers = worker
                .transform_payload_headers(payload_headers)
                .map_err(to_js_error)?;
            let header_integrity_cache = crate::http_cache::js_http_cache::JsHttpCache {
                get: options.header_integrity_get(),
                put: options.header_integrity_put(),
            };
            let sxg: HttpResponse = worker
                .create_signed_exchange(
                    &runtime,
                    crate::CreateSignedExchangeParams {
                        fallback_url: &options.fallback_url(),
                        cert_origin: &options.cert_origin(),
                        payload_body: &options.payload_body(),
                        payload_headers,
                        status_code: options.status_code(),
                        header_integrity_cache,
                        skip_process_link: options.skip_process_link(),
                    },
                )
                .await
                .map_err(to_js_error)?;
            Ok(JsValue::from_serde(&sxg).unwrap())
        })
    }
    #[wasm_bindgen(js_name=updateAcmeStateMachine)]
    pub fn update_acme_state_machine(
        &self,
        js_runtime: JsRuntimeInitParams,
        acme_account: String,
    ) -> JsPromise {
        let _ = self;
        future_to_promise(async move {
            let acme_account: crate::acme::Account =
                serde_json::from_str(&acme_account).map_err(to_js_error)?;
            let runtime = Runtime::try_from(js_runtime).map_err(to_js_error)?;
            crate::acme::state_machine::update_state(&runtime, &acme_account)
                .await
                .map_err(to_js_error)?;
            Ok(JsValue::from_str("asdf"))
        })
    }
}
