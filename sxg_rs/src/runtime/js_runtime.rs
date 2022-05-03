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

use super::Runtime;
use crate::fetcher::{js_fetcher::JsFetcher, Fetcher};
use crate::signature::{js_signer::JsSigner, Signer};
use anyhow::{Error, Result};
use js_sys::Function as JsFunction;
use std::time::{Duration, SystemTime};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    pub type JsRuntimeInitParams;
    #[wasm_bindgen(method, getter, js_name = "nowInSeconds")]
    fn now_in_seconds(this: &JsRuntimeInitParams) -> u32;
    #[wasm_bindgen(method, getter, js_name = "fetcher")]
    fn fetcher(this: &JsRuntimeInitParams) -> Option<JsFunction>;
    #[wasm_bindgen(method, getter, js_name = "sxgAsn1Signer")]
    fn sxg_asn1_signer(this: &JsRuntimeInitParams) -> Option<JsFunction>;
    #[wasm_bindgen(method, getter, js_name = "sxgRawSigner")]
    fn sxg_raw_signer(this: &JsRuntimeInitParams) -> Option<JsFunction>;

}

impl std::convert::TryFrom<JsRuntimeInitParams> for Runtime {
    type Error = Error;
    fn try_from(input: JsRuntimeInitParams) -> Result<Self, Self::Error> {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(input.now_in_seconds() as u64);
        let fetcher = input
            .fetcher()
            .map(|f| Box::new(JsFetcher::new(f)) as Box<dyn Fetcher>);
        let sxg_asn1_signer = input
            .sxg_asn1_signer()
            .map(|f| Box::new(JsSigner::from_asn1_signer(f)) as Box<dyn Signer>);
        let sxg_raw_signer = input
            .sxg_raw_signer()
            .map(|f| Box::new(JsSigner::from_raw_signer(f)) as Box<dyn Signer>);
        let sxg_signer = sxg_asn1_signer.or(sxg_raw_signer);
        Ok(Runtime {
            now,
            fetcher,
            sxg_signer,
        })
    }
}
