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

// TODO(antiphoton) No longer allow unused_unit when a new version wasm_bindgen is released with
// https://github.com/rustwasm/wasm-bindgen/pull/2778
#![allow(clippy::unused_unit)]

use wasm_bindgen::prelude::wasm_bindgen;

extern crate sxg_rs;

#[wasm_bindgen(js_name=init)]
pub fn init() {
    console_error_panic_hook::set_once()
}
