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

use once_cell::sync::Lazy;
use std::panic;
use std::sync::{Mutex, Once};
use wasm_bindgen::JsValue;

pub static LAST_ERROR_MESSAGE: Lazy<Mutex<String>> = Lazy::new(|| Mutex::new("".to_string()));

fn hook(info: &panic::PanicInfo) {
    console_error_panic_hook::hook(info);
    if let Ok(mut last_error_message) = LAST_ERROR_MESSAGE.try_lock() {
        *last_error_message = format!("{}", info);
    }
}

pub fn init() {
    static SET_HOOK: Once = Once::new();
    SET_HOOK.call_once(|| {
        panic::set_hook(Box::new(hook));
    });
}

pub fn get_last_error_message() -> JsValue {
    if let Ok(last_error_message) = LAST_ERROR_MESSAGE.try_lock() {
        JsValue::from_str(&last_error_message)
    } else {
        JsValue::from_str(
            "Last error message is not available, because it is locked by another thread.",
        )
    }
}

pub fn anyhow_error_to_js_value(error: anyhow::Error) -> JsValue {
    JsValue::from_str(&format!("{:?}", error))
}
