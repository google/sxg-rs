use std::panic;
use std::sync::{Mutex, Once};
use once_cell::sync::Lazy;
use wasm_bindgen::JsValue;

pub static LAST_ERROR_MESSAGE: Lazy<Mutex<String>> = Lazy::new(|| {
    Mutex::new("".to_string())
});

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
        JsValue::from_str("Last error message is not available, because it is locked by another thread.")
    }
}

