use std::panic;
use std::sync::Once;
use wasm_bindgen::JsValue;

pub static mut LAST_ERROR_MESSAGE: Option<String> = None;

fn hook(info: &panic::PanicInfo) {
    console_error_panic_hook::hook(info);
    let message = format!("{}", info);
    unsafe {
        LAST_ERROR_MESSAGE = Some(message);
    };
}

pub fn init() {
    static SET_HOOK: Once = Once::new();
    SET_HOOK.call_once(|| {
        panic::set_hook(Box::new(hook));
    });
}

pub fn get_last_error_message() -> JsValue {
    let message = unsafe {
        &LAST_ERROR_MESSAGE
    };
    if let Some(message) = message {
        JsValue::from_str(message)
    } else {
        JsValue::UNDEFINED
    }
}

