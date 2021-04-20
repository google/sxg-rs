extern crate cfg_if;
extern crate wasm_bindgen;

mod utils;

use cfg_if::cfg_if;
use wasm_bindgen::prelude::*;

cfg_if! {
    // When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
    // allocator.
    if #[cfg(feature = "wee_alloc")] {
        extern crate wee_alloc;
        #[global_allocator]
        static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;
    }
}

const CERTIFICATE: &str = include_str!("../certs/cert.pem");
const ISSUER: &str = include_str!("../certs/issuer.pem");
const OCSP: &[u8] = include_bytes!("../certs/ocsp.der");
const PRIVATE_KEY: &str = include_str!("../certs/priv.txt");

#[wasm_bindgen(js_name=createCertCbor)]
pub fn create_cert_cbor() -> Vec<u8> {
    ::sxg_rs::create_cert_cbor(CERTIFICATE, ISSUER, OCSP)
}

#[wasm_bindgen(js_name=createSignedExchange)]
pub fn create_signed_exchange(
    cert_url: &str,
    validity_url: &str,
    fallback_url: &str,
    status_code: u16,
    payload_headers: JsValue,
    payload_body: &str,
    now_in_seconds: u32,
) -> Vec<u8> {
    let payload_headers: Vec<(String, String)> = payload_headers.into_serde().unwrap();
    ::sxg_rs::create_signed_exchange(::sxg_rs::CreateSignedExchangeParams {
        cert_url,
        cert_pem: CERTIFICATE,
        fallback_url,
        now: std::time::UNIX_EPOCH + std::time::Duration::from_secs(now_in_seconds as u64),
        payload_body,
        payload_headers,
        private_key_base64: PRIVATE_KEY.trim(),
        status_code,
        validity_url,
    })
}
