extern crate cfg_if;
extern crate wasm_bindgen;

mod utils;

use cfg_if::cfg_if;
use once_cell::sync::Lazy;
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

fn get_der(pem_text: &str, expected_tag: &str) -> Vec<u8> {
    for pem in ::pem::parse_many(pem_text) {
        if pem.tag == expected_tag {
            return pem.contents;
        }
    }
    panic!("The PEM file does not contains the expected block");
}

static CERT_DER: Lazy<Vec<u8>> = Lazy::new(|| {
    get_der(include_str!("../certs/cert.pem"), "CERTIFICATE")
});
static ISSUER_DER: Lazy<Vec<u8>> = Lazy::new(|| {
    get_der(include_str!("../certs/issuer.pem"), "CERTIFICATE")
});
static PRIVKEY_DER: Lazy<Vec<u8>> = Lazy::new(|| {
    let a = get_der(include_str!("../certs/privkey.pem"), "EC PRIVATE KEY");
    a[7..(7 + 32)].to_vec()
});
const OCSP_DER: &[u8] = include_bytes!("../certs/ocsp.der");

#[wasm_bindgen(js_name=createCertCbor)]
pub fn create_cert_cbor() -> Vec<u8> {
    ::sxg_rs::create_cert_cbor(&CERT_DER, &ISSUER_DER, OCSP_DER)
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
        cert_der: &CERT_DER,
        fallback_url,
        now: std::time::UNIX_EPOCH + std::time::Duration::from_secs(now_in_seconds as u64),
        payload_body,
        payload_headers,
        privkey_der: &PRIVKEY_DER,
        status_code,
        validity_url,
    })
}
