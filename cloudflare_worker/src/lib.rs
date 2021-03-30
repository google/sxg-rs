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

#[wasm_bindgen(js_name=createCertCbor)]
pub fn create_cert_cbor(certificate: &str) -> Vec<u8> {
    ::sxg_rs::create_cert_cbor(certificate)
}

#[wasm_bindgen(js_name=createSignedExchange)]
pub fn create_signed_exchange(url: &str, html: &str, certificate: &str, private_key: &str, seconds_since_epoch: u32) -> Vec<u8> {
    ::sxg_rs::create_signed_exchange(url, html, certificate, private_key, seconds_since_epoch)
}
