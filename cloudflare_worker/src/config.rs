use std::collections::HashSet;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
struct ConfigInput {
    forward_request_headers: HashSet<String>,
    html_host: String,
    reject_stateful_headers: bool,
    respond_debug_info: bool,
    worker_host: String,
}

pub struct Config {
    pub cert_der: Vec<u8>,
    pub cert_url: String,
    pub forward_request_headers: HashSet<String>,
    pub issuer_der: Vec<u8>,
    pub ocsp_der: Vec<u8>,
    pub reject_stateful_headers: bool,
    pub respond_debug_info: bool,
    pub validity_url: String,
}

pub static CONFIG: Lazy<Config> = Lazy::new(|| {
    let input = include_str!("../config.yaml");
    let ConfigInput {
        forward_request_headers,
        html_host,
        reject_stateful_headers,
        respond_debug_info,
        worker_host,
    } = serde_yaml::from_str(&input).unwrap();
    Config {
        cert_der: get_der(include_str!("../certs/cert.pem"), "CERTIFICATE"),
        cert_url: format!("https://{}/cert", worker_host),
        forward_request_headers,
        issuer_der: get_der(include_str!("../certs/issuer.pem"), "CERTIFICATE"),
        ocsp_der: include_bytes!("../certs/ocsp.der").to_vec(),
        reject_stateful_headers,
        respond_debug_info,
        validity_url: format!("https://{}/.sxg_validity", html_host),
    }
});

fn get_der(pem_text: &str, expected_tag: &str) -> Vec<u8> {
    for pem in ::pem::parse_many(pem_text) {
        if pem.tag == expected_tag {
            return pem.contents;
        }
    }
    panic!("The PEM file does not contains the expected block");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        &*CONFIG;
    }
}
