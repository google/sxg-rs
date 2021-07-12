use std::collections::HashSet;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct Config {
    pub cert_url_basename: String,
    pub forward_request_headers: HashSet<String>,
    pub html_host: String,
    pub private_key_base64: String,
    pub reject_stateful_headers: bool,
    pub reserved_path: String,
    pub respond_debug_info: bool,
    pub validity_url_basename: String,
    pub worker_host: String,
}

impl Config {
    pub fn cert_url(&self) -> String {
        format!("https://{}{}{}", self.worker_host, self.reserved_path, self.cert_url_basename)
    }
    pub fn validity_url(&self) -> String {
        format!("https://{}{}{}", self.html_host, self.reserved_path, self.validity_url_basename)
    }
}

pub static CONFIG: Lazy<Config> = Lazy::new(|| {
    let input = include_str!("../config.yaml");
    serde_yaml::from_str(&input).unwrap()
});

pub struct Asset {
    pub cert_der: Vec<u8>,
    pub issuer_der: Vec<u8>,
}

pub static ASSET: Lazy<Asset> = Lazy::new(|| {
    Asset {
        cert_der: get_der(include_str!("../certs/cert.pem"), "CERTIFICATE"),
        issuer_der: get_der(include_str!("../certs/issuer.pem"), "CERTIFICATE"),
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
        &*ASSET;
        &*CONFIG;
    }
}
