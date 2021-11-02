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

use anyhow::Result;
use clap::Parser;
use std::fs::write;

use crate::linux_commands::{
    create_certificate, create_certificate_request_pem, create_private_key_pem, get_public_key_pem,
};

#[derive(Parser)]
pub struct Opts {
    #[clap(long)]
    domain: String,
}

pub fn main(opts: Opts) -> Result<()> {
    const PRIVKEY_FILE: &str = "privkey.pem";
    const CERT_CSR_FILE: &str = "cert.csr";
    const EXT_FILE: &str = "ext.txt";
    const CERT_FILE: &str = "cert.pem";
    const ISSUER_FILE: &str = "issuer.pem";
    const CERT_SHA256_FILE: &str = "cert_sha256.txt";
    let private_key_pem = create_private_key_pem()?;
    write(PRIVKEY_FILE, &private_key_pem)?;
    let cert_csr = create_certificate_request_pem(&opts.domain, PRIVKEY_FILE)?;
    write(CERT_CSR_FILE, &cert_csr)?;
    write(
        EXT_FILE,
        format!(
            "1.3.6.1.4.1.11129.2.1.22 = ASN1:NULL\nsubjectAltName=DNS:{}\n",
            &opts.domain,
        ),
    )?;
    let cert_pem = create_certificate(PRIVKEY_FILE, CERT_CSR_FILE, EXT_FILE)?;
    write(CERT_FILE, &cert_pem)?;
    write(ISSUER_FILE, &cert_pem)?;
    let public_key_pem = get_public_key_pem(CERT_FILE)?;
    let public_key_der = sxg_rs::config::get_der(&public_key_pem, "PUBLIC KEY")?;
    let cert_sha256 = sxg_rs::utils::get_sha(&public_key_der);
    write(
        CERT_SHA256_FILE,
        base64::encode_config(&cert_sha256, base64::URL_SAFE_NO_PAD),
    )?;
    Ok(())
}
