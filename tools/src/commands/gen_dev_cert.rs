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
    create_certificate, create_certificate_request_pem, get_certificate_sha256,
    read_or_create_private_key_pem, write_new_file,
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
    read_or_create_private_key_pem(PRIVKEY_FILE)?;
    create_certificate_request_pem(&opts.domain, PRIVKEY_FILE, CERT_CSR_FILE)?;
    write(
        EXT_FILE,
        format!(
            "1.3.6.1.4.1.11129.2.1.22 = ASN1:NULL\nsubjectAltName=DNS:{}\n",
            &opts.domain,
        ),
    )?;
    let cert_pem = create_certificate(PRIVKEY_FILE, CERT_CSR_FILE, EXT_FILE, CERT_FILE)?;
    write_new_file(ISSUER_FILE, &cert_pem)?;
    write_new_file(
        CERT_SHA256_FILE,
        base64::encode_config(&get_certificate_sha256(CERT_FILE)?, base64::URL_SAFE_NO_PAD),
    )?;
    Ok(())
}
