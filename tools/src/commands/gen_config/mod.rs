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

mod cloudflare;
pub mod fastly;
mod http_server;

use crate::linux_commands::generate_private_key_pem;
use crate::runtime::openssl_signer::OpensslSigner;
use crate::tokio_block_on;
use anyhow::{Error, Result};
use clap::{ArgEnum, Parser};
use cloudflare::CloudlareSpecificInput;
use fastly::FastlySpecificInput;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use sxg_rs::acme::{directory::Directory as AcmeDirectory, Account as AcmeAccount};
use sxg_rs::crypto::EcPrivateKey;
use tools::Artifact;

#[derive(ArgEnum, Clone, Debug, Eq, PartialEq)]
enum Platform {
    Cloudflare,
    Fastly,
    HttpServer,
}

#[derive(Debug, Parser)]
pub struct Opts {
    /// A YAML file containing all config values.
    /// You can use the template
    /// 'tools/src/commands/gen_config/input.example.yaml'.
    #[clap(long, value_name = "FILE_NAME", default_value = "input.yaml")]
    input: PathBuf,
    /// A YAML file containing the generated values.
    #[clap(long, value_name = "FILE_NAME", default_value = "artifact.yaml")]
    artifact: PathBuf,
    /// If set `true`, no longer log in to worker service providers.
    #[clap(long)]
    use_ci_mode: bool,
    #[clap(arg_enum, long)]
    platform: Option<Platform>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    sxg_worker: sxg_rs::config::Config,
    certificates: SxgCertConfig,
    cloudflare: Option<CloudlareSpecificInput>,
    fastly: Option<FastlySpecificInput>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SxgCertConfig {
    PreIssued {
        cert_file: String,
        issuer_file: String,
    },
    CreateAcmeAccount(AcmeConfig),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AcmeConfig {
    server_url: String,
    contact_email: String,
    agreed_terms_of_service: String,
    sxg_cert_request_file: String,
    eab: Option<EabConfig>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EabConfig {
    base64_mac_key: String,
    key_id: String,
}

fn read_certificate_pem_file(path: &str) -> Result<String> {
    let text = std::fs::read_to_string(path)
        .map_err(|_| Error::msg(format!(r#"Failed to read file "{}""#, path)))?;
    // Translate Windows-style line endings to Unix-style so the '\r' is
    // not rendered in the toml. This is purely cosmetic; '\r' is deserialized
    // faithfully from toml and pem::parse_many is able to parse either style.
    let text = text.replace("\r\n", "\n");
    let certs = pem::parse_many(&text).map_err(Error::new)?;
    if certs.len() == 1 && certs[0].tag == "CERTIFICATE" {
        Ok(text)
    } else {
        Err(Error::msg(format!(
            r#"File "{}" is not a valid certificate PEM"#,
            path
        )))
    }
}

async fn create_acme_key_and_account(
    acme_config: &AcmeConfig,
    domain_name: &str,
) -> Result<(EcPrivateKey, AcmeAccount)> {
    let acme_private_key = {
        let pem = generate_private_key_pem()?;
        EcPrivateKey::from_sec1_pem(&pem)?
    };
    let runtime = sxg_rs::runtime::Runtime {
        acme_signer: Box::new(acme_private_key.create_signer()?),
        fetcher: Box::new(crate::runtime::hyper_fetcher::HyperFetcher::new()),
        ..Default::default()
    };
    let sxg_cert_request_der = sxg_rs::crypto::get_der_from_pem(
        &std::fs::read_to_string(&acme_config.sxg_cert_request_file)?,
        "CERTIFICATE REQUEST",
    )?;
    let eab = if let Some(input_eab) = &acme_config.eab {
        let eab_mac_key =
            base64::decode_config(&input_eab.base64_mac_key, base64::URL_SAFE_NO_PAD)?;
        let eab_signer = OpensslSigner::Hmac(&eab_mac_key);
        let new_account_url =
            AcmeDirectory::from_url(&acme_config.server_url, runtime.fetcher.as_ref())
                .await?
                .0
                .new_account;
        let output_eab = sxg_rs::acme::eab::create_external_account_binding(
            sxg_rs::acme::jws::Algorithm::HS256,
            &input_eab.key_id,
            &new_account_url,
            &acme_private_key.public_key,
            &eab_signer,
        )
        .await?;
        Some(output_eab)
    } else {
        None
    };
    let account = sxg_rs::acme::create_account(
        sxg_rs::acme::AccountSetupParams {
            directory_url: acme_config.server_url.clone(),
            agreed_terms_of_service: &acme_config.agreed_terms_of_service,
            external_account_binding: eab,
            email: &acme_config.contact_email,
            domain: domain_name.to_string(),
            public_key: acme_private_key.public_key.clone(),
            cert_request_der: sxg_cert_request_der,
        },
        runtime.fetcher.as_ref(),
        runtime.acme_signer.as_ref(),
    )
    .await?;
    Ok((acme_private_key, account))
}

pub fn read_artifact(file_name: impl AsRef<Path>) -> Result<Artifact> {
    let file_content = std::fs::read_to_string(file_name)?;
    let artifact = serde_yaml::from_str(&file_content)?;
    Ok(artifact)
}

pub fn main(opts: Opts) -> Result<()> {
    if std::env::var("CI").is_ok() && !opts.use_ci_mode {
        println!("The environment variable $CI is set, but --use-ci-mode is not set.");
    }
    let input: Config = serde_yaml::from_str(&std::fs::read_to_string(&opts.input)?)?;
    let mut artifact: Artifact = read_artifact(&opts.artifact).unwrap_or_else(|_| {
        println!("Creating a new artifact");
        Default::default()
    });
    if let SxgCertConfig::CreateAcmeAccount(acme_config) = &input.certificates {
        if artifact.acme_account.is_none() {
            let (acme_private_key, acme_account) = tokio_block_on(create_acme_key_and_account(
                acme_config,
                &input.sxg_worker.html_host,
            ))?;
            artifact.acme_account = Some(acme_account);
            artifact.acme_private_key = Some(acme_private_key);
        }
    };

    match opts.platform {
        Some(Platform::Cloudflare) => {
            cloudflare::main(
                opts.use_ci_mode,
                &input.sxg_worker,
                &input.certificates,
                &input
                    .cloudflare
                    .expect(r#"Input file does not contain "cloudflare" section."#),
                &mut artifact,
            )?;
        }
        Some(Platform::HttpServer) => {
            http_server::main(input.sxg_worker)?;
        }
        Some(Platform::Fastly) => {
            fastly::main(
                opts.use_ci_mode,
                &input.sxg_worker,
                &input.certificates,
                &input
                    .fastly
                    .expect(r#"Input file does not contain "fastly" section."#),
                &mut artifact,
            )?;
        }
        None => (),
    };

    std::fs::write(
        &opts.artifact,
        format!(
            "# This file is generated by command \"cargo run -p tools -- gen-config\".\n\
            # Please do not modify.\n\
            {}",
            serde_yaml::to_string(&artifact)?
        ),
    )?;
    Ok(())
}
