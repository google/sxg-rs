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

use crate::linux_commands::generate_private_key_pem;
use crate::runtime::openssl_signer::OpensslSigner;
use crate::tokio_block_on;
use anyhow::{Error, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use sxg_rs::acme::{directory::Directory as AcmeDirectory, Account as AcmeAccount};
use sxg_rs::crypto::EcPrivateKey;
use wrangler::settings::global_user::GlobalUser;
use wrangler::settings::toml::ConfigKvNamespace;

#[derive(Debug, Parser)]
pub struct Opts {
    /// A YAML file containing all config values.
    /// You can use the template
    /// 'tools/src/commands/gen_config/input.example.yaml'.
    #[clap(long, value_name = "FILE_NAME")]
    input: String,
    /// A YAML file containing the generated values.
    #[clap(long, value_name = "FILE_NAME")]
    artifact: String,
    /// No longer log in to worker service providers.
    #[clap(long)]
    use_ci_mode: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    domain_name: String,
    sxg_worker: sxg_rs::config::Config,
    certificates: SxgCertConfig,
    cloudflare: CloudlareSpecificInput,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum SxgCertConfig {
    PreIssued {
        cert_file: String,
        issuer_file: String,
    },
    CreateAcmeAccount(AcmeConfig),
}

#[derive(Debug, Deserialize, Serialize)]
struct AcmeConfig {
    server_url: String,
    contact_email: String,
    agreed_terms_of_service: String,
    sxg_cert_request_file: String,
    eab: Option<EabConfig>,
}

#[derive(Debug, Deserialize, Serialize)]
struct EabConfig {
    base64_mac_key: String,
    key_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CloudlareSpecificInput {
    account_id: String,
    zone_id: String,
    routes: Vec<String>,
    worker_name: String,
    deploy_on_workers_dev_only: bool,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Artifact {
    acme_account: Option<AcmeAccount>,
    acme_private_key_instruction: Option<String>,
    cloudflare_kv_namespace_id: Option<String>,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
struct WranglerVars {
    html_host: String,
    sxg_config: String,
    cert_pem: Option<String>,
    issuer_pem: Option<String>,
    acme_account: Option<String>,
}

// TODO: Use `wrangler::settings::toml::Triggers`
// after [this PR](https://github.com/cloudflare/wrangler/pull/2259)
// is deployed to the latest `wrangler` version.
#[derive(Deserialize, Serialize)]
pub struct Triggers {
    pub crons: Vec<String>,
}

// TODO: Use `wrangler::settings::toml::Manifest`
// after [this issue](https://github.com/cloudflare/wrangler/issues/2037)
// is resolved.
#[derive(Deserialize, Serialize)]
struct WranglerManifest {
    name: String,
    #[serde(rename = "type")]
    target_type: String,
    account_id: String,
    zone_id: String,
    routes: Vec<String>,
    workers_dev: Option<bool>,
    kv_namespaces: Vec<ConfigKvNamespace>,
    vars: WranglerVars,
    triggers: Option<Triggers>,
}

// Set working directory to the root folder of the "sxg-rs" repository.
fn goto_repository_root() -> Result<(), std::io::Error> {
    let exe_path = std::env::current_exe()?;
    assert!(exe_path.ends_with("target/debug/tools"));
    let repo_root = exe_path
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    std::env::set_current_dir(repo_root)?;
    Ok(())
}

// Get the Cloudflare user.
// If there is no active user, the terminal will display a login link.
// This function will wait for the login process before returning.
fn get_global_user() -> GlobalUser {
    println!("Checking Cloudflare login state");
    let mut user = GlobalUser::new();
    if user.is_err() {
        wrangler::login::run(None).unwrap();
        user = GlobalUser::new();
    }
    let user = user.unwrap();
    println!("Successfully login to Cloudflare");
    user
}

const STORAGE_NAME: &str = "OCSP";
// Get the ID of the KV namespace for OCSP.
// If there is no such KV namespace, one will be created.
fn get_ocsp_kv_id(user: &GlobalUser, account_id: &str) -> String {
    let client = wrangler::http::cf_v4_client(user).unwrap();
    let target: wrangler::settings::toml::Target = Default::default();
    let namespaces = wrangler::kv::namespace::list(&client, &target).unwrap();
    if let Some(namespace) = namespaces.into_iter().find(|n| n.title == STORAGE_NAME) {
        return namespace.id;
    }
    let namespace = wrangler::kv::namespace::create(&client, account_id, STORAGE_NAME)
        .unwrap()
        .result;
    namespace.id
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

fn create_wrangler_secret_instruction(name: &str, value: &str) -> String {
    let base64_value = base64::encode(value);
    format!(
        "echo {} | openssl enc -base64 -d | wrangler secret put {}",
        base64_value, name
    )
}

const WRANGLER_TOML: &str = "cloudflare_worker/wrangler.toml";

fn read_artifact(file_name: &str) -> Result<Artifact> {
    let file_content = std::fs::read_to_string(file_name)?;
    let artifact = serde_yaml::from_str(&file_content)?;
    Ok(artifact)
}

pub fn main(opts: Opts) -> Result<()> {
    if std::env::var("CI").is_ok() && !opts.use_ci_mode {
        println!("The environment variable $CI is set, but --use-ci-mode is not set.");
    }
    goto_repository_root()?;
    let mut input: Config = serde_yaml::from_str(&std::fs::read_to_string(&opts.input)?)?;
    let mut artifact: Artifact = read_artifact(&opts.artifact).unwrap_or_else(|_| {
        println!("Creating a new artifact");
        Default::default()
    });
    input.sxg_worker.html_host = input
        .sxg_worker
        .html_host
        .clone() // TODO: Remove this clone while keep Rust compiler happy.
        .or_else(|| Some(input.domain_name.clone()));
    if artifact.cloudflare_kv_namespace_id.is_none() {
        if opts.use_ci_mode {
            println!("Skipping KV namespace creation, because --use-ci-mode is set.")
        } else {
            let user = get_global_user();
            artifact.cloudflare_kv_namespace_id =
                Some(get_ocsp_kv_id(&user, &input.cloudflare.account_id))
        }
    }
    let mut wrangler_vars = WranglerVars {
        html_host: input.domain_name.clone(),
        sxg_config: serde_yaml::to_string(&input.sxg_worker)?,
        ..Default::default()
    };
    match &input.certificates {
        SxgCertConfig::PreIssued {
            cert_file,
            issuer_file,
        } => {
            wrangler_vars.cert_pem = Some(read_certificate_pem_file(cert_file)?);
            wrangler_vars.issuer_pem = Some(read_certificate_pem_file(issuer_file)?);
        }
        SxgCertConfig::CreateAcmeAccount(acme_config) => {
            if artifact.acme_account.is_none() {
                let (acme_private_key, acme_account) =
                    tokio_block_on(create_acme_key_and_account(acme_config, &input.domain_name))?;
                artifact.acme_account = Some(acme_account);
                artifact.acme_private_key_instruction = Some(create_wrangler_secret_instruction(
                    "ACME_PRIVATE_KEY_JWK",
                    &serde_json::to_string(&acme_private_key)?,
                ))
            }
            wrangler_vars.acme_account = Some(serde_json::to_string(&artifact.acme_account)?);
        }
    };
    let mut routes = input.cloudflare.routes.clone();
    routes.extend(vec![
        format!("{}/.well-known/sxg-certs/*", input.domain_name),
        format!("{}/.well-known/sxg-validity/*", input.domain_name),
        format!("{}/.well-known/acme-challenge/*", input.domain_name),
    ]);
    let wrangler_toml_output = WranglerManifest {
        name: input.cloudflare.worker_name.clone(),
        target_type: "rust".to_string(),
        account_id: input.cloudflare.account_id.clone(),
        zone_id: input.cloudflare.zone_id.clone(),
        routes,
        kv_namespaces: vec![ConfigKvNamespace {
            binding: STORAGE_NAME.to_string(),
            id: artifact
                .cloudflare_kv_namespace_id
                .clone()
                .or_else(|| Some("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX".to_string())),
            preview_id: None,
        }],
        workers_dev: Some(input.cloudflare.deploy_on_workers_dev_only),
        vars: wrangler_vars,
        triggers: Some(Triggers {
            crons: vec![
                // The syntax is at https://developers.cloudflare.com/workers/platform/cron-triggers
                // This triggers at every minute.
                "* * * * *".to_string(),
            ],
        }),
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

    std::fs::write(
        WRANGLER_TOML,
        format!(
            "# This file is generated by command \"cargo run -p tools -- gen-config\".\n\
            # Please note that anything you modify won't be preserved\n\
            # at the next time you run \"cargo run -p tools -- -gen-config\".\n\
            {}",
            toml::to_string_pretty(&wrangler_toml_output)?
        ),
    )?;
    println!("Successfully wrote config to {}", WRANGLER_TOML);
    Ok(())
}
