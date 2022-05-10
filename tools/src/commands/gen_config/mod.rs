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

use anyhow::{anyhow, Error, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use wrangler::settings::global_user::GlobalUser;
use wrangler::settings::toml::ConfigKvNamespace;

#[derive(Debug, Parser)]
#[clap(allow_hyphen_values = true)]
pub struct Opts {
    #[clap(long)]
    cloudflare_account_id: Option<String>,
    #[clap(long)]
    cloudflare_zone_id: Option<String>,
    #[clap(long)]
    /// Your domain registered in Cloudflare
    html_host: String,
    #[clap(long, default_value_t=String::from("credentials/cert.pem"))]
    cert_file: String,
    #[clap(long, default_value_t=String::from("credentials/issuer.pem"))]
    issuer_file: String,
    #[clap(long)]
    /// Deploy the worker only on 'workers.dev'.
    /// Google SXG cache requires this parameter to be false (to be not set).
    deploy_on_workers_dev_only: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
struct WranglerVars {
    html_host: String,
    sxg_config: String,
    #[serde(default)]
    cert_pem: String,
    #[serde(default)]
    issuer_pem: String,
}

// TODO: Use `wrangler::settings::toml::Manifest`
// after [this issue](https://github.com/cloudflare/wrangler/issues/2037)
// is resolved.
#[derive(Deserialize, Serialize)]
struct WranglerConfig {
    name: String,
    #[serde(rename = "type")]
    target_type: String,
    account_id: String,
    zone_id: String,
    routes: Vec<String>,
    workers_dev: Option<bool>,
    kv_namespaces: Vec<ConfigKvNamespace>,
    vars: WranglerVars,
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

// Get the ID of the KV namespace for OCSP.
// If there is no such KV namespace, one will be created.
fn get_ocsp_kv_id(user: &GlobalUser, account_id: &str) -> String {
    let client = wrangler::http::cf_v4_client(user).unwrap();
    let target: wrangler::settings::toml::Target = Default::default();
    let namespaces = wrangler::kv::namespace::list(&client, &target).unwrap();
    if let Some(namespace) = namespaces.into_iter().find(|n| n.title == "sxg-OCSP") {
        return namespace.id;
    }
    let namespace = wrangler::kv::namespace::create(&client, account_id, "OCSP")
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

// Read and parse both `cert.pem` and `issuer.pem`.
// Panics on error.
fn read_certificates(cert_path: &str, issuer_path: &str) -> (String, String) {
    let cert = read_certificate_pem_file(cert_path);
    let issuer = read_certificate_pem_file(issuer_path);
    if let (Ok(cert), Ok(issuer)) = (&cert, &issuer) {
        println!("Successfully read certificates");
        return (cert.to_string(), issuer.to_string());
    }
    if let Err(msg) = cert {
        println!("{}", msg);
    }
    if let Err(msg) = issuer {
        println!("{}", msg);
    }
    println!(
        r#"Failed to load SXG certificates.
What you need to do:
  1. Generate SXG certificates according to the link
     https://github.com/google/sxg-rs/blob/main/credentials/README.md
  2. Copy the "cert.pem" and "issuer.pem" to the "credentials" folder.
  3. Re-run "cargo run -p tools -- gen-config"."#
    );
    std::process::exit(1);
}

const CONFIG_FILE: &str = "cloudflare_worker/wrangler.toml";
// TODO: Remove the example toml, and use Rust code to set the default value of WranglerConfig.
const CONFIG_EXAMPLE_FILE: &str = "cloudflare_worker/wrangler.example.toml";

// Read and parse `wrangler.toml`.
// `wrangler.example.toml` will be read if `wrangler.toml` does not exist.
// This function panics if `wrangler.toml` contains syntax error,
// even when a valid `wrangler.example.toml` exists.
fn read_existing_config() -> (WranglerConfig, bool) {
    let (wrangler_config, exists) = std::fs::read_to_string(CONFIG_FILE)
        .map(|s| (s, true))
        .or_else(|_| std::fs::read_to_string(CONFIG_EXAMPLE_FILE).map(|s| (s, false)))
        .unwrap();
    let wrangler_config: WranglerConfig = toml::from_str(&wrangler_config).unwrap();
    (wrangler_config, exists)
}

pub fn main(opts: Opts) -> Result<()> {
    goto_repository_root()?;
    let (cert_pem, issuer_pem) = read_certificates(&opts.cert_file, &opts.issuer_file);
    let (mut wrangler_config, exists) = read_existing_config();
    wrangler_config.vars.cert_pem = cert_pem;
    wrangler_config.vars.issuer_pem = issuer_pem;
    // TODO: Tell the user that they can create an sh script to store all CLI args.
    if !exists {
        let user = get_global_user();
        wrangler_config.account_id = opts
            .cloudflare_account_id
            .ok_or_else(|| anyhow!("Please specify you Cloudflare account ID"))?;
        wrangler_config.zone_id = opts
            .cloudflare_zone_id
            .ok_or_else(|| anyhow!("Please specify you Cloudflare zone ID"))?;
        let html_host = &opts.html_host;
        if opts.deploy_on_workers_dev_only {
            wrangler_config.routes = vec![];
            wrangler_config.workers_dev = Some(true);
            wrangler_config.vars.html_host = html_host.clone();
        } else {
            wrangler_config.routes = vec![
                format!("{}/*", html_host),
                format!("{}/.well-known/sxg-certs/*", html_host),
                format!("{}/.well-known/sxg-validity/*", html_host),
            ];
        }
        let ocsp_kv_id = get_ocsp_kv_id(&user, &wrangler_config.account_id);
        wrangler_config.kv_namespaces = vec![ConfigKvNamespace {
            binding: String::from("OCSP"),
            id: Some(ocsp_kv_id),
            preview_id: None,
        }];
    }
    std::fs::write(
        CONFIG_FILE,
        format!(
            "# This file is generated by command \"cargo run -p tools -- gen-config\".\n\
            # Feel free to customize your config by directly modifying this file.\n\
            # Please note that comments you add won't be preserved at the next time you run \"cargo run -p tools -- -gen-config\".\n\
            {}",
            toml::to_string_pretty(&wrangler_config).unwrap()
        ),
    )?;
    println!("Successfully wrote config to {}", CONFIG_FILE);
    Ok(())
}
