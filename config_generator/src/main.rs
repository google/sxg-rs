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

use anyhow::{Error, Result};
use console::Term;
use dialoguer::{Input, Select};
use serde::{Deserialize, Serialize};
use wrangler::settings::global_user::GlobalUser;
use wrangler::settings::toml::ConfigKvNamespace;

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
    assert!(exe_path.ends_with("target/debug/config-generator"));
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
        wrangler::login::run().unwrap();
        user = GlobalUser::new();
    }
    let user = user.unwrap();
    println!("Successfully login to Cloudflare");
    user
}

// Get the ID of the KV namespace for OCSP.
// If there is no such KV namespace, one will be created.
fn get_ocsp_kv_id(user: &GlobalUser, account_id: &str) -> String {
    let client = wrangler::http::cf_v4_client(&user).unwrap();
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
    let text =
        std::fs::read_to_string(path).map_err(|_| Error::msg(format!(r#"Failed to read file "{}""#, path)))?;
    // Translate Windows-style line endings to Unix-style so the '\r' is
    // not rendered in the toml. This is purely cosmetic; '\r' is deserialized
    // faithfully from toml and pem::parse_many is able to parse either style.
    let text = text.replace("\r\n", "\n");
    let certs = pem::parse_many(&text);
    if certs.len() == 1 && certs[0].tag == "CERTIFICATE" {
        Ok(text)
    } else {
        Err(Error::msg(format!(r#"File "{}" is not a valid certificate PEM"#, path)))
    }
}

// Read and parse both `cert.pem` and `issuer.pem`.
// Panics on error.
fn read_certificates() -> (String, String) {
    let cert = read_certificate_pem_file("credentials/cert.pem");
    let issuer = read_certificate_pem_file("credentials/issuer.pem");
    if cert.is_ok() && issuer.is_ok() {
        println!("Successfully read certificates");
        return (cert.unwrap(), issuer.unwrap());
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
  3. Re-run "cargo run -p config-generator"."#
    );
    std::process::exit(1);
}

const CONFIG_FILE: &'static str = "cloudflare_worker/wrangler.toml";
// TODO: Remove the example toml, and use Rust code to set the default value of WranglerConfig.
const CONFIG_EXAMPLE_FILE: &'static str = "cloudflare_worker/wrangler.example.toml";

// Read and parse `wrangler.toml`.
// `wrangler.example.toml` will be read if `wrangler.toml` does not exist.
// This function panics if `wrangler.toml` contains syntax error,
// even when a valid `wrangler.example.toml` exists.
fn read_existing_config() -> (WranglerConfig, bool) {
    let (wrangler_config, exists) = std::fs::read_to_string(CONFIG_FILE).map (|s| (s, true))
        .or_else(|_| std::fs::read_to_string(CONFIG_EXAMPLE_FILE).map(|s| (s, false)))
        .unwrap();
    let wrangler_config: WranglerConfig = toml::from_str(&wrangler_config).unwrap();
    (wrangler_config, exists)
}

// TODO: Trap ^C and show cursor.

fn main() -> Result<(), std::io::Error> {
    goto_repository_root()?;
    let (cert_pem, issuer_pem) = read_certificates();
    let (mut wrangler_config, exists) = read_existing_config();
    wrangler_config.vars.cert_pem = cert_pem;
    wrangler_config.vars.issuer_pem = issuer_pem;
    // TODO: Remove interactive part, and allow user to create a file for these values.
    if !exists {
        // Show cursor again, if user hits Ctrl-C during the Select dialog.
        ctrlc::set_handler(|| Term::stdout().show_cursor().unwrap()).ok();
        let user = get_global_user();
        wrangler_config.account_id = Input::new()
            .with_prompt("What's your Cloudflare account ID?")
            .interact_text()
            .unwrap();
        wrangler_config.zone_id = Input::new()
            .with_prompt("What's your Cloudflare zone ID?")
            .interact_text()
            .unwrap();
        let html_host = Input::new()
            .with_prompt("What's your domain registered in Cloudflare?")
            .validate_with(|s: &String| -> Result<(), url::ParseError> {
                url::Host::parse(s)?;
                Ok(())
            })
            .interact_text()
            .unwrap();
        let target = Select::new()
            .with_prompt("Where do you want to deploy the worker?")
            .items(&vec!["On your domain (recommended; required by Google SXG Cache)",
                         "On workers.dev (development only)"])
            .default(0)
            .interact()
            .unwrap();
        if target == 1 {
            wrangler_config.routes = vec![];
            wrangler_config.workers_dev = Some(true);
            wrangler_config.vars.html_host = html_host;
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
            "# This file is generated by command \"cargo run -p config-generator\".\n\
            # Feel free to customize your config by directly modifying this file.\n\
            # Please note that comments you add won't be preserved at the next time you run \"cargo run -p config-generator\".\n\
            {}",
            toml::to_string_pretty(&wrangler_config).unwrap()
        ),
    )?;
    println!("Successfully wrote config to {}", CONFIG_FILE);
    Ok(())
}
