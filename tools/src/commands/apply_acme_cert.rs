// Copyright 2022 Google LLC
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

use super::gen_config::read_artifact;
use crate::runtime::hyper_fetcher::HyperFetcher;
use anyhow::Result;
use clap::Parser;
use sxg_rs::acme::state_machine::{
    get_challenge_token_and_answer, update_state as update_acme_state_machine,
};
use warp::Filter;

#[derive(Debug, Parser)]
#[clap(allow_hyphen_values = true)]
pub struct Opts {
    #[clap(long)]
    port: Option<u16>,
    #[clap(long)]
    artifact: String,
    /// Puts challenge answer and certificate to Fastly edge dictionary.
    #[clap(long)]
    use_fastly_dictionary: bool,
}

fn start_warp_server(port: u16, answer: impl ToString) -> tokio::sync::oneshot::Sender<()> {
    let answer = answer.to_string();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let routes =
        warp::path!(".well-known" / "acme-challenge" / String).map(move |_name| answer.to_string());
    let (_addr, server) =
        warp::serve(routes).bind_with_graceful_shutdown(([127, 0, 0, 1], port), async {
            rx.await.ok();
        });
    tokio::spawn(server);
    tx
}

pub async fn main(opts: Opts) -> Result<()> {
    let artifact = read_artifact(&opts.artifact)?;
    let acme_account = artifact.acme_account.unwrap();
    let acme_private_key = artifact.acme_private_key.unwrap();
    let mut runtime = sxg_rs::runtime::Runtime {
        acme_signer: Box::new(acme_private_key.create_signer()?),
        fetcher: Box::new(HyperFetcher::new()),
        ..Default::default()
    };
    let (challenge_token, challenge_answer) = loop {
        runtime.now = std::time::SystemTime::now();
        update_acme_state_machine(&runtime, &acme_account).await?;
        if let Some((token, answer)) = get_challenge_token_and_answer(&runtime).await? {
            break (token, answer);
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    };

    let challenge_url = format!(
        "http://{}/.well-known/acme-challenge/{}",
        acme_account.domain, challenge_token
    );
    let graceful_shutdown = if let Some(port) = opts.port {
        println!("Serving ACME challenge answer on local port {}, assuming that this port is binding to http://{}/", port, acme_account.domain);
        Some(start_warp_server(port, &challenge_answer))
    } else if opts.use_fastly_dictionary {
        println!("Writing ACME challenge answer to Fastly edige dictionary.");
        let acme_state =
            sxg_rs::acme::state_machine::create_from_challenge(&challenge_token, &challenge_answer);
        super::gen_config::fastly::update_dictionary_item(
            artifact.fastly_service_id.as_ref().unwrap(),
            artifact.fastly_dictionary_id.as_ref().unwrap(),
            sxg_rs::acme::state_machine::ACME_STORAGE_KEY,
            &serde_json::to_string(&acme_state)?,
        )?;
        None
    } else {
        println!(
            "\
            Please create a file in your HTTP server to serve the following URL.\n\
            URL:\n\
            {}\n\
            Plain-text content:\n\
            {}\n\
            ",
            challenge_url, challenge_answer
        );
        None
    };

    println!(
        "Waiting for the propagation of ACME challenge answer; checking every 10 seconds from {}.",
        challenge_url
    );
    loop {
        let url = format!(
            "http://{}/.well-known/acme-challenge/{}",
            acme_account.domain, challenge_token
        );
        let actual_response = sxg_rs::fetcher::get(runtime.fetcher.as_ref(), &url).await?;
        if let Ok(actual_response) = String::from_utf8(actual_response) {
            if actual_response.trim() == challenge_answer {
                println!("ACME challenge answer succesfully detected.");
                break;
            }
        }
        print!(".");
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }

    let certificate_pem = loop {
        runtime.now = std::time::SystemTime::now();
        update_acme_state_machine(&runtime, &acme_account).await?;
        let state = sxg_rs::acme::state_machine::read_current_state(&runtime).await?;
        if let Some(cert) = state.certificates.last() {
            break cert.clone();
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    };
    if opts.use_fastly_dictionary {
        println!("Uploading certificates to Fastly edge dicionary.");
        let acme_state = sxg_rs::acme::state_machine::create_from_certificate(certificate_pem);
        super::gen_config::fastly::update_dictionary_item(
            artifact.fastly_service_id.as_ref().unwrap(),
            artifact.fastly_dictionary_id.as_ref().unwrap(),
            sxg_rs::acme::state_machine::ACME_STORAGE_KEY,
            &serde_json::to_string(&acme_state)?,
        )?;
    } else {
        println!("{}", certificate_pem);
    }
    if let Some(tx) = graceful_shutdown {
        let _ = tx.send(());
    }
    Ok(())
}
