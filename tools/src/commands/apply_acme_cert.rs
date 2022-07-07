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
}

fn start_warp_server(port: u16, answer: String) -> tokio::sync::oneshot::Sender<()> {
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

fn wait_enter_key() {
    std::io::stdin().read_line(&mut String::new()).unwrap();
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
    let graceful_shutdown = if let Some(port) = opts.port {
        Some(start_warp_server(port, challenge_answer))
    } else {
        println!(
            "\
            Please create a file in your HTTP server to serve the following URL.\n\
            URL:\n\
            http://{}/.well-known/acme-challenge/{}\n\
            Plain-text content:\n\
            {}\n\
            Press Enter key after your HTTP server is ready.\
            ",
            acme_account.domain, challenge_token, challenge_answer
        );
        wait_enter_key();
        None
    };
    let certificate_pem = loop {
        runtime.now = std::time::SystemTime::now();
        update_acme_state_machine(&runtime, &acme_account).await?;
        let state = sxg_rs::acme::state_machine::read_current_state(&runtime).await?;
        if let Some(cert) = state.certificates.last() {
            break cert.clone();
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    };
    if let Some(tx) = graceful_shutdown {
        let _ = tx.send(());
    }
    println!("{}", certificate_pem);
    Ok(())
}
