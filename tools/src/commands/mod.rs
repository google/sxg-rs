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

mod apply_acme_cert;
mod gen_config;
mod gen_dev_cert;
mod gen_sxg;

use super::tokio_block_on as block_on;
use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
enum SubCommand {
    ApplyAcmeCert(apply_acme_cert::Opts),
    GenConfig(gen_config::Opts),
    GenDevCert(gen_dev_cert::Opts),
    GenSxg(gen_sxg::Opts),
}

#[derive(Parser)]
struct Opts {
    #[clap(subcommand)]
    sub_command: SubCommand,
}

pub fn main() -> Result<()> {
    match Opts::parse().sub_command {
        SubCommand::ApplyAcmeCert(opts) => block_on(apply_acme_cert::main(opts)),
        SubCommand::GenConfig(opts) => gen_config::main(opts),
        SubCommand::GenSxg(opts) => block_on(gen_sxg::main(opts)),
        SubCommand::GenDevCert(opts) => gen_dev_cert::main(opts),
    }
}
