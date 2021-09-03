<!--
Copyright 2021 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

## Setup

1. Get an SXG-compatible certificate
   using [these steps](../credentials/README.md#get-an-sxg_compatible-certificate).

1. Install [Rust](https://www.rust-lang.org/tools/install).
1. Install [@cloudflare/wrangler](https://github.com/cloudflare/wrangler).

1. Clone this repo and cd into the current folder.
   ```bash
   git clone https://github.com/google/sxg-rs.git
   cd sxg-rs/cloudflare_worker/
   ```
   All following steps in this `README.md` should be done in this folder.

1. Run `cargo run -p config-generator` and follow the command line prompt.
   This command will creates a `wrangler.toml` that can be modified futher if desired.

   - To find Cloudflare **account ID** and **zone ID**,
     see [this screenshot](https://forum.aapanel.com/d/3914-how-to-get-zone-id-of-cloudflare).

1. Put your private key as a
   [secret](https://developers.cloudflare.com/workers/cli-wrangler/commands#secret)
   to cloudflare worker.
   1. Parse your private key to JWK format.
      ```bash
      go run ../credentials/parse_private_key.go <../credentials/privkey.pem
      ```
   1. Run `wrangler secret put PRIVATE_KEY_JWK`. (Use the string
      `PRIVATE_KEY_JWK` as is, and don't replace it with the
      actual private key.)
   1. The terminal will interactively ask for the value of the secret.
      Put the private key in JWK format here.

1. Run `./publish.sh` to build and deploy the worker online.

1. Go to the [workers dashboard](https://dash.cloudflare.com/workers), and edit
   the `your_domain.com/*` route to fail open, like this:
   ![screenshot of workers dashboard with "Fail open" highlighted](fail_open.png)

1. To check whether the worker generates a valid SXG,
   use Chrome browser to open `https://${WORKER_HOST}/.sxg/test.html`.

1. Read on for [next steps](../README.md).

## Maintenance

The certificates need to be renewed every 90 days.

1. Follow [these steps](../credentials/README.md#renew-certificate) to renew
   the certificate.
1. Run `cargo run -p config-generator`.
1. Run `./publish.sh` to restart the worker.

## Uninstall

The worker and KV namespace can be deleted from the [workers
dashboard](https://dash.cloudflare.com/workers/overview).
