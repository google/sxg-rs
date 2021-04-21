## Setup

1. Install [Rust](https://www.rust-lang.org/tools/install).
1. Install [@cloudflare/wrangler](https://github.com/cloudflare/wrangler).
1. Create a `wrangler.toml` by running `cp wrangler.toml.example wrangler.toml`.
   1. Fill in your Cloudflare account ID.
   1. Replace `example.com` by your domain.

1. Add your certificate and keys to [certs](./certs) folder.
1. `wrangler publish`

