use anyhow::{anyhow, bail, ensure, Result};
use ciborium::value::Value;
use futures::TryStreamExt;
use hyper::Body;
use sxg_rs::crypto::HashAlgorithm::Sha256;

// Verify that the expected_integrity matches, to reduce risk of version skew
// after the origin renews its certificate -- e.g. serving a new certificate
// for an SXG that needs the old and not-yet-expired one -- when cert responses
// from the distributor are cached by an intermediary. Origins using
// content-addressed cert paths won't have this issue, but not all do that.
// TODO: Add a timeout.
pub async fn validate(expected_integrity: &Option<&str>, mut cert: Body) -> Result<Body> {
    // https://wicg.github.io/webpackage/draft-yasskin-httpbis-origin-signed-exchanges-impl.html#name-loading-a-certificate-chain
    let mut body: Vec<u8> = vec![];
    while let Some(bytes) = cert.try_next().await? {
        body.extend_from_slice(&bytes);
        ensure!(body.len() < 10_000);
    }
    let chain: Vec<Value> = ciborium::de::from_reader(body.as_slice())?;
    match &chain[..] {
        [Value::Text(tag), Value::Map(attrs), ..] if tag == "📜⛓" => {
            let cert = match attrs
                .iter()
                .find(|(name, _)| matches!(name, Value::Text(name) if name == "cert"))
            {
                Some((_, Value::Bytes(cert))) => cert,
                _ => bail!("missing cert attr"),
            };
            if let Some(expected_integrity) = expected_integrity {
                ensure!(
                    expected_integrity
                        == &base64::encode_config(Sha256.digest(cert), base64::URL_SAFE)
                            .get(..12)
                            .ok_or_else(|| anyhow!("invalid integrity"))?
                );
            }
            Ok(Body::from(body))
        }
        _ => bail!("invalid cert-chain+cbor"),
    }
    // TODO: Extract min(forall cert. cert expiry, forall ocsp. ocsp expiry), so the caller can set s-maxage based on it.
}

// TODO: Test.
