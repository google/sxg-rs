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

//! This module implements
//! [JSON Web Signature (JWS)](https://datatracker.ietf.org/doc/html/rfc7515).
//! [ACME spec](https://datatracker.ietf.org/doc/html/rfc8555#:~:text=payload%20in%20a%20JSON%20Web%20Signature)
//! requires the request body to be encapsulated in JWS format for authentication.

use crate::crypto::EcPublicKey;
use crate::signature::Signer;
use anyhow::{Error, Result};
use serde::Serialize;

pub async fn create_acme_request_body<S: Signer, P: Serialize>(
    jwk: Option<&EcPublicKey>,
    kid: Option<&str>,
    nonce: String,
    url: &str,
    payload: Option<P>,
    signer: &S,
) -> Result<Vec<u8>> {
    let protected_header = AcmeProtectedHeader {
        alg: "ES256",
        nonce,
        url,
        jwk,
        kid,
    };
    let jws = JsonWebSignature::new(protected_header, payload, signer).await?;
    serde_json::to_vec(&jws).map_err(|e| Error::new(e).context("Failed to serialize JWS"))
}

/// The protected headers which is used authentication ACME request
/// [(ACME spec)](https://datatracker.ietf.org/doc/html/rfc8555#:~:text=The%20JWS%20Protected%20Header%20MUST%20include%20the%20following%20fields).
#[derive(Serialize)]
struct AcmeProtectedHeader<'a> {
    // https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
    alg: &'static str,
    nonce: String,
    url: &'a str,
    jwk: Option<&'a EcPublicKey>,
    kid: Option<&'a str>,
}

/// [JSON Web Signature](https://datatracker.ietf.org/doc/html/rfc7515).
#[derive(Debug, Serialize)]
pub struct JsonWebSignature {
    protected: String,
    payload: String,
    signature: String,
}

// Parses an asn1 format signature and returns the raw 64 bytes data.
// This is the inverse function of `crate::signature::js_signer::raw_sig_to_asn1`.
// We need this funciton because the SXG uses asn1 signature,
// however JSON WebSignature needs a raw 64 bytes signature.
// TODO: refactor `crate::signature::Signer` to return both formats.
fn parse_asn1_sig(asn1: &[u8]) -> Result<Vec<u8>> {
    let signature = der_parser::parse_ber(asn1)?.1;
    let numbers = signature.as_sequence()?;
    let r = numbers[0].as_bigint()?.to_bytes_be();
    let s = numbers[1].as_bigint()?.to_bytes_be();
    Ok([r.1, s.1].concat())
}

impl JsonWebSignature {
    /// Constructs a signature from serialiable header and payload.
    /// If the given `payload` is `None`, it will be serialized into an empty
    /// string.
    async fn new<H: Serialize, P: Serialize, S: Signer>(
        protected_header: H,
        payload: Option<P>,
        signer: &S,
    ) -> Result<Self> {
        let protected_header = serde_json::to_string(&protected_header)
            .map_err(|e| Error::new(e).context("Failed to serialize protected header."))?;
        let payload = if let Some(payload) = payload {
            serde_json::to_string(&payload)
                .map_err(|e| Error::new(e).context("Failed to serialize payload."))?
        } else {
            "".to_string()
        };
        Self::new_from_serialized(&protected_header, &payload, signer).await
    }
    /// Constructs a signature from strings of serialized header and payload.
    pub async fn new_from_serialized<S: Signer>(
        protected_header: &str,
        payload: &str,
        signer: &S,
    ) -> Result<Self> {
        let protected_header = base64::encode_config(protected_header, base64::URL_SAFE_NO_PAD);
        let payload = base64::encode_config(payload, base64::URL_SAFE_NO_PAD);
        // https://datatracker.ietf.org/doc/html/rfc7515#:~:text=The%20input%20to%20the%20digital%20signature
        let message = format!("{}.{}", protected_header, payload);
        let signature = signer
            .sign(message.as_bytes())
            .await
            .map_err(|e| e.context("Failed to sign message"))?;
        let signature = parse_asn1_sig(&signature)?;
        let signature = base64::encode_config(&signature, base64::URL_SAFE_NO_PAD);
        Ok(JsonWebSignature {
            protected: protected_header,
            payload,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[async_std::test]
    async fn json_web_signature() {
        // This test follow the example given in RFC 7515.
        // https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.3.1
        let protected_header = r#"{"alg":"ES256"}"#;
        let payload =
            "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";
        let private_key = base64::decode_config(
            "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI",
            base64::URL_SAFE_NO_PAD,
        )
        .unwrap();
        let signer = crate::signature::rust_signer::RustSigner::new(&private_key).unwrap();
        let jws = JsonWebSignature::new_from_serialized(protected_header, payload, &signer)
            .await
            .unwrap();
        assert_eq!(jws.protected, "eyJhbGciOiJFUzI1NiJ9");
        assert_eq!(
            jws.payload,
            "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt\
            cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
        );
        assert_eq!(
            jws.signature,
            // Although this signature is not the same as RFC 7515, it is still
            // a valid signature, because ECDSA uses a random number.
            // TODO: add code to test it.
            "e4ZrhZdbFQ7630Tq51E6RQiJaae9bFNGJszIhtusEwzvO21rzH76Wer6yRn2Zb34V\
            jIm3cVRl0iQctbf4uBY3w"
        );
    }
}

// TODO: Add a test by
