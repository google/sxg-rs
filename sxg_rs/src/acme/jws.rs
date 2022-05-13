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
use crate::signature::{Format as SignatureFormat, Signer};
use anyhow::{Error, Result};
use serde::{Serialize, Serializer};

pub async fn create_acme_request_body<P: Serialize>(
    jwk: Option<&EcPublicKey>,
    kid: Option<&str>,
    nonce: String,
    url: &str,
    payload: Option<P>,
    signer: &dyn Signer,
) -> Result<Vec<u8>> {
    let protected_header = AcmeProtectedHeader {
        alg: Algorithm::ES256,
        nonce,
        url,
        jwk,
        kid,
    };
    let jws = JsonWebSignature::new(protected_header, payload, signer).await?;
    serde_json::to_vec(&jws).map_err(|e| Error::new(e).context("Failed to serialize JWS"))
}

/// Cryptographic signing algorithms allowed in JWS, as defined in
/// [RFC-7518](https://datatracker.ietf.org/doc/html/rfc7518#section-3.1).
#[derive(Clone, Copy)]
pub enum Algorithm {
    /// ECDSA using P-256 and SHA-256
    ES256,
    /// HMAC using SHA-256
    HS256,
}

impl Serialize for Algorithm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Algorithm::ES256 => serializer.serialize_str("ES256"),
            Algorithm::HS256 => serializer.serialize_str("HS256"),
        }
    }
}

/// The protected headers which is used authentication ACME request
/// [(ACME spec)](https://datatracker.ietf.org/doc/html/rfc8555#:~:text=The%20JWS%20Protected%20Header%20MUST%20include%20the%20following%20fields).
#[derive(Serialize)]
struct AcmeProtectedHeader<'a> {
    alg: Algorithm,
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

impl JsonWebSignature {
    /// Constructs a signature from serialiable header and payload.
    /// If the given `payload` is `None`, it will be serialized into an empty
    /// string.
    pub async fn new<H: Serialize, P: Serialize>(
        protected_header: H,
        payload: Option<P>,
        signer: &dyn Signer,
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
    pub async fn new_from_serialized(
        protected_header: &str,
        payload: &str,
        signer: &dyn Signer,
    ) -> Result<Self> {
        let protected_header = base64::encode_config(protected_header, base64::URL_SAFE_NO_PAD);
        let payload = base64::encode_config(payload, base64::URL_SAFE_NO_PAD);
        // https://datatracker.ietf.org/doc/html/rfc7515#:~:text=The%20input%20to%20the%20digital%20signature
        let message = format!("{}.{}", protected_header, payload);
        let signature = signer
            .sign(message.as_bytes(), SignatureFormat::Raw)
            .await
            .map_err(|e| e.context("Failed to sign message"))?;
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
    #[tokio::test]
    #[cfg(feature = "rust_signer")]
    async fn json_web_signature() {
        use super::*;
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
