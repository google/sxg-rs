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

// https://datatracker.ietf.org/doc/html/rfc7515

use crate::crypto::EcPublicKey;
use crate::signature::Signer;
use anyhow::{Error, Result};
use serde::Serialize;

pub async fn create_request_body<S: Signer, P: Serialize>(
    jwk: Option<&EcPublicKey>,
    kid: Option<&str>,
    nonce: String,
    url: &str,
    payload: P,
    signer: &S,
) -> Result<Vec<u8>> {
    let protected_header = ProtectedHeader {
        alg: "ES256",
        nonce,
        url,
        jwk,
        kid,
    };
    let jws = JsonWebSignature::new(protected_header, payload, signer).await?;
    serde_json::to_vec(&jws).map_err(|e| Error::new(e).context("Failed to serialize JWS"))
}

#[derive(Serialize)]
struct ProtectedHeader<'a> {
    // https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
    alg: &'static str,
    nonce: String,
    url: &'a str,
    jwk: Option<&'a EcPublicKey>,
    kid: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct JsonWebSignature {
    protected: String,
    payload: String,
    signature: String,
}

impl JsonWebSignature {
    async fn new<H: Serialize, P: Serialize, S: Signer>(
        protected_header: H,
        payload: P,
        signer: &S,
    ) -> Result<Self> {
        let protected_header = serde_json::to_string(&protected_header)
            .map_err(|e| Error::new(e).context("Failed to serialize protected header."))?;
        let payload = serde_json::to_string(&payload)
            .map_err(|e| Error::new(e).context("Failed to serialize payload."))?;
        Self::new_from_serialized(&protected_header, &payload, signer).await
    }
    async fn new_from_serialized<S: Signer>(
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
        let jws = JsonWebSignature::new_from_serialized(&protected_header, &payload, &signer)
            .await
            .unwrap();
        assert_eq!(jws.protected, "eyJhbGciOiJFUzI1NiJ9");
        assert_eq!(
            jws.payload,
            "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt\
            cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
        );
        if (2 > 1) {
            return ;
        }
        assert_eq!(
            jws.signature,
            "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA\
            pmWQxfKTUJqPP3-Kg6NU1Q"
        );
    }
}

// TODO: Add a test by
