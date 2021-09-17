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

use crate::fetcher::Fetcher;
use crate::header_integrity;
use crate::headers::Headers;
use crate::http_cache::HttpCache;
use anyhow::{anyhow, Result};
use std::collections::BTreeSet;
use url::Url;

pub fn get_sha(bytes: &[u8]) -> Vec<u8> {
    use ::sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}

pub async fn signed_headers_and_payload<F: Fetcher, C: HttpCache>(
    fallback_url: &Url,
    status_code: u16,
    payload_headers: &Headers,
    payload_body: &[u8],
    subresource_fetcher: F,
    header_integrity_cache: C,
    strip_response_headers: &BTreeSet<String>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    if status_code != 200 {
        return Err(anyhow!("The resource status code is {}.", status_code));
    }
    // 16384 is the max mice record size allowed by SXG spec.
    // https://wicg.github.io/webpackage/draft-yasskin-http-origin-signed-responses.html#section-3.5-7.9.1
    let (mice_digest, payload_body) = crate::mice::calculate(payload_body, 16384);
    let mut header_integrity_fetcher = header_integrity::new_fetcher(
        subresource_fetcher,
        header_integrity_cache,
        strip_response_headers,
    );
    let signed_headers = payload_headers
        .get_signed_headers_bytes(
            fallback_url,
            status_code,
            &mice_digest,
            &mut header_integrity_fetcher,
        )
        .await;
    Ok((signed_headers, payload_body))
}

#[cfg(test)]
pub mod tests {
    use futures::{
        future::{BoxFuture, Future},
        task::{Context, Poll, Waker},
    };
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};

    // Generated with:
    //   KEY=`mktemp` && CSR=`mktemp` &&
    //   openssl ecparam -out "$KEY" -name prime256v1 -genkey &&
    //   openssl req -new -sha256 -key "$KEY" -out "$CSR" -subj '/CN=example.org/O=Test/C=US' &&
    //   openssl x509 -req -days 90 -in "$CSR" -signkey "$KEY" -out - -extfile <(echo -e "1.3.6.1.4.1.11129.2.1.22 = ASN1:NULL\nsubjectAltName=DNS:example.org") &&
    //   rm "$KEY" "$CSR"
    pub const SELF_SIGNED_CERT_PEM: &str = "
-----BEGIN CERTIFICATE-----
MIIBkTCCATigAwIBAgIUL/D6t/l3OrSRCI0KlCP7zH1U5/swCgYIKoZIzj0EAwIw
MjEUMBIGA1UEAwwLZXhhbXBsZS5vcmcxDTALBgNVBAoMBFRlc3QxCzAJBgNVBAYT
AlVTMB4XDTIxMDgyMDAwMTc1MFoXDTIxMTExODAwMTc1MFowMjEUMBIGA1UEAwwL
ZXhhbXBsZS5vcmcxDTALBgNVBAoMBFRlc3QxCzAJBgNVBAYTAlVTMFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAE3jibTycCk9tifTFg6CyiUirdSlblqLoofEC7B0I4
IO9A52fwDYjZfwGSdu/6ji0MQ1+19Ovr3d9DvXSa7pN1j6MsMCowEAYKKwYBBAHW
eQIBFgQCBQAwFgYDVR0RBA8wDYILZXhhbXBsZS5vcmcwCgYIKoZIzj0EAwIDRwAw
RAIgdTuJ4IXs6LeXQ15TxIsRtfma4F8ypUk0bpBLLbVPbyACIFYul0BjPa2qVd/l
SFfkmh8Fc2QXpbbaK5AQfnQpkDHV
-----END CERTIFICATE-----
    ";

    // Generated from above cert using:
    //   openssl x509 -in - -outform DER | openssl dgst -sha256 -binary | base64 | tr /+ _- | tr -d =
    pub const SELF_SIGNED_CERT_SHA256: &str = "Lz2EMcys4NR9FP0yYnuS5Uw8xM3gbVAOM2lwSBU9qX0";

    // Returns a future for the given state object. If multiple futures are created from the same
    // shared state, the first to be polled resolves after the second.
    pub fn out_of_order<'a, T: 'a, F: 'a + Fn() -> T + Send>(
        state: Arc<Mutex<OutOfOrderState>>,
        value: F,
    ) -> BoxFuture<'a, T> {
        Box::pin(OutOfOrderFuture { value, state })
    }

    pub struct OutOfOrderState {
        first: bool,
        waker: Option<Waker>,
    }

    impl OutOfOrderState {
        pub fn new() -> Arc<Mutex<Self>> {
            Arc::new(Mutex::new(OutOfOrderState {
                first: true,
                waker: None,
            }))
        }
    }

    struct OutOfOrderFuture<T, F: Fn() -> T> {
        value: F,
        state: Arc<Mutex<OutOfOrderState>>,
    }

    impl<T, F: Fn() -> T> Future for OutOfOrderFuture<T, F> {
        type Output = T;
        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let mut state = &mut *self.state.lock().unwrap();
            let first = state.first;
            state.first = false;
            println!("first = {}", first);
            if first {
                state.waker = Some(cx.waker().clone());
                Poll::Pending
            } else {
                if let Some(waker) = &state.waker {
                    println!("waking!");
                    waker.wake_by_ref();
                }
                Poll::Ready((self.value)())
            }
        }
    }
}
