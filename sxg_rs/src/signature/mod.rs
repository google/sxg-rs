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

#[cfg(feature = "wasm")]
pub mod js_signer;
pub mod mock_signer;
#[cfg(feature = "rust_signer")]
pub mod rust_signer;

use crate::structured_header::{ParamItem, ShItem, ShParamList};
use crate::utils::{MaybeSend, MaybeSync};
use anyhow::{anyhow, Error, Result};
use async_trait::async_trait;
use der_parser::ber::{BerObject, BerObjectContent};
use std::cmp::min;
use std::convert::TryInto;
use std::time::Duration;

#[derive(Clone, Copy)]
pub enum Format {
    Raw,
    EccAsn1,
}

#[cfg_attr(feature = "wasm", async_trait(?Send))]
#[cfg_attr(not(feature = "wasm"), async_trait)]
pub trait Signer: MaybeSend + MaybeSync {
    /// Signs the message, and returns in the given format.
    async fn sign(&self, message: &[u8], format: Format) -> Result<Vec<u8>>;
}

pub struct SignatureParams<'a> {
    pub cert_url: &'a str,
    pub cert_sha256: &'a [u8],
    pub date: std::time::SystemTime,
    pub expires: Option<std::time::SystemTime>,
    pub headers: &'a [u8],
    pub id: &'a str,
    pub request_url: &'a str,
    pub signer: &'a dyn Signer,
    pub validity_url: &'a str,
}

// https://wicg.github.io/webpackage/draft-yasskin-httpbis-origin-signed-exchanges-impl.html#name-the-signature-header
pub struct Signature<'a> {
    cert_url: &'a str,
    cert_sha256: &'a [u8],
    date: i64,
    expires: i64,
    id: &'a str,
    sig: Vec<u8>,
    validity_url: &'a str,
}

// Maximum signature duration per https://wicg.github.io/webpackage/draft-yasskin-http-origin-signed-responses.html#section-3.5-7.3.
const SEVEN_DAYS: Duration = Duration::from_secs(60 * 60 * 24 * 7);

fn seven_days_from(date: &std::time::SystemTime) -> Result<std::time::SystemTime> {
    date.checked_add(SEVEN_DAYS)
        .ok_or_else(|| anyhow!("Overflow computing expires"))
}

impl<'a> Signature<'a> {
    pub async fn new(params: SignatureParams<'a>) -> Result<Signature<'a>> {
        let SignatureParams {
            cert_url,
            cert_sha256,
            date,
            expires,
            headers,
            id,
            request_url,
            signer,
            validity_url,
        } = params;
        let expires = match expires {
            None => seven_days_from(&date)?,
            Some(expires) => min(expires, seven_days_from(&date)?),
        };
        let date = time_to_number(date);
        let expires = time_to_number(expires);
        // https://wicg.github.io/webpackage/draft-yasskin-httpbis-origin-signed-exchanges-impl.html#name-signature-validity
        let message = [
            &[32u8; 64],
            "HTTP Exchange 1 b3".as_bytes(),
            &[0u8],
            &[32u8],
            cert_sha256,
            &(validity_url.len() as u64).to_be_bytes(),
            validity_url.as_bytes(),
            &date.to_be_bytes(),
            &expires.to_be_bytes(),
            &(request_url.len() as u64).to_be_bytes(),
            request_url.as_bytes(),
            &(headers.len() as u64).to_be_bytes(),
            headers,
        ]
        .concat();
        let sig = signer
            .sign(&message, Format::EccAsn1)
            .await
            .map_err(|e| e.context("Failed to sign the message."))?;
        Ok(Signature {
            cert_url,
            cert_sha256,
            date: date.try_into()?,
            expires: expires.try_into()?,
            id,
            sig,
            validity_url,
        })
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut list = ShParamList::new();
        let mut param = ParamItem::new(self.id);
        param.push(("sig".into(), Some(ShItem::ByteSequence((&self.sig).into()))));
        param.push((
            "integrity".into(),
            Some(ShItem::String("digest/mi-sha256-03".into())),
        ));
        param.push((
            "cert-url".into(),
            Some(ShItem::String(self.cert_url.into())),
        ));
        param.push((
            "cert-sha256".into(),
            Some(ShItem::ByteSequence(self.cert_sha256.into())),
        ));
        param.push((
            "validity-url".into(),
            Some(ShItem::String(self.validity_url.into())),
        ));
        param.push(("date".into(), Some(ShItem::Integer(self.date))));
        param.push(("expires".into(), Some(ShItem::Integer(self.expires))));
        list.push(param);
        format!("{}", list).into_bytes()
    }
}

fn time_to_number(t: std::time::SystemTime) -> u64 {
    t.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

// Parses an asn1 format signature and returns the raw 64 bytes data.
pub fn parse_asn1_sig(asn1: &[u8]) -> Result<Vec<u8>> {
    let signature = der_parser::parse_ber(asn1)?.1;
    let numbers = signature.as_sequence()?;
    let r = numbers[0].as_bigint()?.to_bytes_be();
    let s = numbers[1].as_bigint()?.to_bytes_be();
    Ok([r.1, s.1].concat())
}

pub fn raw_sig_to_asn1(raw: Vec<u8>) -> Result<Vec<u8>> {
    const NUMBER_LENGTH: usize = 32; // 256 bit is 32 bytes.
    const SIG_LENGTH: usize = NUMBER_LENGTH * 2; // A signature contains two numbers;
    if raw.len() != SIG_LENGTH {
        return Err(Error::msg(format!(
            "Expecting signature length to be {}, found {}.",
            SIG_LENGTH,
            raw.len()
        )));
    }
    let mut r = raw;
    let mut s = r.split_off(NUMBER_LENGTH);
    ensure_positive(&mut r);
    ensure_positive(&mut s);
    let asn1 = BerObject::from_obj(BerObjectContent::Sequence(vec![
        BerObject::from_obj(BerObjectContent::Integer(&r)),
        BerObject::from_obj(BerObjectContent::Integer(&s)),
    ]));
    asn1.to_vec()
        .map_err(|e| Error::new(e).context("Failed to serialize asn1 BER Object"))
}

// Prepend the big-endian integer with leading zeros if needed, in order to
// make it a positive integer. For example, when the input is 0xffff,
// it will be parsed as a negative number, hence we need to change it to
// 0x00ffff.
fn ensure_positive(a: &mut Vec<u8>) {
    if a[0] >= 0x80 {
        a.insert(0, 0x00);
    }
}
