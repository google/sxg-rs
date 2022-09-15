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

// OCSP request is defined in
// https://tools.ietf.org/html/rfc6960#section-4.1
//
// OCSP over http is defined in
// https://tools.ietf.org/html/rfc2560#appendix-A.1

use crate::crypto::{CertificateChain, HashAlgorithm};
use crate::fetcher::Fetcher;
use crate::http::{HttpRequest, Method};
use crate::runtime::Runtime;
use anyhow::{anyhow, Error, Result};
use der_parser::{
    ber::{BerObject, BerObjectContent},
    oid,
    oid::Oid,
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};
use tokio::sync::Mutex;
use x509_parser::{
    certificate::X509Certificate,
    extensions::{GeneralName, ParsedExtension},
};

fn create_ocsp_request(cert: &X509Certificate, issuer: &X509Certificate) -> Vec<u8> {
    let hash_algorithm = HashAlgorithm::Sha1;
    let issuer_name = issuer.tbs_certificate.subject.as_raw();
    let issuer_key = issuer
        .tbs_certificate
        .subject_pki
        .subject_public_key
        .data
        .as_ref();
    let issuer_key_hash = hash_algorithm.digest(issuer_key);
    let issuer_name_hash = hash_algorithm.digest(issuer_name);
    let serial_number = cert.tbs_certificate.raw_serial();
    // https://tools.ietf.org/html/rfc6960#section-4.1.1
    // CertID          ::=     SEQUENCE {
    //     hashAlgorithm       AlgorithmIdentifier,
    //     issuerNameHash      OCTET STRING, -- Hash of issuer's DN
    //     issuerKeyHash       OCTET STRING, -- Hash of issuer's public key
    //     serialNumber        CertificateSerialNumber }
    let cert_id = BerObject::from_seq(vec![
        hash_algorithm.to_ber(),
        BerObject::from_obj(BerObjectContent::OctetString(&issuer_name_hash)),
        BerObject::from_obj(BerObjectContent::OctetString(&issuer_key_hash)),
        BerObject::from_obj(BerObjectContent::Integer(serial_number)),
    ]);
    // https://tools.ietf.org/html/rfc6960#section-4.1.1
    // Request         ::=     SEQUENCE {
    //     reqCert                     CertID,
    //     singleRequestExtensions     [0] EXPLICIT Extensions OPTIONAL }
    let request = BerObject::from_seq(vec![cert_id]);
    // https://tools.ietf.org/html/rfc6960#section-4.1.1
    // TBSRequest      ::=     SEQUENCE {
    //     version             [0]     EXPLICIT Version DEFAULT v1,
    //     requestorName       [1]     EXPLICIT GeneralName OPTIONAL,
    //     requestList                 SEQUENCE OF Request,
    //     requestExtensions   [2]     EXPLICIT Extensions OPTIONAL }
    let tbs_request = BerObject::from_seq(vec![BerObject::from_seq(vec![request])]);
    // https://tools.ietf.org/html/rfc6960#section-4.1.1
    // OCSPRequest     ::=     SEQUENCE {
    //     tbsRequest                  TBSRequest,
    //     optionalSignature   [0]     EXPLICIT Signature OPTIONAL }
    let ocsp_request = BerObject::from_seq(vec![tbs_request]);
    ocsp_request.to_vec().unwrap()
}

// https://datatracker.ietf.org/doc/html/rfc4325#section-2
// https://datatracker.ietf.org/doc/html/rfc3280#section-4.2.2.1
const AIA: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .1 .1);
// https://www.iana.org/assignments/smi-numbers/smi-numbers.xhtml#smi-numbers-1.3.6.1.5.5.7.48.1
const AIA_OCSP: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .48 .1);

pub async fn fetch_from_ca(
    cert_der: &[u8],
    issuer_der: &[u8],
    fetcher: &dyn Fetcher,
) -> Result<Vec<u8>> {
    let cert = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| Error::from(e).context("Failed to parse cert DER"))?
        .1;
    let issuer = x509_parser::parse_x509_certificate(issuer_der)
        .map_err(|e| Error::from(e).context("Failed to parse issuer DER"))?
        .1;
    let aia = cert.extensions().iter().find(|ext| ext.oid == AIA);
    let aia = if let Some(aia) = aia {
        aia
    } else {
        // If the certificate doesn't include an AIA section, it is probably a
        // self-signed certificate. Return a stub OCSP response.
        return Ok(b"ocsp".to_vec());
    };
    let aia = if let ParsedExtension::AuthorityInfoAccess(aia) = aia.parsed_extension() {
        aia
    } else {
        return Err(anyhow!("Failed to parse AIA extension"));
    };
    let url = aia
        .accessdescs
        .iter()
        .find_map(|access_desc| {
            if access_desc.access_method == AIA_OCSP {
                match access_desc.access_location {
                    GeneralName::URI(url) => Some(url),
                    _ => None,
                }
            } else {
                None
            }
        })
        .ok_or_else(|| anyhow!("AIA OCSP responder with type of URI is not found."))?;
    let req = HttpRequest {
        body: create_ocsp_request(&cert, &issuer),
        headers: vec![(
            String::from("content-type"),
            String::from("application/ocsp-request"),
        )],
        method: Method::Post,
        url: url.into(),
    };
    let rsp = fetcher
        .fetch(req)
        .await
        .map_err(|e| e.context("Failed to fetch OCSP"))?;
    Ok(rsp.body)
}

const OCSP_KEY: &str = "OCSP";

#[derive(Serialize, Deserialize)]
struct OcspData {
    pub expiration_time: SystemTime,
    pub recommended_update_time: SystemTime,
    #[serde(with = "crate::serde_helpers::base64")]
    pub value: Vec<u8>,
}

pub enum OcspUpdateStrategy {
    EarlyAsRecommended,
    LazyIfUnexpired,
}

/// Reads OCSP in storage, checks the expiration status, and returns latest.
/// If OCSP in storage needs update, fetches it from the server and writes it
/// into storage. The outging traffic to the server is throttled to be a
/// single task.
/// If there is any error when reading from and writing to storage, the error
/// will be ignored but an error message will be printed to output/log.
pub async fn read_and_update_ocsp_in_storage(
    certificate_chain: &CertificateChain,
    runtime: &Runtime,
    strategy: OcspUpdateStrategy,
) -> Result<Vec<u8>> {
    // Checks whether we can directly return the existing OCSP in storage.
    match runtime.storage.read(OCSP_KEY).await {
        Ok(Some(old_ocsp)) => {
            if let Ok(old_ocsp) = serde_json::from_str::<OcspData>(&old_ocsp) {
                match strategy {
                    OcspUpdateStrategy::EarlyAsRecommended => {
                        if old_ocsp.recommended_update_time > runtime.now {
                            return Ok(old_ocsp.value);
                        }
                    }
                    OcspUpdateStrategy::LazyIfUnexpired => {
                        if old_ocsp.expiration_time > runtime.now {
                            return Ok(old_ocsp.value);
                        }
                    }
                }
            } else {
                // The existing OCSP in storage can't be parsed as `OcspData`.
            }
        }
        Ok(None) => {
            // There is no OCSP in storage.
        }
        Err(e) => {
            println!("Failed to read OCSP from storage. {}", e);
        }
    }
    if certificate_chain.issuers.is_empty() {
        return Err(Error::msg("Certificate chain contains no issuer."));
    }
    let cert_der = &certificate_chain.end_entity.der;
    let issuer_der = &certificate_chain.issuers[0].der;
    let new_ocsp_value = {
        static SINGLE_TASK: Mutex<()> = Mutex::const_new(());
        let guard = SINGLE_TASK.lock().await;
        let ocsp = fetch_from_ca(cert_der, issuer_der, runtime.fetcher.as_ref()).await?;
        std::mem::drop(guard);
        ocsp
    };
    const SIX_DAYS: Duration = Duration::from_secs(3600 * 24 * 6);
    const ONE_DAY: Duration = Duration::from_secs(3600 * 24);
    let new_ocsp = OcspData {
        expiration_time: runtime.now + SIX_DAYS,
        recommended_update_time: runtime.now + ONE_DAY,
        value: new_ocsp_value,
    };
    let write_result = runtime
        .storage
        .write(OCSP_KEY, &serde_json::to_string(&new_ocsp)?)
        .await;
    if let Err(e) = write_result {
        println!("Failed to write OCSP to storage. {}", e);
    }
    Ok(new_ocsp.value)
}
