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

#[cfg(feature = "rust_signer")]
use crate::signature::rust_signer::RustSigner;
use anyhow::{anyhow, Error, Result};
use der_parser::{
    ber::{BerObject, BerObjectContent},
    oid::Oid,
};
use serde::{Deserialize, Serialize};

pub fn get_der_from_pem(pem_text: &str, expected_tag: &str) -> Result<Vec<u8>> {
    for pem in ::pem::parse_many(pem_text).map_err(Error::new)? {
        if pem.tag == expected_tag {
            return Ok(pem.contents);
        }
    }
    Err(anyhow!(
        r#"The PEM file does not contains "{}" block"#,
        expected_tag
    ))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EcPublicKey {
    pub crv: String,
    pub kty: String,
    #[serde(with = "crate::serde_helpers::base64")]
    pub x: Vec<u8>,
    #[serde(with = "crate::serde_helpers::base64")]
    pub y: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct EcPrivateKey {
    #[serde(with = "crate::serde_helpers::base64")]
    pub d: Vec<u8>,
    #[serde(flatten)]
    pub public_key: EcPublicKey,
}

impl EcPublicKey {
    /// Parses public key from DER-encoded
    /// [SPKI](https://datatracker.ietf.org/doc/html/rfc5480) format.
    pub fn from_spki_der(der: &[u8]) -> Result<Self> {
        // https://datatracker.ietf.org/doc/html/rfc5480#section-2.2
        //   ECC public keys have the following syntax:
        //     ECPoint ::= OCTET STRING
        //      o The first octet of the OCTET STRING indicates whether the key is
        //        compressed or uncompressed.  The uncompressed form is indicated
        //        by 0x04 and the compressed form is indicated by either 0x02 or
        //        0x03 (see 2.3.3 in [SEC1]).  The public key MUST be rejected if
        //        any other value is included in the first octet.
        let octets = der_parser::parse_ber(der)?
            .1
            .as_slice()
            .map_err(|e| Error::new(e).context("Expecting ECPoint to be an OCTET STRING"))?;
        const KEY_SIZE: usize = 32; // Both X and Y of the EC Point are 32 bytes (256 bit).
        if octets.len() != 1 + KEY_SIZE * 2 {
            return Err(Error::msg(format!("Expecting ECPoint to contain 1 octet of uncompression flag and {}*2 octets of point coordinates", KEY_SIZE)));
        }
        match octets[0] {
            0x04 => (),
            0x03 => {
                return Err(Error::msg(
                    "We don't support ECPoint in compressed form, please use uncompressed form.",
                ))
            }
            _ => return Err(Error::msg("Invalid ECPoint form")),
        };
        let mut x = octets[1..].to_vec();
        let y = x.split_off(KEY_SIZE);
        Ok(EcPublicKey {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x,
            y,
        })
    }
    /// Calculates the JWK thumbprint defined by
    /// [RFC7638](https://datatracker.ietf.org/doc/html/rfc7638#section-3).
    pub fn get_jwk_thumbprint(&self) -> Result<Vec<u8>> {
        let message = serde_json::to_string(&self)?;
        Ok(HashAlgorithm::Sha256.digest(message.as_bytes()))
    }
}

impl EcPrivateKey {
    /// Parses private key from DER-encoded
    /// [SEC1](https://www.secg.org/sec1-v2.pdf) format,
    /// which is also defined in [RFC5915](https://datatracker.ietf.org/doc/html/rfc5915).
    pub fn from_sec1_der(der: &[u8]) -> Result<Self> {
        let ec_private_key = der_parser::parse_ber(der)?.1;
        // https://datatracker.ietf.org/doc/html/rfc5915#section-3
        //   ECPrivateKey ::= SEQUENCE {
        //     version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
        //     privateKey     OCTET STRING,
        //     parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
        //     publicKey  [1] BIT STRING OPTIONAL
        //   }
        let d = ec_private_key
            .as_sequence()
            .map_err(|e| Error::new(e).context("Expecting ECPrivateKey to be a SEQUENCE"))?
            .get(1)
            .ok_or_else(|| Error::msg("Expecting ECPrivateKey to contain at least 2 items"))?;
        let d = d
            .as_slice()
            .map_err(|e| Error::new(e).context("Expecting privateKey to be an OCTET STRING"))?
            .to_vec();
        let public_key = EcPublicKey::from_spki_der(
            ec_private_key
                .as_sequence()?
                .get(3)
                .ok_or_else(|| Error::msg("Expecting ECPrivateKey to contain at least 4 items"))?
                .as_slice()?,
        )?;
        Ok(EcPrivateKey { d, public_key })
    }
    /// Parses private key from PEM-encoded
    /// [SEC1](https://www.secg.org/sec1-v2.pdf) format.
    pub fn from_sec1_pem(pem: &str) -> Result<Self> {
        let der = get_der_from_pem(pem, "EC PRIVATE KEY")?;
        Self::from_sec1_der(&der)
    }
    #[cfg(feature = "rust_signer")]
    pub fn create_signer(&self) -> Result<RustSigner> {
        RustSigner::new(&self.d)
    }
}

// https://datatracker.ietf.org/doc/html/rfc7638#section-3
// RFC-7638 requires the field names to be ordered lexicographically;
// the order must be `[crv, d, x, y]`.
// If we use the macro `#[derive(Serialize)] and #[serde(flatten)]`,
// we can't insert `d` between the other three fields of `public_key`;
// we can only get `[crv, x, y, d]` or `[d, crv, x, y]`.
// Hence we have to implement serialization by ourself.
impl Serialize for EcPrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("EcPrivateKey", /*number of fields=*/ 5)?;
        s.serialize_field("crv", &self.public_key.crv)?;
        s.serialize_field(
            "d",
            &base64::encode_config(&self.d, base64::URL_SAFE_NO_PAD),
        )?;
        s.serialize_field("kty", &self.public_key.kty)?;
        s.serialize_field(
            "x",
            &base64::encode_config(&self.public_key.x, base64::URL_SAFE_NO_PAD),
        )?;
        s.serialize_field(
            "y",
            &base64::encode_config(&self.public_key.y, base64::URL_SAFE_NO_PAD),
        )?;
        s.end()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SingleCertificate {
    #[serde(with = "crate::serde_helpers::base64")]
    pub der: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CertificateChain {
    pub end_entity: SingleCertificate,
    /// `issuers` are sorted as Secion 7.4.2 in RFC-4346.
    /// For example, the root certificate is the last one.
    pub issuers: Vec<SingleCertificate>,
    #[serde(with = "crate::serde_helpers::base64")]
    pub end_entity_sha256: Vec<u8>,
    pub basename: String,
}

impl CertificateChain {
    const TAG: &'static str = "CERTIFICATE";
    /// Parse `CertificateChain` from multiple PEM files.
    /// Each input file may contain multiple PEM certificates.
    /// Input files must be sorted like `[cert_pem, issuer_pem, root_pem]`.
    pub fn from_pem_files(pem_files: &[&str]) -> Result<Self> {
        let mut pem_items = vec![];
        for current_file in pem_files {
            let items_in_current_file = ::pem::parse_many(current_file).map_err(Error::new)?;
            pem_items.extend_from_slice(&items_in_current_file);
        }
        let der_items = Self::take_certificate_contents(pem_items)?;
        let mut der_items = der_items.into_iter();
        let end_entity = der_items
            .next()
            .ok_or_else(|| Error::msg("Expecting PEM files to contain at least one certificate"))?;
        let issuers = der_items.collect();
        let end_entity_sha256 = HashAlgorithm::Sha256.digest(&end_entity.der);
        Ok(CertificateChain {
            end_entity,
            issuers,
            basename: base64::encode_config(&end_entity_sha256, base64::URL_SAFE_NO_PAD),
            end_entity_sha256,
        })
    }
    pub fn create_cert_cbor(&self, end_entity_ocsp_der: &[u8]) -> Vec<u8> {
        use crate::cbor::DataItem;
        let mut cert_cbor = vec![
            DataItem::TextString("📜⛓"),
            DataItem::Map(vec![
                (
                    DataItem::TextString("cert"),
                    DataItem::ByteString(&self.end_entity.der),
                ),
                (
                    DataItem::TextString("ocsp"),
                    DataItem::ByteString(end_entity_ocsp_der),
                ),
            ]),
        ];
        for issuer in self.issuers.iter() {
            cert_cbor.push(DataItem::Map(vec![(
                DataItem::TextString("cert"),
                DataItem::ByteString(&issuer.der),
            )]));
        }

        let cert_cbor = DataItem::Array(cert_cbor);
        cert_cbor.serialize()
    }
    fn take_certificate_contents(pem_items: Vec<::pem::Pem>) -> Result<Vec<SingleCertificate>> {
        pem_items
            .into_iter()
            .map(|pem_item| {
                const TAG: &str = "CERTIFICATE";
                if pem_item.tag == TAG {
                    Ok(SingleCertificate {
                        der: pem_item.contents,
                    })
                } else {
                    Err(anyhow!("Expecting {}, found {}", Self::TAG, pem_item.tag))
                }
            })
            .collect::<Result<_>>()
    }
}

#[derive(Clone, Copy)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
}

impl HashAlgorithm {
    // https://tools.ietf.org/html/rfc5280#section-4.1.1.2
    // AlgorithmIdentifier  ::=  SEQUENCE  {
    //      algorithm               OBJECT IDENTIFIER,
    //      parameters              ANY DEFINED BY algorithm OPTIONAL  }
    pub fn to_ber(&self) -> BerObject<'static> {
        BerObject::from_seq(vec![
            BerObject::from_obj(BerObjectContent::OID(match self {
                HashAlgorithm::Sha1 => Oid::from(&[1, 3, 14, 3, 2, 26]).unwrap(),
                HashAlgorithm::Sha256 => Oid::from(&[2, 16, 840, 1, 101, 3, 4, 2, 1]).unwrap(),
            })),
            BerObject::from_obj(BerObjectContent::Null),
        ])
    }
    pub fn digest(&self, bytes: &[u8]) -> Vec<u8> {
        match self {
            HashAlgorithm::Sha1 => {
                use sha1::{Digest, Sha1};
                let mut hasher = Sha1::new();
                hasher.update(bytes);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha256 => {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(bytes);
                hasher.finalize().to_vec()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn assert_bytes_eq_hex(bytes: Vec<u8>, hex: &str) {
        let bytes: Vec<String> = bytes.iter().map(|x| format!("{:02x}", x)).collect();
        let mut hex = hex.to_string();
        hex.retain(|c| !c.is_whitespace());
        assert_eq!(bytes.join(":"), hex);
    }
    #[test]
    fn parse_ec_private_key() {
        // Generated with:
        //    KEY=`mktemp`
        //    openssl ecparam -name prime256v1 -genkey -out $KEY
        //    openssl ec -in $KEY -noout -text
        const PRIVKEY_PEM: &str = "
-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIHe67M0Bh00ZJbMcgMAJaGLC6oGBj7UwJCXq7lXSCO6GoAoGCCqGSM49
AwEHoUQDQgAEBwqyu0DJoqq0T6KYNjPfhBeYs9iesy/boi1/Cqrp8jceL0Zh8uo2
rS6wVo+rtspBMOwa/DK3LJE1W9nS6MqL4Q==
-----END EC PRIVATE KEY-----";
        const PRIV_HEX: &str = "
            77:ba:ec:cd:01:87:4d:19:25:b3:1c:80:c0:09:68:
            62:c2:ea:81:81:8f:b5:30:24:25:ea:ee:55:d2:08:
            ee:86";
        const PUB_HEX: &str = "
            04:07:0a:b2:bb:40:c9:a2:aa:b4:4f:a2:98:36:33:
            df:84:17:98:b3:d8:9e:b3:2f:db:a2:2d:7f:0a:aa:
            e9:f2:37:1e:2f:46:61:f2:ea:36:ad:2e:b0:56:8f:
            ab:b6:ca:41:30:ec:1a:fc:32:b7:2c:91:35:5b:d9:
            d2:e8:ca:8b:e1";
        let private_key = EcPrivateKey::from_sec1_pem(PRIVKEY_PEM).unwrap();
        assert_bytes_eq_hex(private_key.d, PRIV_HEX);
        assert_bytes_eq_hex(
            [
                vec![0x04],
                private_key.public_key.x,
                private_key.public_key.y,
            ]
            .concat(),
            PUB_HEX,
        );
    }
    #[test]
    fn returns_err_on_invalid_input() {
        const INVALID_PRIVKEY: &str = "
-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
-----END EC PRIVATE KEY-----";
        assert!(EcPrivateKey::from_sec1_pem(INVALID_PRIVKEY).is_err());
    }
    // According to https://datatracker.ietf.org/doc/html/rfc7638#section-3,
    // to generate valid thumbprint, the serialization of JWK must be
    //   1. containing no whitespace or line breaks
    //   2. with the required members ordered lexicographically
    #[test]
    fn jwk_serialization() {
        let public_key = EcPublicKey {
            kty: "EC".to_string(),
            crv: "".to_string(),
            x: vec![1],
            y: vec![2],
        };
        assert_eq!(
            serde_json::to_string(&public_key).unwrap(),
            r#"{"crv":"","kty":"EC","x":"AQ","y":"Ag"}"#
        );
        let private_key = EcPrivateKey {
            d: vec![3],
            public_key,
        };
        assert_eq!(
            serde_json::to_string(&private_key).unwrap(),
            r#"{"crv":"","d":"Aw","kty":"EC","x":"AQ","y":"Ag"}"#
        );
    }
}
