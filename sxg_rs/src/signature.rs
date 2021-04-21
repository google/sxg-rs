use ::p256::ecdsa::signature::Signer;
use crate::structured_header::{ShItem, ShParamList, ParamItem};

pub struct SignatureParams<'a> {
    pub cert_url: &'a str,
    pub cert_sha256: Vec<u8>,
    pub date: std::time::SystemTime,
    pub expires: std::time::SystemTime,
    pub headers: &'a [u8],
    pub id: &'a str,
    pub private_key: Vec<u8>,
    pub request_url: &'a str,
    pub validity_url: &'a str,
}

// https://wicg.github.io/webpackage/draft-yasskin-httpbis-origin-signed-exchanges-impl.html#name-the-signature-header
pub struct Signature<'a> {
    cert_url: &'a str,
    cert_sha256: Vec<u8>,
    date: u64,
    expires: u64,
    id: &'a str,
    sig: Vec<u8>,
    validity_url: &'a str,
}

impl<'a> Signature<'a> {
    pub fn new(params: SignatureParams<'a>) -> Self {
        let SignatureParams {
            cert_url,
            cert_sha256,
            date,
            expires,
            headers,
            id,
            private_key,
            request_url,
            validity_url,
        } = params;
        let date = time_to_number(date);
        let expires = time_to_number(expires);
        // https://wicg.github.io/webpackage/draft-yasskin-httpbis-origin-signed-exchanges-impl.html#name-signature-validity
        let message = [
            &[32u8; 64],
            "HTTP Exchange 1 b3".as_bytes(),
            &[0u8],
            &[32u8],
            &cert_sha256,
            &(validity_url.len() as u64).to_be_bytes(),
            validity_url.as_bytes(),
            &date.to_be_bytes(),
            &expires.to_be_bytes(),
            &(request_url.len() as u64).to_be_bytes(),
            request_url.as_bytes(),
            &(headers.len() as u64).to_be_bytes(),
            &headers,
        ].concat();
        let private_key = ::p256::ecdsa::SigningKey::from_bytes(&private_key).unwrap();
        let sig = private_key.sign(&message).to_asn1();
        let sig = sig.as_ref().to_vec();
        Signature {
            cert_url,
            cert_sha256,
            date,
            expires,
            id,
            sig,
            validity_url,
        }
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut list = ShParamList::new();
        let mut param = ParamItem::new(&self.id);
        param.push(("sig", Some(ShItem::ByteSequence(&self.sig))));
        param.push(("integrity", Some(ShItem::String("digest/mi-sha256-03"))));
        param.push(("cert-url", Some(ShItem::String(&self.cert_url))));
        param.push(("cert-sha256", Some(ShItem::ByteSequence(&self.cert_sha256))));
        param.push(("validity-url", Some(ShItem::String(&self.validity_url))));
        param.push(("date", Some(ShItem::Integer(self.date))));
        param.push(("expires", Some(ShItem::Integer(self.expires))));
        list.push(param);
        format!("{}", list).into_bytes()
    }
}

fn time_to_number(t: std::time::SystemTime) -> u64 {
    t.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

