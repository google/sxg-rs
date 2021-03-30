use ::p256::ecdsa::signature::Signer;
use crate::structured_header::{ShItem, ShParamList, ParamItem};

pub struct SignatureParams {
    pub cert_url: String,
    pub cert_sha256: Vec<u8>,
    pub date: std::time::SystemTime,
    pub expires: std::time::SystemTime,
    pub headers: Vec<u8>,
    pub id: String,
    pub private_key: Vec<u8>,
    pub request_url: String,
    pub validity_url: String,
}

// https://wicg.github.io/webpackage/draft-yasskin-httpbis-origin-signed-exchanges-impl.html#name-the-signature-header
pub struct Signature {
    cert_url: String,
    cert_sha256: Vec<u8>,
    date: u64,
    expires: u64,
    id: String,
    sig: Vec<u8>,
    validity_url: String,
}

impl Signature {
    pub fn new(params: SignatureParams) -> Self {
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
        let mut param = ParamItem::new(self.id.clone());
        param.push(("sig".to_string(), Some(ShItem::ByteSequence(self.sig.clone()))));
        param.push(("integrity".to_string(), Some(ShItem::String("digest/mi-sha256-03".to_string()))));
        param.push(("cert-url".to_string(), Some(ShItem::String(self.cert_url.clone()))));
        param.push(("cert-sha256".to_string(), Some(ShItem::ByteSequence(self.cert_sha256.clone()))));
        param.push(("validity-url".to_string(), Some(ShItem::String(self.validity_url.clone()))));
        param.push(("date".to_string(), Some(ShItem::Integer(self.date))));
        param.push(("expires".to_string(), Some(ShItem::Integer(self.expires))));
        list.push(param);
        format!("{}", list).into_bytes()
    }
}

fn time_to_number(t: std::time::SystemTime) -> u64 {
    t.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

