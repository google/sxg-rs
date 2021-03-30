use std::collections::BTreeMap;

pub struct SignedHeaders(BTreeMap<Vec<u8>, Vec<u8>>);

impl SignedHeaders {
    pub fn new() -> Self {
        SignedHeaders(BTreeMap::new())
    }
    pub fn insert(&mut self, key: &str, value: &str) {
        self.0.insert(key.as_bytes().to_vec(), value.as_bytes().to_vec());
    }
    pub fn serialize(&self) -> Vec<u8> {
        use crate::cbor::DataItem;
        let cbor_data = DataItem::Map(
            self.0.iter().map(|(key, value)| {
                (DataItem::ByteString(key.clone()), DataItem::ByteString(value.clone()))
            }).collect()
        );
        cbor_data.serialize()
    }
}
