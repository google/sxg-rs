use std::collections::BTreeMap;

pub struct SignedHeaders<'a>(BTreeMap<&'a str, &'a str>);

impl<'a> SignedHeaders<'a> {
    pub fn new() -> Self {
        SignedHeaders(BTreeMap::new())
    }
    pub fn insert(&mut self, key: &'a str, value: &'a str) {
        self.0.insert(key, value);
    }
    pub fn serialize(&self) -> Vec<u8> {
        use crate::cbor::DataItem;
        let cbor_data = DataItem::Map(
            self.0.iter().map(|(key, value)| {
                (DataItem::ByteString(key.as_bytes()), DataItem::ByteString(value.as_bytes()))
            }).collect()
        );
        cbor_data.serialize()
    }
}
