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
