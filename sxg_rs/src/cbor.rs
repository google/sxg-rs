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

// https://tools.ietf.org/html/rfc7049

use std::collections::BTreeMap;

pub enum DataItem<'a> {
    #[allow(dead_code)]
    UnsignedInteger(u64),
    ByteString(&'a [u8]),
    TextString(&'a str),
    Array(Vec<DataItem<'a>>),
    Map(Vec<(DataItem<'a>, DataItem<'a>)>),
}

impl<'a> DataItem<'a> {
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();
        self.append_binary_to(&mut result);
        result
    }
    fn append_binary_to(&self, output: &mut Vec<u8>) {
        use DataItem::*;
        match self {
            UnsignedInteger(x) => append_integer(output, 0, *x),
            ByteString(bytes) => {
                append_integer(output, 2, bytes.len() as u64);
                output.extend_from_slice(bytes);
            }
            TextString(text) => {
                append_integer(output, 3, text.len() as u64);
                output.extend_from_slice(text.as_bytes());
            }
            Array(items) => {
                append_integer(output, 4, items.len() as u64);
                for item in items {
                    item.append_binary_to(output);
                }
            }
            Map(fields) => {
                let mut map = BTreeMap::<Vec<u8>, Vec<u8>>::new();
                for (key, value) in fields {
                    map.insert(key.serialize(), value.serialize());
                }
                append_integer(output, 5, map.len() as u64);
                for (mut key, mut value) in map.into_iter() {
                    output.append(&mut key);
                    output.append(&mut value);
                }
            }
        }
    }
}

fn append_integer(output: &mut Vec<u8>, major_type: u8, data: u64) {
    let major_type = major_type << 5;
    match data {
        0..=23 => {
            output.push(major_type | (data as u8));
        }
        24..=0xff => {
            output.push(major_type | 24);
            output.push(data as u8);
        }
        0x100..=0xffff => {
            output.push(major_type | 25);
            output.extend_from_slice(&(data as u16).to_be_bytes());
        }
        0x10000..=0xffffffff => {
            output.push(major_type | 26);
            output.extend_from_slice(&(data as u32).to_be_bytes());
        }
        0x100000000..=0xffffffffffffffff => {
            output.push(major_type | 27);
            output.extend_from_slice(&data.to_be_bytes());
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    fn from_hex(input: &str) -> Vec<u8> {
        (0..input.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&input[i..i + 2], 16).unwrap())
            .collect()
    }
    #[test]
    fn it_works() {
        assert_eq!(DataItem::UnsignedInteger(0).serialize(), from_hex("00"),);
        assert_eq!(DataItem::UnsignedInteger(23).serialize(), from_hex("17"),);
        assert_eq!(DataItem::UnsignedInteger(24).serialize(), from_hex("1818"),);
        assert_eq!(DataItem::UnsignedInteger(100).serialize(), from_hex("1864"),);
        assert_eq!(
            DataItem::UnsignedInteger(1000).serialize(),
            from_hex("1903e8"),
        );
        assert_eq!(
            DataItem::UnsignedInteger(1000000).serialize(),
            from_hex("1a000f4240"),
        );
        assert_eq!(
            DataItem::UnsignedInteger(1000000000000).serialize(),
            from_hex("1b000000e8d4a51000"),
        );
        assert_eq!(
            DataItem::UnsignedInteger(18446744073709551615).serialize(),
            from_hex("1bffffffffffffffff"),
        );
        assert_eq!(
            DataItem::ByteString(&[1, 2, 3, 4]).serialize(),
            from_hex("4401020304"),
        );
        assert_eq!(
            DataItem::TextString("IETF").serialize(),
            from_hex("6449455446"),
        );
        assert_eq!(DataItem::Map(vec![]).serialize(), from_hex("a0"),);
        assert_eq!(
            DataItem::Map(vec![
                (DataItem::UnsignedInteger(1), DataItem::UnsignedInteger(2)),
                (DataItem::UnsignedInteger(3), DataItem::UnsignedInteger(4)),
            ])
            .serialize(),
            from_hex("a201020304"),
        );
    }
    #[test]
    fn map_keys_are_sorted() {
        use DataItem::*;
        assert_eq!(
            Map(vec![
                (UnsignedInteger(2), UnsignedInteger(5)),
                (UnsignedInteger(1), UnsignedInteger(6)),
            ])
            .serialize(),
            from_hex("a201060205"),
        );
        // Although "AA" is lexicographically less than "B", the CBOR format
        // of the string is prefixed with the string length, hence "B" is less
        // than "AA".
        assert_eq!(
            Map(vec![
                (TextString("AA"), UnsignedInteger(6)),
                (TextString("B"), UnsignedInteger(5)),
            ])
            .serialize(),
            from_hex("a261420562414106"),
        );
    }
}
