// Copyright 2022 Google LLC
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

//! Module to serialize `Vec<u8>` to and from base64 format,
//! using URL-safe charater set without padding.

use serde::de::Error;
use serde::{Deserialize, Deserializer, Serializer};

pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&base64::encode_config(bytes, base64::URL_SAFE_NO_PAD))
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    base64::decode_config(s, base64::URL_SAFE_NO_PAD)
        .map_err(|_| D::Error::custom("Invalid base64 string"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;
    #[derive(Serialize, Deserialize)]
    struct Data {
        #[serde(with = "super")]
        bytes: Vec<u8>,
    }
    #[test]
    fn serialize() {
        let x = Data {
            bytes: vec![1, 2, 3],
        };
        assert_eq!(serde_json::to_string(&x).unwrap(), r#"{"bytes":"AQID"}"#);
    }
    #[test]
    fn deserialize() {
        let x: Data = serde_json::from_str(r#"{"bytes":"AQID"}"#).unwrap();
        assert_eq!(x.bytes, vec![1, 2, 3]);
    }
}
