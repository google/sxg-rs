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

use std::borrow::Cow;
use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum ShItem<'a> {
    ByteSequence(Cow<'a, [u8]>),
    Integer(i64),
    String(Cow<'a, str>),
}

// should be https://tools.ietf.org/html/draft-ietf-httpbis-header-structure-10#section-4.1.5
impl<'a> fmt::Display for ShItem<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShItem::ByteSequence(bytes) => {
                write!(f, "*{}*", ::base64::encode(bytes))
            }
            ShItem::Integer(x) => write!(f, "{}", x),
            ShItem::String(x) => {
                write!(f, "\"")?;
                for c in x.chars() {
                    match c {
                        '\\' | '\"' => {
                            write!(f, "\\{}", c)?;
                        }
                        '\u{20}'..='\u{21}' | '\u{23}'..='\u{5b}' | '\u{5d}'..='\u{7e}' => {
                            write!(f, "{}", c)?;
                        }
                        '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{10ffff}' => {
                            return Err(std::fmt::Error);
                        }
                    };
                }
                write!(f, "\"")
            }
        }
    }
}
