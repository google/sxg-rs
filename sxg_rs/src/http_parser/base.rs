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

use nom::{
    branch::alt,
    bytes::complete::{take, take_while, take_while1},
    character::complete::char as char1,
    combinator::{map, map_opt},
    multi::many0,
    sequence::{delimited, preceded},
    IResult,
};

// `token` are defined in
// https://tools.ietf.org/html/rfc7230#section-3.2.6
pub fn token(input: &str) -> IResult<&str, &str> {
    take_while1(is_tchar)(input)
}

pub fn is_tchar(c: char) -> bool {
    matches!(c,
        '!' | '#' | '$' | '%' | '&' | '\'' | '*' |
        '+' | '-' | '.' | '^' | '_' | '`' | '|' | '~' |
        '0'..='9' | 'A'..='Z' | 'a'..='z'
    )
}

fn is_space_or_tab(c: char) -> bool {
    c == '\t' || c == ' '
}

// `OWS` is defined in
// https://tools.ietf.org/html/rfc7230#section-3.2.3
pub fn ows(input: &str) -> IResult<&str, &str> {
    take_while(is_space_or_tab)(input)
}

// `quoted-string` is defined in
// https://tools.ietf.org/html/rfc7230#section-3.2.6
pub fn quoted_string(input: &str) -> IResult<&str, String> {
    map(
        delimited(char1('"'), many0(alt((qdtext, quoted_pair))), char1('"')),
        |s: Vec<char>| s.into_iter().collect(),
    )(input)
}

fn qdtext(input: &str) -> IResult<&str, char> {
    char_if(is_qdtext)(input)
}

fn is_qdtext(c: char) -> bool {
    matches!(c,
        '\t' | ' ' | '\x21' |
        '\x23'..='\x5B' | '\x5D'..='\x7E' |
        '\u{80}'..=std::char::MAX
    )
}

pub fn is_quoted_pair_payload(c: char) -> bool {
    matches!(c,
        '\t' | ' ' |
        '\x21'..='\x7E' |
        '\u{80}'..=std::char::MAX
    )
}

fn quoted_pair(input: &str) -> IResult<&str, char> {
    preceded(char1('\\'), char_if(is_quoted_pair_payload))(input)
}

fn char_if(predicate: fn(c: char) -> bool) -> impl Fn(&str) -> IResult<&str, char> {
    move |input: &str| {
        map_opt(take(1usize), |s: &str| {
            let c = s.chars().next()?;
            if predicate(c) {
                Some(c)
            } else {
                None
            }
        })(input)
    }
}

pub fn parameter_value(input: &str) -> IResult<&str, String> {
    alt((map(token, |s: &str| s.to_string()), quoted_string))(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn incomplete() {
        assert!(quoted_string(r#""amp"#).is_err());
        assert!(parameter_value(r#""amp"#).is_err());
    }
    #[test]
    fn obs_text() {
        // `obs-text` are text made by non-ascii bytes (0x80-0xff).
        // `obs-test` are not allowed in tokens.
        assert_eq!(
            token("amp⚡").unwrap(),
            (
                "⚡", // unparsed bytes
                "amp", // parsed token
            )
        );
        // `obs-text` are allowed in quoted-string.
        assert_eq!(
            quoted_string(r#""amp⚡s""#).unwrap(),
            ("", "amp⚡s".to_string(),)
        );
        // `obs-text` are allowed as quoted-pair.
        assert_eq!(
            quoted_string(r#""amp\⚡s""#).unwrap(),
            ("", "amp⚡s".to_string(),)
        );
    }
}
