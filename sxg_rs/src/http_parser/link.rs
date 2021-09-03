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
    IResult,
    bytes::complete::take_while,
    character::complete::char,
    combinator::{map, opt},
    multi::many0,
    sequence::{delimited, pair, preceded, terminated, tuple},
};
use super::base::{
    is_quoted_pair_payload,
    is_tchar,
    ows,
    parameter_value,
    token,
};

// Represents an individual link directive i.e. an instance of `link-value`
// from https://datatracker.ietf.org/doc/html/rfc8288#section-3.
// Parameters with alternate character encodings (via RFC8187) are not
// supported.
#[derive(Clone, Debug, PartialEq)]
pub struct Link<'a> {
    pub uri: &'a str,
    pub params: Vec<(&'a str, Option<String>)>,
}

fn quote(value: &str) -> Option<String> {
    if value.chars().all(|c| is_tchar(c)) {
        Some(value.into())
    } else if value.chars().all(|c| is_quoted_pair_payload(c)) {
        Some("\"".to_string() + &value.chars().map(|c: char| {
            if c == '\\' || c == '"' {
                format!("\\{}", c)
            } else {
                format!("{}", c)
            }
        }).collect::<String>() + "\"")
    } else {
        None
    }
}

impl <'a> Link<'a> {
    pub fn serialize(&self) -> String {
        "<".to_string() + self.uri + ">" +
            &self.params.iter().filter_map(|(k, v)| {
                Some(if let Some(v) = v {
                    format!(";{}={}", k, quote(v)?)
                } else {
                    format!(";{}", k)
                })
            }).collect::<String>()
    }
}

fn uri_ref(input: &str) -> IResult<&str, &str> {
    // We don't need to fully parse the URI ref using nom. It would be
    // sufficient to scan up until the closing delimiter '>' and then pass the result to the
    // URL class for parsing and validation. For defense in depth, we only allow
    // the characters specified in
    // https://datatracker.ietf.org/doc/html/rfc3986#appendix-A.
    take_while(|c: char|
        match c {
            // unreserved
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '.' | '_' | '~' => true,
            // gen-delims
            ':' | '|' | '?' | '#' | '[' | ']' | '@' => true,
            // sub-delims
            '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | ';' | '=' => true,
            // pct-encoded
            '%' => true,
            // path
            '/' => true,
            _ => false,
        }
    )(input)
}

fn link_param<'a>(input: &'a str) -> IResult<&str, (&'a str, Option<String>)> {
    pair(terminated(token, ows),
         opt(preceded(pair(char('='), ows), parameter_value)))(input)
}

pub fn link(input: &str) -> IResult<&str, Link> {
    map(pair(delimited(char('<'), uri_ref, char('>')),
             many0(preceded(tuple((ows, char(';'), ows)), link_param))), |(uri, params)|
        Link{uri, params}
    )(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse() {
        assert_eq!(link("<>").unwrap(), ("", Link{uri: "", params: vec![]}));
        assert_eq!(link("</foo,bar;baz>").unwrap(), ("", Link{uri: "/foo,bar;baz", params: vec![]}));
        assert_eq!(link("</foo>;bar;baz=quux").unwrap(),
                   ("", Link{uri: "/foo",
                             params: vec![("bar", None), ("baz", Some("quux".into()))]}));
        assert_eq!(link(r#"</foo>;bar="baz \\\"quux""#).unwrap(),
                   ("", Link{uri: "/foo",
                             params: vec![("bar", Some(r#"baz \"quux"#.into()))]}));
        assert!(matches!(link(r#"</foo>;bar="baz \""#).unwrap_err(), nom::Err::Incomplete(_)));
    }
    #[test]
    fn serialize() {
        assert_eq!(Link{uri: "/foo", params: vec![("bar", None)]}.serialize(),
                   "</foo>;bar");
        assert_eq!(Link{uri: "/foo", params: vec![("bar", Some("baz".into()))]}.serialize(),
                   "</foo>;bar=baz");
        assert_eq!(Link{uri: "/foo", params: vec![("bar", Some("baz quux".into()))]}.serialize(),
                   r#"</foo>;bar="baz quux""#);
        assert_eq!(Link{uri: "/foo", params: vec![("bar", Some(r#"baz\"quux"#.into()))]}.serialize(),
                   r#"</foo>;bar="baz\\\"quux""#);
        assert_eq!(Link{uri: "/foo", params: vec![("bar", Some("\x7f".into()))]}.serialize(),
                   "</foo>");
    }
}
