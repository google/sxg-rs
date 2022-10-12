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

mod accept;
mod base;
pub mod cache_control;
pub mod link;
pub mod media_type;
pub mod srcset;

use anyhow::{Error, Result};
use base::ows;
use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::char as char1,
    combinator::eof,
    multi::separated_list0,
    sequence::{separated_pair, terminated},
    IResult,
};
use std::time::Duration;

fn format_nom_err(err: nom::Err<nom::error::Error<&str>>) -> Error {
    Error::msg(format!("{}", err))
}

// Parses a http header which might have multiple values separated by comma.
fn parse_vec<'a, F, T>(input: &'a str, parse_single: F) -> Result<Vec<T>>
where
    F: Fn(&'a str) -> IResult<&'a str, T>,
{
    terminated(
        separated_list0(separated_pair(ows, char1(','), ows), parse_single),
        eof,
    )(input)
    .map(|(_, items)| items)
    .map_err(format_nom_err)
}

pub fn parse_accept_header(input: &str) -> Result<Vec<accept::Accept>> {
    parse_vec(input, accept::accept)
}

pub fn parse_cache_control_directives(input: &str) -> Result<Vec<cache_control::Directive>> {
    parse_vec(input, cache_control::directive)
}

// Returns the freshness lifetime for a shared cache.
pub fn parse_cache_control_header(input: &str) -> Result<Duration> {
    cache_control::freshness_lifetime(parse_cache_control_directives(input)?)
        .ok_or_else(|| Error::msg("Freshness lifetime is implicit"))
}

pub fn parse_content_type_header(input: &str) -> Result<media_type::MediaType> {
    terminated(media_type::media_type, eof)(input)
        .map(|(_, output)| output)
        .map_err(format_nom_err)
}

pub fn parse_link_header(input: &str) -> Result<Vec<link::Link>> {
    parse_vec(input, link::link)
}

pub fn parse_token_list(input: &str) -> Result<Vec<&str>> {
    parse_vec(input, base::token)
}

// https://datatracker.ietf.org/doc/html/rfc7231#section-7.1.4
pub fn parse_vary_header(input: &str) -> Result<Vec<&str>> {
    parse_vec(input, |input| {
        alt((
            tag("*"),
            // https://datatracker.ietf.org/doc/html/rfc7230#section-3.2
            base::token,
        ))(input)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn vary() {
        assert_eq!(
            parse_vary_header("*  , cookie").unwrap(),
            vec!["*", "cookie"]
        );
        assert!(parse_vary_header("tokens only; no spaces or semicolons allowed").is_err());
    }
    #[test]
    fn incomplete_is_err() {
        assert!(parse_accept_header("application/signed-exchange;v=").is_err());
        assert!(parse_cache_control_header("max-age=\"3600").is_err());
        assert!(parse_content_type_header("application/signed-exchange;v=\"b3").is_err());
        assert!(parse_link_header(r#"</foo>;bar="baz \""#).is_err());
        assert!(parse_vary_header("incomplete,").is_err());
    }
}
