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
mod cache_control;
pub mod media_type;
pub mod link;

use anyhow::{Error, Result};
use nom::{
    IResult,
    character::complete::char as char1,
    combinator::complete,
    eof,
    separated_list0,
    separated_pair,
};
use base::ows;
use std::time::Duration;

fn format_nom_err(err: nom::Err<nom::error::Error<&str>>) -> Error {
    Error::msg(format!("{}", err))
}

// Parses a http header which might have multiple values separated by comma.
fn parse_vec<'a, F, T>(input: &'a str, parse_single: F) -> Result<Vec<T>>
where
    F: Fn(&'a str) -> IResult<&'a str, T>
{
    let (input, items) = separated_list0!(
        input,
        separated_pair!(ows, char1(','), ows),
        parse_single
    ).map_err(format_nom_err)?;
    eof!(input,).map_err(format_nom_err)?;
    Ok(items)
}

pub fn parse_accept_header(input: &str) -> Result<Vec<accept::Accept>> {
    parse_vec(input, accept::accept)
}

// Returns the freshness lifetime for a shared cache.
pub fn parse_cache_control_header(input: &str) -> Result<Duration> {
    let directives = parse_vec(input, cache_control::directive)?;
    cache_control::freshness_lifetime(directives).ok_or(Error::msg("Freshness lifetime is implicit"))
}

pub fn parse_content_type_header(input: &str) -> Result<media_type::MediaType> {
    complete(media_type::media_type)(input)
        .map(|(_, output)| output)
        .map_err(format_nom_err)
}

pub fn parse_link_header(input: &str) -> Result<Vec<link::Link>> {
    parse_vec(input, link::link)
}
