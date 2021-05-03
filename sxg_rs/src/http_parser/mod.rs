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
mod media_type;

use nom::{
    IResult,
    character::complete::char as char1,
    eof,
    separated_list0,
    separated_pair,
};
use base::ows;

fn format_nom_err(err: nom::Err<nom::error::Error<&str>>) -> String {
    format!("{}", err)
}

// Parses a http header which might have multiple values separated by comma.
fn parse_vec<'a, F, T>(input: &'a str, parse_single: F) -> Result<Vec<T>, String>
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

pub fn parse_accept_header(input: &str) -> Result<Vec<accept::Accept>, String> {
    parse_vec(input, accept::accept)
}

