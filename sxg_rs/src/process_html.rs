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

use crate::http::HttpResponse;
use crate::http_parser::link::Link;
use crate::link::ALLOWED_PARAM_NAMES;
use anyhow::Result;
use serde::Deserialize;
use std::borrow::Cow;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessHtmlOption {
    is_sxg: bool,
}

/// Processes HTML using the following processors.
/// - For `<link rel=preload>` elements, they are promoted to Link headers.
/// - For `<template data-sxg-only>` elements:
///   - If SXG, they are "unwrapped" (i.e. their children promoted out of the <teplate>).
///   - Else, they are deleted.
/// - For `<script data-issxg-var>` elements, they are replaced with
///   `<script>window.isSXG=...</script>`, where `...` is true or false.
/// This function tries the input body as UTF8 string, if input body is not valid UTF8, the input
/// will be returned back without any HTML processing.
pub fn process_html(input: HttpResponse, option: ProcessHtmlOption) -> Result<HttpResponse> {
    let input_body = match String::from_utf8(input.body) {
        Ok(input_body) => input_body,
        Err(e) => return Ok(HttpResponse {
            body: e.into_bytes(),
            headers: input.headers,
            status: input.status,
        }),
    };
    let mut link_headers: Vec<String> = vec![];
    let element_content_handlers = vec![
        lol_html::element!(
            r#"link[rel~="preload" i][href][as]:not([data-sxg-no-header])"#,
            |e| {
                if let Some(href) = e.get_attribute("href") {
                    let params: Vec<(Cow<'static, str>, Option<String>)> = e
                        .attributes()
                        .iter()
                        .filter_map(|attr| {
                            let name = attr.name();
                            let value = attr.value();
                            if ALLOWED_PARAM_NAMES.contains(name.as_str()) {
                                Some((Cow::Owned(name), Some(value)))
                            } else {
                                None
                            }
                        })
                        .collect();
                    let link = Link { uri: href, params };
                    link_headers.push(link.serialize());
                }
                Ok(())
            }
        ),
        lol_html::element!(r#"script[data-issxg-var]"#, |e| {
            e.set_inner_content(
                &format!("window.isSXG={}", option.is_sxg),
                lol_html::html_content::ContentType::Html,
            );
            Ok(())
        }),
        lol_html::element!(r#"template[data-sxg-only]"#, |e| {
            if option.is_sxg {
                e.remove_and_keep_content()
            } else {
                e.remove()
            }
            Ok(())
        }),
    ];
    let output = lol_html::rewrite_str(
        &input_body,
        lol_html::Settings {
            element_content_handlers,
            ..lol_html::Settings::default()
        },
    )?;
    let mut output_headers = input.headers;
    output_headers.push(("Link".to_string(), link_headers.join(",")));
    Ok(HttpResponse {
        body: output.into_bytes(),
        headers: output_headers,
        status: input.status,
    })
}
