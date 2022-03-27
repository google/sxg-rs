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

use crate::http::HttpResponse;
use crate::http_parser::link::Link;
use anyhow::Result;
use once_cell::sync::Lazy;
use std::borrow::Cow;
use std::collections::BTreeSet;

static ALLOWED_LINK_ATTRS: Lazy<BTreeSet<&'static str>> = Lazy::new(|| {
    vec![
        "as",
        "header-integrity",
        "media",
        "rel",
        "imagesrcset",
        "imagesizes",
        "crossorigin",
    ]
    .into_iter()
    .collect()
});

pub fn process_html(input: HttpResponse) -> Result<HttpResponse> {
    let mut link_headers: Vec<String> = vec![];
    let element_content_handlers = vec![lol_html::element!(
        r#"link[rel~="preload" i][href][as]:not([data-sxg-no-header])"#,
        |e| {
            if let Some(href) = e.get_attribute("href") {
                let params: Vec<(Cow<'static, str>, Option<String>)> = e
                    .attributes()
                    .iter()
                    .filter_map(|attr| {
                        let name = attr.name();
                        let value = attr.value();
                        if ALLOWED_LINK_ATTRS.contains(name.as_str()) {
                            Some((Cow::Owned(name), Some(value)))
                        } else {
                            None
                        }
                    })
                    .collect();
                let link = Link {
                    uri: href.to_string(),
                    params,
                };
                link_headers.push(link.serialize());
            }
            Ok(())
        }
    )];
    let input_body = String::from_utf8(input.body)?;
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
