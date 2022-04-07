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

//! This file is the Rust implementation of
//! [processor.ts](https://github.com/google/sxg-rs/blob/main/typescript_utilities/src/processor.ts).
//! Most of the context of why and how we process HTML are documented in that file.

use crate::http::HttpResponse;
use crate::http_parser::link::Link;
use crate::link::ALLOWED_PARAM_NAMES;
use anyhow::Result;
use serde::Deserialize;
use std::borrow::Cow;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessHtmlOption {
    pub is_sxg: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum ContentType {
    HtmlUtf8,
    HtmlOther,
    Other,
}
fn parse_content_type(content_type_header_value: &str) -> ContentType {
    let content_type_header_value = content_type_header_value.trim_start().to_ascii_lowercase();
    if content_type_header_value.starts_with("text/html") {
        if content_type_header_value.contains("utf-8") {
            ContentType::HtmlUtf8
        } else {
            ContentType::HtmlOther
        }
    } else {
        ContentType::Other
    }
}

/// Processes HTML using the following processors.
/// - For `<link rel=preload>` elements, they are promoted to Link headers.
/// - For `<template data-sxg-only>` elements:
///   - If SXG, they are "unwrapped" (i.e. their children are promoted out of the <template>).
///   - Else, they are deleted.
/// - For `<script data-issxg-var>` elements, they are replaced with
///   `<script>window.isSXG=...</script>`, where `...` is true or false.
/// If input charset is not UTF8, the input will be returned back without any modification.
pub fn process_html(input: HttpResponse, option: ProcessHtmlOption) -> Result<HttpResponse> {
    let content_type_header = input.headers.iter().find_map(|(name, value)| {
        if name.eq_ignore_ascii_case("content-type") {
            Some(value)
        } else {
            None
        }
    });
    let mut known_utf8 = false;
    if let Some(content_type_header) = content_type_header {
        match parse_content_type(content_type_header) {
            ContentType::HtmlUtf8 => known_utf8 = true,
            ContentType::HtmlOther => (),
            ContentType::Other => return Ok(input),
        };
    } else {
        // Doesn't process HTML because content-type header does not exsist.
        return Ok(input);
    }
    let input_body = match String::from_utf8(input.body) {
        Ok(input_body) => input_body,
        Err(e) => {
            // Doesn't process HTML because input body bytes can't be parsed at UTF-8 string, for
            // example, a UTF-16 BOM exsists.
            return Ok(HttpResponse {
                body: e.into_bytes(),
                headers: input.headers,
                status: input.status,
            });
        }
    };
    let mut link_headers: Vec<String> = vec![];
    let element_content_handlers = vec![
        // Parse the meta tag, per the implementation in HTMLMetaCharsetParser::CheckForMetaCharset:
        // https://source.chromium.org/chromium/chromium/src/+/main:third_party/blink/renderer/core/html/parser/html_meta_charset_parser.cc;l=62-125;drc=7a0b88f6d5c015fd3c280b58c7a99d8e1dca28ac.
        // This differs slightly from what's described at https://github.com/whatwg/html/issues/6962, and
        // differs drastically from what's specified in
        // https://html.spec.whatwg.org/multipage/parsing.html#prescan-a-byte-stream-to-determine-its-encoding.
        lol_html::element!("meta", |e| {
            // EncodingFromMetaAttributes:
            // https://source.chromium.org/chromium/chromium/src/+/main:third_party/blink/renderer/core/html/parser/html_parser_idioms.cc;l=362-393;drc=7a0b88f6d5c015fd3c280b58c7a99d8e1dca28ac
            if let Some(charset) = e.get_attribute("charset") {
                if charset.eq_ignore_ascii_case("utf-8") {
                    known_utf8 = true;
                }
            } else if let (Some(http_equiv), Some(content)) =
                (e.get_attribute("http-equiv"), e.get_attribute("content"))
            {
                if http_equiv.eq_ignore_ascii_case("content-type")
                    && parse_content_type(&content) == ContentType::HtmlUtf8
                {
                    known_utf8 = true;
                }
            }
            Ok(())
        }),
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
    if !known_utf8 {
        return Ok(HttpResponse {
            headers: input.headers,
            status: input.status,
            body: input_body.into_bytes(),
        });
    }
    let mut output_headers = input.headers;
    output_headers.push(("Link".to_string(), link_headers.join(",")));
    Ok(HttpResponse {
        body: output.into_bytes(),
        headers: output_headers,
        status: input.status,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_parses_content_type() {
        assert_eq!(parse_content_type(r#"text/html"#), ContentType::HtmlOther);
        assert_eq!(
            parse_content_type(r#"text/html; charset=utf-8"#),
            ContentType::HtmlUtf8
        );
        assert_eq!(
            parse_content_type(r#"text/html; charset="utf-8""#),
            ContentType::HtmlUtf8
        );
        assert_eq!(
            parse_content_type(r#"text/html; charset=ascii"#),
            ContentType::HtmlOther
        );
        assert_eq!(parse_content_type(r#"text/plain"#), ContentType::Other);
    }
    fn quick_process(content_type: &str, input_body: &str) -> String {
        let output = process_html(
            HttpResponse {
                status: 200,
                headers: vec![("content-type".to_string(), content_type.to_string())],
                body: input_body.to_string().into_bytes(),
            },
            ProcessHtmlOption { is_sxg: true },
        );
        String::from_utf8(output.unwrap().body).unwrap()
    }
    #[test]
    fn it_works() {
        assert_eq!(
            quick_process(
                "text/html;charset=utf-8",
                "<script data-issxg-var></script>",
            ),
            "<script data-issxg-var>window.isSXG=true</script>"
        );
        // HTML is not processed when charset is not specified.
        assert_eq!(
            quick_process("text/html", "<script data-issxg-var></script>",),
            "<script data-issxg-var></script>",
        );
        // Meta tag of charset is supported.
        assert_eq!(
            quick_process(
                "text/html",
                "<meta http-equiv=content-type content=\"text/html;charset=utf-8\">\
                <script data-issxg-var></script>"
            ),
            "<meta http-equiv=content-type content=\"text/html;charset=utf-8\">\
            <script data-issxg-var>window.isSXG=true</script>"
        );
        // Meta tag with HTML-encoded attribute
        assert_eq!(
            quick_process(
                "text/html",
                "<meta http-equiv=content-type content=\"text/html;charset=&quot;utf-8&quot;\">\
                <script data-issxg-var></script>"
            ),
            "<meta http-equiv=content-type content=\"text/html;charset=&quot;utf-8&quot;\">\
            <script data-issxg-var>window.isSXG=true</script>",
        );
    }
}
