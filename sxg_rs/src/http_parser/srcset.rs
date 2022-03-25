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

#[cfg(feature = "srcset")]
use anyhow::bail;
use anyhow::Result;

// Extracts the URI refs inside the srcset attribute, for instance 'imagesrcset' on <link>, per
// https://html.spec.whatwg.org/multipage/semantics.html#attr-link-imagesrcset. Descriptors are
// discarded; not needed for our use case.
#[cfg(feature = "srcset")]
pub fn parse(mut input: &str) -> Result<Vec<&str>> {
    // Parsing is done imperatively rather than using nom for two reasons:
    // 1. It's defined imperatively at
    //    https://html.spec.whatwg.org/multipage/images.html#parsing-a-srcset-attribute:srcset-attribute,
    //    so it's easier to compare implementation to spec this way.
    // 2. There are things that are difficult to do in nom, like the comma backtracking and the
    //    splitting on commas except in (non-matched) parens.
    let mut candidates = vec![];
    loop {
        const WHITESPACE: &[char] = &['\t', '\r', '\x0C', '\n', ' '];
        const WHITESPACE_OR_COMMA: &[char] = &['\t', '\r', '\x0C', '\n', ' ', ','];
        input = input.trim_start_matches(WHITESPACE_OR_COMMA);
        if input.is_empty() {
            return Ok(candidates);
        }
        let (mut url, remaining) = input.split_at(input.find(WHITESPACE).unwrap_or(input.len()));
        input = remaining;
        let len_before_trim = url.len();
        url = url.trim_end_matches(',');
        let commas_trimmed = len_before_trim - url.len();
        if commas_trimmed > 0 {
            if commas_trimmed > 1 {
                bail!("Ambiguous comma at end of URL in srcset");
            }
        } else {
            input = input.trim_start_matches(WHITESPACE);
            // A simplification of step 8, since descriptors are discarded. Look for the first comma not
            // inside parens:
            let mut in_parens = false;
            input = input.trim_start_matches(|c| match c {
                '(' => {
                    in_parens = true;
                    true
                }
                ')' => {
                    in_parens = false;
                    true
                }
                ',' => in_parens, // Stop on comma outside of parens.
                _ => true,
            });
            // The found comma will be trimmed at the beginning of the next iteration.
        }
        // There are additional steps for validating the descriptors. This is skipped for
        // simplicity, so this parser may extract more URI refs than a fully compliant one.
        candidates.push(url);
    }
}

#[cfg(not(feature = "srcset"))]
pub fn parse(_input: &str) -> Result<Vec<&str>> {
    Ok(vec![])
}

#[cfg(all(test, feature = "srcset"))]
mod tests {
    use super::*;
    #[test]
    fn srcset() {
        assert_eq!(
            parse("elva-fairy-480w.jpg 480w, elva-fairy-800w.jpg 800w").unwrap(),
            vec!["elva-fairy-480w.jpg", "elva-fairy-800w.jpg"]
        );
        assert_eq!(
            parse("elva-fairy-320w.jpg, elva-fairy-480w.jpg 1.5x, elva-fairy-640w.jpg 2x").unwrap(),
            vec![
                "elva-fairy-320w.jpg",
                "elva-fairy-480w.jpg",
                "elva-fairy-640w.jpg"
            ]
        );
        assert_eq!(parse("elva-800w.jpg").unwrap(), vec!["elva-800w.jpg"]);
        assert_eq!(
            parse("url,with,comma.jpg 400w, other,url,with,comma.jpg, third,url.jpg").unwrap(),
            vec![
                "url,with,comma.jpg",
                "other,url,with,comma.jpg",
                "third,url.jpg"
            ]
        );
        assert_eq!(
            parse("hypothetical-comma-in-parens.jpg (400w, 500h), other.jpg").unwrap(),
            vec!["hypothetical-comma-in-parens.jpg", "other.jpg"]
        );
        assert!(matches!(parse("too,many,trailing,commas,,"), Err(_)));
    }
}
