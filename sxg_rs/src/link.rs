use crate::header_integrity::HeaderIntegrityFetcher;
use crate::http_parser::{link::Link, parse_link_header, srcset};
use futures::{stream, stream::StreamExt};
use once_cell::sync::Lazy;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::iter::once;
use std::sync::Mutex;
use url::{Origin, Url};

// Filters the link header to comply with
// https://github.com/google/webpackager/blob/main/docs/cache_requirements.md,
// and adds allowed-alt-sxg with header-integrity if not present.
pub(crate) async fn process_link_header(
    value: &str,
    fallback_url: &Url,
    header_integrity_fetcher: &mut dyn HeaderIntegrityFetcher,
) -> String {
    let links = match parse_link_header(value) {
        Ok(links) => links,
        Err(_) => {
            return "".into();
        }
    };

    let (preloads, allowed_alt_sxgs) = preloads_and_allowed_alt_sxgs(links, fallback_url);

    let fallback_origin = fallback_url.origin();
    let directives = Mutex::new(vec![]);
    stream::iter(preloads)
        .for_each_concurrent(None, |link| async {
            let link = link;
            let srcset = get_param(&link.params, "imagesrcset");
            let images = match &srcset {
                Some(srcset) => srcset::parse(srcset).unwrap_or_default(),
                None => vec![],
            };
            // Convert image hrefs from srcset to absolute, for comparison with
            // allowed_alt_sxgs.
            let images = images
                .iter()
                .filter_map(|url| fallback_url.join(url).ok().map(String::from));

            // Collect allowed-alt-sxg directives for all URLs referred to by this preload.
            // We will only output the preload if all of them can be found or computed.
            let mut allow_directives = vec![];
            let mut all_allow_sxg = true;

            // Iterate over all URLs referred to by this preload.
            // TODO: Make these concurrent also. (Not critical because imagesrcset is rare.)
            let urls = once(link.uri.clone()).chain(images);
            for url in urls {
                let mut allow_sxg = false;
                match allowed_alt_sxgs.get(&url) {
                    Some(allowed_alt_sxg) => {
                        allow_directives.push(allowed_alt_sxg.clone());
                        allow_sxg = true;
                    }
                    None => {
                        // Fetch and compute header-integrity only for same-origin preloads.
                        // Cross-origin preloads are assumed unlikely to be SXG.
                        if origin_is(&fallback_origin, &url) {
                            if let Ok(integrity) = header_integrity_fetcher.fetch(&url).await {
                                allow_directives.push(Link {
                                    uri: url,
                                    params: vec![
                                        (Cow::Borrowed("rel"), Some("allowed-alt-sxg".into())),
                                        (Cow::Borrowed("header-integrity"), Some(integrity)),
                                    ],
                                });
                                allow_sxg = true;
                            }
                        }
                    }
                };
                if !allow_sxg {
                    all_allow_sxg = false;
                    break;
                }
            }

            // If all allowed-alt-sxg directives were found, output the preload and allow
            // directives.
            if all_allow_sxg {
                if let Ok(mut directives) = directives.try_lock() {
                    directives.push(link.clone());
                    directives.extend_from_slice(&allow_directives);
                }
            }
        })
        .await;
    directives
        .into_inner()
        .unwrap_or_default()
        .iter()
        .map(|link| link.serialize())
        .collect::<Vec<String>>()
        .join(",")
}

// Attributes allowed on Link headers by
// https://github.com/google/webpackager/blob/main/docs/cache_requirements.md.
pub static ALLOWED_PARAM_NAMES: Lazy<HashSet<&'static str>> = Lazy::new(|| {
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

// Filters the given Link header to only the allowed preload and allowed-alt-sxg directives.
// Converts URLs to absolute, given fallback_url as base href. Returns the allowed-alt-sxgs as a
// HashMap for convenient lookup by URL.
fn preloads_and_allowed_alt_sxgs<'a>(
    links: Vec<Link<'a>>,
    fallback_url: &Url,
) -> (Vec<Link<'a>>, HashMap<String, Link<'a>>) {
    static ALLOWED_REL: Lazy<HashSet<&'static str>> =
        Lazy::new(|| vec!["preload", "allowed-alt-sxg"].into_iter().collect());
    static ALLOWED_CROSSORIGIN: Lazy<HashSet<&'static str>> =
        Lazy::new(|| vec!["", "anonymous"].into_iter().collect());
    let links = links.into_iter().filter(|link| {
        link.params.iter().all(|(k, v)| {
            ALLOWED_PARAM_NAMES.contains(k.as_ref())
                && match k.as_ref() {
                    "rel" => matches!(v, Some(v) if ALLOWED_REL.contains(v.as_str())),
                    "crossorigin" => {
                        matches!(v, Some(v) if ALLOWED_CROSSORIGIN.contains(v.as_str()))
                    }
                    _ => true,
                }
        })
    });

    let (mut preloads, allowed_alt_sxgs) = links
        .filter_map(|link| {
            let uri: String = fallback_url.join(&link.uri).ok()?.into();
            match get_param(&link.params, "rel") {
                Some(rel) if ALLOWED_REL.contains(rel.as_str()) => {
                    Some((rel == "preload", Link { uri, ..link }))
                }
                _ => None,
            }
        })
        .partition::<Vec<(bool, Link)>, _>(|(is_preload, _)| *is_preload);
    preloads.truncate(20);

    let preloads: Vec<Link> = preloads.into_iter().map(|(_, link)| link).collect();
    let allowed_alt_sxgs: HashMap<String, Link> = allowed_alt_sxgs
        .into_iter()
        .map(|(_, link)| (link.uri.clone(), link))
        .collect();
    (preloads, allowed_alt_sxgs)
}

fn get_param(params: &[(Cow<'_, str>, Option<String>)], name: &str) -> Option<String> {
    let values: Vec<&Option<String>> = params
        .iter()
        .filter(|(k, _)| *k == name)
        .map(|(_, v)| v)
        .collect();
    if values.len() == 1 {
        values[0].clone()
    } else {
        None
    }
}

fn origin_is(origin: &Origin, uri: &str) -> bool {
    Url::parse(uri).map_or(false, |u| &u.origin() == origin)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header_integrity::tests::null_integrity_fetcher;
    use anyhow::{anyhow, Result};
    use async_trait::async_trait;

    struct FakeIntegrityFetcher(std::result::Result<String, String>);

    #[cfg_attr(feature = "wasm", async_trait(?Send))]
    #[cfg_attr(not(feature = "wasm"), async_trait)]
    impl HeaderIntegrityFetcher for FakeIntegrityFetcher {
        async fn fetch(&self, _url: &str) -> Result<String> {
            self.0.clone().map_err(|e| anyhow!(e))
        }
    }

    #[tokio::test]
    async fn sanitizes_preloads() {
        let url = Url::parse("https://foo.com").unwrap();
        assert_eq!(
            process_link_header(
                r#"<https://foo.com/> ; rel = "preload",</>;rel=allowed-alt-sxg;header-integrity=blah"#,
                &url,
                &mut null_integrity_fetcher()
            )
            .await,
            "<https://foo.com/>;rel=preload,<https://foo.com/>;rel=allowed-alt-sxg;header-integrity=blah"
        );

        let preloads: Vec<String> = (0..21)
            .map(|n| format!("<https://foo.com/{}.js>;rel=preload", n))
            .collect();
        assert_eq!(
            process_link_header(&preloads.join(","), &url, &mut null_integrity_fetcher()).await,
            ""
        );
        let allowed_alt_sxgs: Vec<String> = (0..20).map(|n|
            format!(r#"<https://foo.com/{}.js>;rel=allowed-alt-sxg;header-integrity="sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=""#, n)).collect();
        let preloads_mixed: Vec<String> = preloads
            .iter()
            .zip(allowed_alt_sxgs)
            .map(|(preload, allowed_alt_sxg)| preload.to_string() + "," + &allowed_alt_sxg)
            .collect();
        assert_eq!(
            process_link_header(
                &preloads_mixed.join(","),
                &url,
                &mut null_integrity_fetcher()
            )
            .await,
            preloads_mixed.join(",")
        );

        assert_eq!(
            process_link_header("</foo>;rel=preload,<https://foo.com/foo>;rel=allowed-alt-sxg;header-integrity=blah", &url, &mut null_integrity_fetcher()).await,
            "<https://foo.com/foo>;rel=preload,<https://foo.com/foo>;rel=allowed-alt-sxg;header-integrity=blah"
        );
        assert_eq!(
            process_link_header(
                "<../quux>;rel=preload,<../quux>;rel=allowed-alt-sxg;header-integrity=blah",
                &url.join("/bar/baz/").unwrap(),
                &mut null_integrity_fetcher()
            )
            .await,
            "<https://foo.com/bar/quux>;rel=preload,<https://foo.com/bar/quux>;rel=allowed-alt-sxg;header-integrity=blah"
        );
        assert_eq!(
            process_link_header(
                "<https://foo.com/>;rel=prefetch,<https://foo.com/>;rel=allowed-alt-sxg;header-integrity=blah",
                &url,
                &mut null_integrity_fetcher()
            )
            .await,
            ""
        );
        assert_eq!(
            process_link_header("</foo>", &url, &mut null_integrity_fetcher()).await,
            ""
        );
        assert_eq!(
            process_link_header(
                "<https://foo.com/>;other",
                &url,
                &mut null_integrity_fetcher()
            )
            .await,
            ""
        );
        assert_eq!(
            process_link_header(
                "<https://foo.com/>;rel=preload,<https://foo.com/>;rel=prefetch,<https://foo.com/>;rel=allowed-alt-sxg;header-integrity=blah",
                &url,
                &mut null_integrity_fetcher()
            )
            .await,
            "<https://foo.com/>;rel=preload,<https://foo.com/>;rel=allowed-alt-sxg;header-integrity=blah"
        );
    }

    #[cfg(feature = "srcset")]
    #[tokio::test]
    async fn imagesrcset() {
        let url = Url::parse("https://foo.com").unwrap();
        assert_eq!(
            process_link_header(
                r#"<img.jpg>;rel=preload;as=image;imagesizes=800px;imagesrcset="img2.jpg 800w",<img.jpg>;rel=allowed-alt-sxg;header-integrity=blah"#,
                &url,
                &mut null_integrity_fetcher()
            )
            .await,
            ""
        );
        assert_eq!(
            process_link_header(
                "<img.jpg>;rel=preload;as=image;imagesizes=800px;imagesrcset=\"img2.jpg 800w, img3.jpg\",\
                 <img.jpg>;rel=allowed-alt-sxg;header-integrity=blah,\
                 <img2.jpg>;rel=allowed-alt-sxg;header-integrity=blah2,\
                 <img3.jpg>;rel=allowed-alt-sxg;header-integrity=blah3",
                &url,
                &mut null_integrity_fetcher()
            )
            .await,
            "<https://foo.com/img.jpg>;rel=preload;as=image;imagesizes=800px;imagesrcset=\"img2.jpg 800w, img3.jpg\",\
             <https://foo.com/img.jpg>;rel=allowed-alt-sxg;header-integrity=blah,\
             <https://foo.com/img2.jpg>;rel=allowed-alt-sxg;header-integrity=blah2,\
             <https://foo.com/img3.jpg>;rel=allowed-alt-sxg;header-integrity=blah3"
        );
        let mut fetcher = FakeIntegrityFetcher(Ok("sha256-blah".into()));
        assert_eq!(
            process_link_header(
                "<img.jpg>;rel=preload;as=image;imagesizes=800px;imagesrcset=\"img2.jpg 800w, img3.jpg\"",
                &url,
                &mut fetcher,
            )
            .await,
            "<https://foo.com/img.jpg>;rel=preload;as=image;imagesizes=800px;imagesrcset=\"img2.jpg 800w, img3.jpg\",\
             <https://foo.com/img.jpg>;rel=allowed-alt-sxg;header-integrity=sha256-blah,\
             <https://foo.com/img2.jpg>;rel=allowed-alt-sxg;header-integrity=sha256-blah,\
             <https://foo.com/img3.jpg>;rel=allowed-alt-sxg;header-integrity=sha256-blah"
        );
    }

    #[tokio::test]
    async fn fetch_header_integrity_ok() {
        let mut fetcher = FakeIntegrityFetcher(Ok(
            "sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=".into(),
        ));
        let url = Url::parse("https://foo.com").unwrap();
        assert_eq!(
            process_link_header("</>;rel=preload", &url, &mut fetcher).await,
            r#"<https://foo.com/>;rel=preload,<https://foo.com/>;rel=allowed-alt-sxg;header-integrity="sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=""#
        );
        assert_eq!(process_link_header(r#"</>;rel=preload,</>;rel=allowed-alt-sxg;header-integrity="sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=""#,
        &url, &mut fetcher).await,
                   r#"<https://foo.com/>;rel=preload,<https://foo.com/>;rel=allowed-alt-sxg;header-integrity="sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=""#);
        assert_eq!(process_link_header(r#"</>;rel=preload,<https://foo.com/>;rel=allowed-alt-sxg;header-integrity="sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=""#,
        &url, &mut fetcher).await,
                   r#"<https://foo.com/>;rel=preload,<https://foo.com/>;rel=allowed-alt-sxg;header-integrity="sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=""#);
    }

    #[tokio::test]
    async fn fetch_header_integrity_multiple() {
        let mut fetcher = FakeIntegrityFetcher(Ok(
            "sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=".into(),
        ));
        let url = Url::parse("https://foo.com").unwrap();
        assert_eq!(
            process_link_header("</a>;rel=preload,</b>;rel=preload", &url, &mut fetcher).await,
            concat!(
                r#"<https://foo.com/a>;rel=preload,<https://foo.com/a>;rel=allowed-alt-sxg;header-integrity="sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=","#,
                r#"<https://foo.com/b>;rel=preload,<https://foo.com/b>;rel=allowed-alt-sxg;header-integrity="sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=""#
            ),
        );
    }

    #[tokio::test]
    async fn fetch_header_integrity_out_of_order() {
        use crate::utils::tests::{out_of_order, OutOfOrderState};
        use futures::future::BoxFuture;
        struct OutOfOrderFetcher<F: Fn() -> BoxFuture<'static, Result<String>> + Send + Sync>(F);
        #[cfg_attr(feature = "wasm", async_trait(?Send))]
        #[cfg_attr(not(feature = "wasm"), async_trait)]
        impl<F: Fn() -> BoxFuture<'static, Result<String>> + Send + Sync> HeaderIntegrityFetcher
            for OutOfOrderFetcher<F>
        {
            async fn fetch(&self, url: &str) -> Result<String> {
                println!("url = {}", url);
                self.0().await
            }
        }
        let state = OutOfOrderState::new();
        let mut fetcher = OutOfOrderFetcher(|| {
            out_of_order(state.clone(), || {
                Ok("sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=".into())
            })
        });
        let url = Url::parse("https://foo.com").unwrap();
        assert_eq!(
            process_link_header("</a>;rel=preload,</b>;rel=preload", &url, &mut fetcher).await,
            concat!(
                r#"<https://foo.com/b>;rel=preload,<https://foo.com/b>;rel=allowed-alt-sxg;header-integrity="sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=","#,
                r#"<https://foo.com/a>;rel=preload,"#,
                r#"<https://foo.com/a>;rel=allowed-alt-sxg;header-integrity="sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=""#
            ),
        );
    }

    #[tokio::test]
    async fn fetch_header_integrity_ok_none() {
        let mut fetcher = FakeIntegrityFetcher(Err("some error".into()));
        let url = Url::parse("https://foo.com").unwrap();
        assert_eq!(
            process_link_header("</>;rel=preload", &url, &mut fetcher).await,
            ""
        );
        assert_eq!(process_link_header(r#"</>;rel=preload,</>;rel=allowed-alt-sxg;header-integrity="sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=""#,
        &url, &mut fetcher).await,
                   r#"<https://foo.com/>;rel=preload,<https://foo.com/>;rel=allowed-alt-sxg;header-integrity="sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=""#);
        assert_eq!(process_link_header(r#"</>;rel=preload,<https://foo.com/>;rel=allowed-alt-sxg;header-integrity="sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=""#,
        &url, &mut fetcher).await,
                   r#"<https://foo.com/>;rel=preload,<https://foo.com/>;rel=allowed-alt-sxg;header-integrity="sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=""#);
    }
}
