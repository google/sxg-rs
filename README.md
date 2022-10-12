<!--
Copyright 2021 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# sxg-rs

sxg-rs is a set of tools for generating [signed
exchanges](https://web.dev/signed-exchanges/) at serve time:

  * [`cloudflare_worker`](cloudflare_worker) runs on [Cloudflare Workers](https://workers.cloudflare.com/).
  * [`distributor`](distributor) is an example implementation of privacy-preserving SXG prefetch of outlinks.
  * [`fastly_compute`](fastly_compute) runs on [Fastly Compute@Edge](https://www.fastly.com/products/edge-compute/serverless).
  * [`http_server`](http_server) runs as an HTTP reverse-proxy on Linux.
  * [`playground`](playground) is a CLI for previewing LCP impact of SXG on any site.
  * [`sxg_rs`](sxg_rs) is the Rust library that can be used as a basis for other serverless platforms.

These tools enable sites to be [prefetched from Google
Search](https://developers.google.com/search/docs/advanced/experience/signed-exchange)
in order to improve their [Largest Contentful Paint](https://web.dev/lcp/), one
of the [Core Web Vitals](https://web.dev/vitals/).

For other technology stacks, see [this list of SXG tools](https://web.dev/signed-exchanges/#tooling).

## Next steps

After installing, take the following steps.

### Verify and monitor

After installing, you may want to
[verify](https://developers.google.com/search/docs/advanced/experience/signed-exchange#verify-sxg-setup)
and
[monitor](https://developers.google.com/search/docs/advanced/experience/signed-exchange#monitor-and-debug-sxg)
the results.

### HTML processing

The worker contains some HTML processors. To activate them, explicitly label the character encoding as UTF-8, either via:

```http
Content-Type: text/html;charset=utf-8
```

or via:

```html
<meta charset=utf-8>
```

#### Preload subresources

LCP can be further improved by instructing Google Search to prefetch
render-critical subresources for the page.

##### Same-origin

Add a preload link tag to the page, such as:

```
<link rel=preload as=image href="/foo.png">
```

sxg-rs will automatically convert these link tags into Link headers as needed for [SXG
subresource
substitution](https://github.com/WICG/webpackage/blob/main/explainers/signed-exchange-subresource-substitution.md).
This uses a form of subresource integrity that includes HTTP headers. sxg-rs
tries to ensure a static integrity value by stripping many noisy HTTP headers
(like Date) for signed subresources, but you may need to list additional ones
in the `strip_response_headers` config param.

To confirm it is working, run:

```bash
$ go install github.com/WICG/webpackage/go/signedexchange/cmd/dump-signedexchange@latest
$ dump-signedexchange -uri "$HTML_URL" -payload=false | grep Link
```

and verify that there is a `rel=allowed-alt-sxg` whose `header-integrity`
matches the output of:

```bash
$ dump-signedexchange -uri "$SUBRESOURCE_URL" -headerIntegrity
```

If you have any same-origin preload tags that should not be converted into
headers, add the `data-sxg-no-header` attribute to them.

##### Cross-origin

SXG preloading requires that the subresource is also an SXG. This worker
assumes only same-origin resources are SXG, so its automatic logic is limited
to those. You can manually support cross-origin subresources by adding the
appropriate Link header as
[specified](https://github.com/WICG/webpackage/blob/main/explainers/signed-exchange-subresource-substitution.md).

#### SXG-only behavior

There are two syntaxes for behavior that happens only when the page is viewed
as an SXG. If you write:

```html
<script data-issxg-var>window.isSXG=false</script>
```

then its inner content will be replaced by `window.isSXG=true` in an SXG. This
could be used as a custom dimension by which to slice web analytics, or as a
cue to fetch a fresh CSRF token.

If you write:

```html
<template data-sxg-only>...</template>
```

then in an SXG, its inner content will be "unwrapped" out of the template and
thus activated, and when non-SXG it will be deleted. Since SXGs can't Vary by
Cookie, this could be used to add lazy-loaded personalization to the SXG, while
not adding unnecesary bytes to the non-SXG. It could also be used to add
SXG-only subresource preloads.

### Preview in Chrome

Optionally, preview the results in the browser:

 - In development, set Chrome flags to [allow the
   certificate](https://github.com/google/webpackager/tree/main/cmd/webpkgserver#testing-with-self-signed--invalid-certificates).
 - Use an extension such as
   [ModHeader](https://chrome.google.com/webstore/detail/modheader/idgpnmonknjnojddfkpgkljpfnnfcklj)
   to set the `Accept` header to
   `text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3`
   (equivalent to what Googlebot sends).
 - Explore the results [in the DevTools Network tab](https://web.dev/signed-exchanges/#debugging).
