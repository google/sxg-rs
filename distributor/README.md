# SXG distributor

This is an example SXG distributor that could be used for privacy-preserving
prefetching. If an HTTP caching layer is put in front, the result would be
similar to webpkgcache.com.

This is early experimental code, useful only as a demo so far.

It's coded as an https server, but it's stateless so it could easily be ported
to a serverless architecture.

## Instructions

### Launch the distributor
```bash
$ openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes -subj '/CN=localhost'
$ cargo run -p distributor -- --origin https://localhost:8080 --user-agent Test --cert cert.pem --key key.pem &
```

### Launch the prefetching referrer
```bash
$ cd distributor
$ wget https://raw.githubusercontent.com/instantpage/instant.page/v5.1.1/instantpage.js
$ patch instantpage.js instantpage.js.patch
$ python3 -m http.server &
```

### Launch the test browser
```bash
$ google-chrome --user-data-dir=/tmp/udd --ignore-certificate-errors-spki-list=$(openssl x509 -pubkey -noout -in cert.pem | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64) https://localhost:8000/example.html &
```

Open the DevTools Network tab to see how, on hoverm cross-origin links are prefetched from the distributor.
