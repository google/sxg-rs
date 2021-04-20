addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

function acceptsSxg(request) {
  const accept = request.headers.get('accept') ?? '';
  return accept.includes('application/signed-exchange');
}

function cloneUrlWith(urlString, mutate) {
  const url = new URL(urlString);
  mutate(url);
  return url.href;
}

const HARMFUL_HEADER = [
    "authentication-control",
    "authentication-info",
    "clear-site-data",
    "connection",
    "keep-alive",
    "optional-www-authenticate",
    "proxy-authenticate",
    "proxy-authentication-info",
    "proxy-connection",
    "public-key-pins",
    "sec-websocket-accept",
    "set-cookie",
    "set-cookie2",
    "setprofile",
    "strict-transport-security",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "variant-key-04",
    "variants-04",
    "www-authenticate",
];

async function myFetch(url) {
  const response = await fetch(url);
  const headers = Array.from(response.headers).filter((entry) => {
    const key = entry[0];
    return !HARMFUL_HEADER.includes(key) &&
        !key.startsWith('cf-');
  });
  return {
    body: await response.text(),
    headers,
    statusCode: response.status,
  };
}

/**
 * Fetch and log a request
 * @param {Request} request
 */
async function handleRequest(request) {
  const requestUrl = request.url;
  const certUrl = cloneUrlWith(requestUrl, u => u.pathname = '/.sxg_cert');
  const fallbackUrl = cloneUrlWith(requestUrl, u => u.host = HOST);
  const validityUrl = cloneUrlWith(fallbackUrl, u => u.pathname = '/.sxg_validity');
  if (requestUrl === validityUrl) {
    return new Response(
      new UInt8Array([96]),
      {
        status: 200,
      },
    );
  }
  const {
    createCertCbor,
    createSignedExchange,
  } = wasm_bindgen;
  await wasm_bindgen(wasm);
  if (requestUrl === certUrl) {
    return new Response(
      createCertCbor(),
      {
        status: 200,
        headers: {
          'content-type': 'application/cert-chain+cbor',
        },
      },
    );
  }
  if (!acceptsSxg(request)) {
    return Response.redirect(fallbackUrl, 302);
  }
  const {
    body: payloadBody,
    headers: payloadHeaders,
    statusCode: payloadStatusCode,
  } = await myFetch(fallbackUrl);
  const sxg = createSignedExchange(
    certUrl,
    validityUrl,
    fallbackUrl,
    payloadStatusCode,
    payloadHeaders,
    payloadBody,
    Math.round(Date.now() / 1000 - 60 * 60 * 12),
  );
  return new Response(
      sxg,
      {
        status: 200,
        headers: {
          'Content-Type': 'application/signed-exchange;v=b3',
          'X-Content-Type-Options': 'nosniff',
        },
      },
  );
}
