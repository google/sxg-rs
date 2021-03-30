addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function fetchLibsxgTestdata(filename) {
  const TESTDATA_DIR = 'https://raw.githubusercontent.com/google/libsxg/master/tests/testdata/';
  const response = await fetch(`${TESTDATA_DIR}/${filename}`);
  const text = await response.text();
  return text;
}

function acceptsSxg(request) {
  const accept = request.headers.get('accept') ?? '';
  return accept.includes('application/signed-exchange');
}

/**
 * Fetch and log a request
 * @param {Request} request
 */
async function handleRequest(request) {
  const url = new URL(request.url);
  if (url.pathname === "/validity") {
    return new Response(
      new UInt8Array([96]),
      {
        status: 200,
        headers: {
        },
      },
    );
  }
  const {
    createCertCbor,
    createSignedExchange,
  } = wasm_bindgen;
  const [
    certString,
    privateKeyString,
  ] = await Promise.all([
    fetchLibsxgTestdata('cert256.pem'),
    fetchLibsxgTestdata('priv256.key'),
    wasm_bindgen(wasm),
  ]);
  if (url.pathname === "/cert") {
    return new Response(
      createCertCbor(certString),
      {
        status: 200,
        headers: {
          'content-type': 'application/cert-chain+cbor',
        },
      },
    );
  }
  if (!acceptsSxg(request)) {
    return new Response(
        `This is not SXG`,
        {
          status: 200,
          headers: {
            'content-type': 'text/html;charset=UTF-8',
          },
        },
    );
  }
  // This is the private key inside https://raw.githubusercontent.com/google/libsxg/master/tests/testdata/priv256.key
  // TODO add code to parse pem file
  const privateKeyBase64 = 'szcbp4ROOkiX22BTLNKvFpW8ssRPayfzmlfwbDG52ZE=';
  const sxg = createSignedExchange(request.url, `This is SXG.`, certString, privateKeyBase64, Math.round(Date.now() / 1000));
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
