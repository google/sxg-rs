export type Signer = (message: Uint8Array) => Promise<Uint8Array>;

export function fromJwk(subtle: any, jwk: Object): Signer {
    const privateKeyPromise = (async function initPrivateKey() {
        return await subtle.importKey(
            "jwk",
            jwk,
            {
                name: "ECDSA",
                namedCurve: 'P-256',
            },
            /*extractable=*/false,
            ['sign'],
        );
    })();
    return async function signer(message: Uint8Array): Promise<Uint8Array> {
        const privateKey = await privateKeyPromise;
        const signature = await subtle.sign(
            {
                name: "ECDSA",
                hash: 'SHA-256',
            },
            privateKey,
            message,
        );
        return new Uint8Array(signature);
    }
}
