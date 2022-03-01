import assert from 'assert';
import {
    createSelfSignedCredentials,
} from './server/credentials';

import {
    startClient,
} from './client/';
import {
    startSxgServer,
} from './server/';

async function main() {
    const url = process.argv[2];
    assert(url, 'Please specify URL as CLI argument');
    const {
        certificatePem,
        privateKeyJwk,
        privateKeyPem,
        publicKeyHash,
    } = await createSelfSignedCredentials((new URL(url)).hostname);
    await startSxgServer({
        certificatePem,
        privateKeyJwk,
        privateKeyPem,
    });
    await startClient({
        url,
        certificateSpki: publicKeyHash,
    });
}

main().catch(e => console.error(e));
