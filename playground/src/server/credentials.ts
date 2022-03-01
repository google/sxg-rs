import childProcess from 'child_process';
import crypto from 'crypto';
import {
    promises as fs,
} from 'fs';
import os from 'os';
import path from 'path';
import util from 'util';

const execFile = util.promisify(childProcess.execFile);

export async function createSelfSignedCredentials(domain: string) {
    const certDir = await fs.mkdtemp(path.join(os.tmpdir(), 'sxg-cert-'));
    const {
        stdout: privateKeyPem,
    } = await execFile(
        'openssl',
        ['ecparam', '-outform', 'pem', '-name', 'prime256v1', '-genkey'],
    );
    const privateKeyFile = path.join(certDir, 'privkey.pem');
    await fs.writeFile(privateKeyFile, privateKeyPem);
    const privateKeyJwk = crypto.createPrivateKey(privateKeyPem)
        .export({format: 'jwk'});
    const certificateRequestFile = path.join(certDir, 'csr.pem');
    const {
        stdout: certificateRequestPem,
    } = await execFile(
        'openssl',
        ['req', '-new', '-sha256', '-key', privateKeyFile, '-subj', `/CN=${domain}/OTest/C=US`],
    );
    await fs.writeFile(certificateRequestFile, certificateRequestPem);
    const certificateExtensionFile = path.join(certDir, 'ext.txt');
    await fs.writeFile(
        certificateExtensionFile, 
        `1.3.6.1.4.1.11129.2.1.22 = ASN1:NULL\nsubjectAltName=DNS:${domain}`,
    );
    const certificateFile = path.join(certDir, 'certificate.pem');
    const {
        stdout: certificatePem,
    } = await execFile(
        'openssl',
        [
            'x509', '-req',
            '-days', '90',
            '-in', certificateRequestFile,
            '-signkey', privateKeyFile,
            '-extfile', certificateExtensionFile,
        ],
    );
    await fs.writeFile(certificateFile, certificatePem);
    const {
        stdout: publicKeyPem,
    } = await execFile(
        'openssl',
        ['x509', '-pubkey', '-noout', '-in', certificateFile],
    );
    const publicKeyDer = crypto.createPublicKey(publicKeyPem)
        .export({format: 'der', type: 'spki'});
    const publicKeyHash = crypto.createHash('sha256')
        .update(publicKeyDer).digest('base64');
    return {
        certificatePem,
        privateKeyPem,
        privateKeyJwk,
        publicKeyHash,
    }
}
