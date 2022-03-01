import puppeteer from 'puppeteer';

export async function startClient({
    certificateSpki,
    url,
}: {
    certificateSpki: string,
    url: string,
}) {
    const browser = await puppeteer.launch({
        devtools: true,
        args: [
            `--ignore-certificate-errors-spki-list=${certificateSpki}`,
        ],
    });
    const page = (await browser.pages())[0]!;

    const slow3g = puppeteer.networkConditions['Slow 3G']!;
    const cdpSession = await page.target().createCDPSession()
    await cdpSession.send('Network.emulateNetworkConditions', {
        offline: false,
        downloadThroughput: slow3g.download,
        uploadThroughput: slow3g.upload,
        latency: slow3g.latency,
    });

    await page.goto(`https://localhost:8443/srp/${encodeURIComponent(url)}`);
}
