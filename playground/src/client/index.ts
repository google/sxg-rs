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
    await page.goto(`https://localhost:8443/srp/${encodeURIComponent(url)}`);
}
