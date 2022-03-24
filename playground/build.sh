node_modules/.bin/esbuild src/index.ts --bundle --external:puppeteer --platform=node --outfile=dist/tmp.js
cat ../cloudflare_worker/pkg/cloudflare_worker.js dist/tmp.js > dist/index.js
