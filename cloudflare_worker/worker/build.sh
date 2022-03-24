set -e
node_modules/.bin/tsc --noEmit
node_modules/.bin/esbuild src/index.ts --bundle --platform=browser --outfile=dist/index.js
