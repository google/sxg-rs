set -e
node_modules/.bin/esbuild src/*.test.ts --bundle --platform=browser --outdir=dist
