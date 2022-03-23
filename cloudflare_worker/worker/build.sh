node_modules/.bin/esbuild src/index.ts --bundle --platform=browser --outfile=dist/index.js
node_modules/.bin/esbuild src/streams.test.ts --bundle --platform=browser --outfile=dist/streams.test.js
node_modules/.bin/esbuild src/utils.test.ts --bundle --platform=browser --outfile=dist/utils.test.js
