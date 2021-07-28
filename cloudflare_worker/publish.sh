#!/bin/bash

set -e;

cd worker
npm install
npm run build
cp dist/index.js worker.js
cd ..

wrangler publish
