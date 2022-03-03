/**
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import fs from 'fs';
import module from 'module';
import path from 'path';

import commonjs from '@rollup/plugin-commonjs';
import json from '@rollup/plugin-json';
import { nodeResolve } from '@rollup/plugin-node-resolve';
import typescript from '@rollup/plugin-typescript';

import pkg from './package.json';

const sxgRsBinary = fs.readFileSync(path.resolve(__dirname, '..', 'cloudflare_worker', 'pkg', 'cloudflare_worker.js'));

export default [
  {
    input: 'src/index.ts',
    output: {
      banner: sxgRsBinary,
      dir: 'dist',
      format: 'commonjs',
    },
    plugins: [
      typescript(),
      json(),
      nodeResolve({
        preferBuiltins: true,
      }),
      commonjs(),
    ],
    preserveEntrySignatures: false,
    external: [
      ...module.builtinModules.map(x => `node:${x}`),
      ...Object.keys(pkg.dependencies),
    ],
  },
];
