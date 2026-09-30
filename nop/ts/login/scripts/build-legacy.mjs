// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const loginRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const defaultOutDir = path.resolve(loginRoot, '../../builtin/login-dev');
const outDir = process.env.LOGIN_SPA_OUT_DIR
  ? path.resolve(process.env.LOGIN_SPA_OUT_DIR)
  : defaultOutDir;

async function listLoginScripts() {
  const entries = await fs.readdir(outDir, { withFileTypes: true });
  return entries
    .filter((entry) => entry.isFile() && /^login(?:-|\.js$)/.test(entry.name) && entry.name.endsWith('.js'))
    .map((entry) => path.join(outDir, entry.name))
    .sort();
}

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: loginRoot,
    encoding: 'utf8',
    stdio: 'inherit'
  });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} failed with status ${result.status}`);
  }
}

const scripts = await listLoginScripts();
if (scripts.length === 0) {
  throw new Error(`No login JavaScript files found in ${outDir}`);
}

for (const script of scripts) {
  run('npx', [
    'babel',
    script,
    '--out-file',
    script,
    '--config-file',
    './babel.legacy.config.cjs',
    '--compact',
    'true'
  ]);
  run('npx', [
    'terser',
    script,
    '--compress',
    'ecma=2019',
    '--mangle',
    '--format',
    'ecma=2019,comments=false',
    '-o',
    script
  ]);
}
