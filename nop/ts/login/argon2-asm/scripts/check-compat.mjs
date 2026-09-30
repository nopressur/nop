// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
import { spawnFile } from './process.mjs';

const loginRoot = path.resolve(import.meta.dirname, '../..');
const artifactPath = path.join(loginRoot, 'argon2-asm/dist/argon2id.asm.js');
const manifestPath = path.join(loginRoot, 'argon2-asm/argon2id.asm.manifest.json');
const source = fs.readFileSync(artifactPath, 'utf8');

function sha256(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function checkManifest() {
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const packageLock = JSON.parse(fs.readFileSync(path.join(loginRoot, 'package-lock.json'), 'utf8'));
  const hashWasm = packageLock.packages?.['node_modules/hash-wasm'];
  const manifestArtifactPath = path.join(loginRoot, 'argon2-asm', manifest.artifact);

  if (path.resolve(manifestArtifactPath) !== artifactPath) {
    throw new Error('Manifest artifact path does not point at dist/argon2id.asm.js.');
  }
  if (manifest.artifactSha256 !== sha256(artifactPath)) {
    throw new Error('Manifest artifact SHA-256 does not match dist/argon2id.asm.js.');
  }
  if (!hashWasm || manifest.upstream.version !== hashWasm.version || manifest.upstream.integrity !== hashWasm.integrity) {
    throw new Error('Manifest hash-wasm metadata does not match package-lock.json.');
  }
  for (const input of manifest.inputs) {
    const inputPath = path.join(loginRoot, input.path);
    if (input.sha256 !== sha256(inputPath)) {
      throw new Error(`Manifest input SHA-256 does not match ${input.path}.`);
    }
  }
}

const banned = [
  ['WebAssembly runtime dependency', /\bWebAssembly\b/],
  ['BigInt runtime dependency', /\bBigInt\b/],
  ['Proxy runtime dependency', /\bProxy\b/],
  ['Promise runtime dependency', /\bPromise\b/],
  ['fetch runtime dependency', /\bfetch\b/],
  ['globalThis runtime dependency', /\bglobalThis\b/],
  ['async syntax/runtime', /(^|[=(:,;{}\n\r])\s*async\s+(function|\(|[\w$]+\s*=>)/],
  ['dynamic import', /\bimport\s*\(/],
  ['ES module import declaration', /(^|[;\n\r])\s*import\s+[\w{*]/],
  ['ES module export declaration', /(^|[;\n\r])\s*export\s+[\w{*]/],
  ['class syntax', /(^|[;{}\n\r])\s*class\s+[\w$]/],
  ['let declaration', /(^|[;\n\r])\s*let\s+/],
  ['const declaration', /(^|[;\n\r])\s*const\s+/],
  ['arrow function syntax', /=>/],
  ['optional chaining syntax', /\?\./],
  ['nullish coalescing syntax', /\?\?/]
];

const failures = [];
for (const [label, pattern] of banned) {
  if (pattern.test(source)) {
    failures.push(label);
  }
}

if (failures.length > 0) {
  throw new Error(`Compatibility scanner rejected ${path.relative(loginRoot, artifactPath)}:\n- ${failures.join('\n- ')}`);
}

checkManifest();
spawnFile('npx', ['es-check', 'es5', artifactPath], { cwd: loginRoot, capture: false });
spawnFile('npx', ['eslint', 'argon2-asm/src/wrapper.js', '--config', 'argon2-asm/eslint.config.js'], {
  cwd: loginRoot,
  capture: false
});

console.log('Argon2 asm.js compatibility checks passed.');
