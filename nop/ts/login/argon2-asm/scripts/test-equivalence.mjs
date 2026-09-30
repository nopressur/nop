// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

const loginRoot = path.resolve(import.meta.dirname, '../..');
const artifactPath = path.join(loginRoot, 'argon2-asm/dist/argon2id.asm.js');
const vectorPath = path.join(loginRoot, 'argon2-asm/vectors/argon2id-vectors.json');

function loadArtifact() {
  const source = fs.readFileSync(artifactPath, 'utf8');
  const sandbox = {
    Array,
    ArrayBuffer,
    DataView,
    Error,
    Int8Array,
    Int16Array,
    Int32Array,
    Math,
    Number,
    Object,
    String,
    Uint8Array,
    Uint16Array,
    Uint32Array,
    console,
    module: { exports: {} }
  };
  sandbox.window = sandbox;
  sandbox.self = sandbox;
  sandbox.global = sandbox;
  vm.runInNewContext(source, sandbox, { filename: artifactPath });
  return sandbox.module.exports.deriveArgon2id
    ? sandbox.module.exports
    : sandbox.NoPressureArgon2id;
}

const api = loadArtifact();
if (!api || typeof api.deriveArgon2id !== 'function') {
  throw new Error('dist/argon2id.asm.js did not export deriveArgon2id.');
}

try {
  api.deriveArgon2id('', '0001020304050607', {
    memoryKib: 8,
    iterations: 1,
    parallelism: 1,
    outputLen: 16
  });
  throw new Error('Expected empty password rejection.');
} catch (err) {
  if (!String(err.message).includes('Password must be specified')) {
    throw err;
  }
}

const corpus = JSON.parse(fs.readFileSync(vectorPath, 'utf8'));
const vectors = corpus.vectors;

for (let i = 0; i < vectors.length; i++) {
  const vector = vectors[i];
  const actual = api.deriveArgon2id(vector.password, vector.saltHex, vector.params);
  if (actual !== vector.expectedHex) {
    throw new Error(`Argon2 asm.js mismatch for ${vector.id}: expected ${vector.expectedHex}, got ${actual}`);
  }
  if ((i + 1) % 100 === 0) {
    console.log(`Matched ${i + 1}/${vectors.length} vectors`);
  }
}

console.log(`All ${vectors.length} Argon2id vectors matched.`);
