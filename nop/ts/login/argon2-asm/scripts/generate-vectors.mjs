// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import fs from 'node:fs';
import path from 'node:path';
import { argon2id } from 'hash-wasm';
import { buildPasswords, buildSalts, hexToBytes, parameterProfiles } from './vectors.mjs';

const loginRoot = path.resolve(import.meta.dirname, '../..');
const vectorPath = path.join(loginRoot, 'argon2-asm/vectors/argon2id-vectors.json');

const vectors = [];
const passwords = buildPasswords();

for (let passwordIndex = 0; passwordIndex < passwords.length; passwordIndex++) {
  const password = passwords[passwordIndex];
  const salts = buildSalts(passwordIndex);
  for (const salt of salts) {
    for (const profile of parameterProfiles) {
      const expectedHex = await argon2id({
        password: password.value,
        salt: hexToBytes(salt.hex),
        iterations: profile.iterations,
        parallelism: profile.parallelism,
        memorySize: profile.memoryKib,
        hashLength: profile.outputLen,
        outputType: 'hex'
      });
      vectors.push({
        id: `${password.id}-${salt.id}-${profile.id}`,
        password: password.value,
        passwordEncoding: 'utf8',
        saltHex: salt.hex,
        params: {
          memoryKib: profile.memoryKib,
          iterations: profile.iterations,
          parallelism: profile.parallelism,
          outputLen: profile.outputLen
        },
        expectedHex
      });
    }
  }
  if ((passwordIndex + 1) % 10 === 0) {
    console.log(`Generated vectors for ${passwordIndex + 1}/${passwords.length} passwords`);
  }
}

fs.mkdirSync(path.dirname(vectorPath), { recursive: true });
fs.writeFileSync(vectorPath, `${JSON.stringify({
  generatedBy: 'hash-wasm argon2id',
  matrix: {
    passwords: passwords.length,
    saltsPerPassword: 5,
    parameterProfiles: parameterProfiles.length,
    totalVectors: vectors.length
  },
  vectors
}, null, 2)}\n`);

console.log(`Generated ${vectors.length} vectors at ${path.relative(loginRoot, vectorPath)}`);
