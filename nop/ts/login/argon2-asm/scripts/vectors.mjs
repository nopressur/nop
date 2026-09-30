// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

export const parameterProfiles = [
  { id: 'tiny-fast', memoryKib: 8, iterations: 1, parallelism: 1, outputLen: 16 },
  { id: 'low-memory-iterations', memoryKib: 16, iterations: 3, parallelism: 1, outputLen: 32 },
  { id: 'medium-output-variation', memoryKib: 64, iterations: 2, parallelism: 1, outputLen: 24 },
  { id: 'parallelism-two', memoryKib: 64, iterations: 2, parallelism: 2, outputLen: 32 },
  { id: 'production-front-end', memoryKib: 65536, iterations: 2, parallelism: 1, outputLen: 32 },
  { id: 'high-output-length', memoryKib: 32, iterations: 1, parallelism: 1, outputLen: 64 }
];

function createPrng(seed) {
  let state = seed >>> 0;
  return function next() {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
}

function hexByte(value) {
  return `0${(value & 255).toString(16)}`.slice(-2);
}

export function bytesToHex(bytes) {
  return Array.from(bytes, hexByte).join('');
}

function deterministicHex(length, seed) {
  const next = createPrng(seed);
  const bytes = [];
  for (let i = 0; i < length; i++) {
    bytes.push(next() & 255);
  }
  return bytesToHex(bytes);
}

export function buildPasswords() {
  const passwords = [
    'empty-string-disallowed',
    ' ',
    '  leading and trailing  ',
    '\t',
    '\n',
    'a',
    'password',
    'correct horse battery staple',
    'this is a longer pass phrase with spaces',
    '1234567890',
    '0000000000000000',
    '9999999999999999',
    'line one\nline two',
    'tabs\tinside\tphrase',
    'punctuation!@#$%^&*()',
    'mixed CASE Password',
    'emoji \\ud83d\\udd12 lock',
    'cafe\\u0301',
    'caf\\u00e9',
    '\\u039a\\u03b1\\u03bb\\u03b7\\u03bc\\u03ad\\u03c1\\u03b1',
    '\\u3053\\u3093\\u306b\\u3061\\u306f',
    '\\u0645\\u0631\\u062d\\u0628\\u0627',
    '\\u05e9\\u05dc\\u05d5\\u05dd',
    '\\u0928\\u092e\\u0938\\u094d\\u0924\\u0947',
    'a'.repeat(128),
    'z'.repeat(1024)
  ];

  const words = ['amber', 'brisk', 'cipher', 'delta', 'ember', 'fable', 'garden', 'harbor', 'index', 'juniper'];
  for (let i = 0; passwords.length < 70; i++) {
    passwords.push(`${words[i % words.length]} ${words[(i + 3) % words.length]} ${i} phrase`);
  }

  const next = createPrng(0x6e6f7072);
  while (passwords.length < 100) {
    const length = 6 + (next() % 42);
    let value = '';
    for (let i = 0; i < length; i++) {
      value += String.fromCharCode(33 + (next() % 94));
    }
    passwords.push(value);
  }

  return passwords.slice(0, 100).map((password, index) => ({
    id: `password-${String(index).padStart(3, '0')}`,
    value: password
  }));
}

export function buildSalts(passwordIndex) {
  return [
    { id: 'min-zero-8', hex: '00'.repeat(8) },
    { id: 'standard-increment-16', hex: Array.from({ length: 16 }, (_, index) => hexByte(index + passwordIndex)).join('') },
    { id: 'long-ff-32', hex: 'ff'.repeat(32) },
    { id: 'edge-alternating-16', hex: Array.from({ length: 16 }, (_, index) => (index % 2 === 0 ? 'aa' : '55')).join('') },
    { id: 'seeded-random-24', hex: deterministicHex(24, 0x9e3779b9 ^ passwordIndex) }
  ];
}

export function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
