// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawnFile } from './process.mjs';

const loginRoot = path.resolve(import.meta.dirname, '../..');
const asmRoot = path.resolve(import.meta.dirname, '..');
const buildDir = path.join(asmRoot, 'build');
const distDir = path.join(asmRoot, 'dist');
const sourceDir = path.join(loginRoot, 'node_modules/hash-wasm/src');
const wrapperPath = path.join(asmRoot, 'src/wrapper.js');
const babelConfigPath = path.join(asmRoot, 'babel.legacy.config.cjs');
const manifestPath = path.join(asmRoot, 'argon2id.asm.manifest.json');
const rawPath = path.join(buildDir, 'argon2id.raw.js');
const patchedPath = path.join(buildDir, 'argon2id.raw.patched.js');
const babelPath = path.join(buildDir, 'argon2id.babel.js');
const outputPath = path.join(distDir, 'argon2id.asm.js');
const argonBridgePath = path.join(asmRoot, 'src/argon2_bridge.c');

const argonObject = path.join(buildDir, 'argon2.o');
const blakeObject = path.join(buildDir, 'blake2b.o');

const exportedFunctions = [
  '_Argon2_GetBuffer',
  '_Argon2_SetMemorySize',
  '_Argon2_Calculate',
  '_Blake2b_GetBuffer',
  '_Blake2b_Init',
  '_Blake2b_Update',
  '_Blake2b_Final',
  '_Blake2b_Calculate'
];

function sha256(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function readPackageLock() {
  const packageLock = JSON.parse(fs.readFileSync(path.join(loginRoot, 'package-lock.json'), 'utf8'));
  const packageInfo = packageLock.packages?.['node_modules/hash-wasm'];
  if (!packageInfo) {
    throw new Error('Could not find node_modules/hash-wasm in package-lock.json.');
  }
  return packageInfo;
}

function ensureCleanBuild() {
  fs.rmSync(buildDir, { recursive: true, force: true });
  fs.mkdirSync(buildDir, { recursive: true });
  fs.mkdirSync(distDir, { recursive: true });
}

function emccVersion() {
  const result = spawnFile('emcc', ['-v'], { cwd: loginRoot, allowFailure: true });
  return `${result.stdout}${result.stderr}`.trim();
}

function emccPath() {
  return spawnFile('which', ['emcc'], { cwd: loginRoot }).stdout.trim();
}

function compileObjects() {
  const blakeSource = path.join(sourceDir, 'blake2b.c');

  spawnFile('emcc', [
    '-O2',
    '-c',
    argonBridgePath,
    '-I',
    sourceDir,
    '-o',
    argonObject
  ], { cwd: loginRoot });

  spawnFile('emcc', [
    '-O2',
    '-c',
    blakeSource,
    '-DHash_GetBuffer=Blake2b_GetBuffer',
    '-DHash_Init=Blake2b_Init',
    '-DHash_Update=Blake2b_Update',
    '-DHash_Final=Blake2b_Final',
    '-DHash_GetState=Blake2b_GetState',
    '-DHash_Calculate=Blake2b_Calculate',
    '-DSTATE_SIZE=Blake2b_STATE_SIZE',
    '-o',
    blakeObject
  ], { cwd: loginRoot });
}

function linkRawArtifact() {
  spawnFile('emcc', [
    argonObject,
    blakeObject,
    '-O2',
    '-sWASM=0',
    '-sMINIMAL_RUNTIME=1',
    '-sLEGACY_VM_SUPPORT=1',
    '-sENVIRONMENT=web',
    '-sFILESYSTEM=0',
    '-sINITIAL_MEMORY=134217728',
    "-sINCOMING_MODULE_JS_API=[]",
    `-sEXPORTED_FUNCTIONS=${JSON.stringify(exportedFunctions)}`,
    '--pre-js',
    wrapperPath,
    '-o',
    rawPath
  ], { cwd: loginRoot });
}

function patchRuntimeNames() {
  const raw = fs.readFileSync(rawPath, 'utf8');
  fs.writeFileSync(
    patchedPath,
    raw
      .replace('var Module=Module;', 'var Module={wasm:[]};')
      .replace('function ready(){}', '')
      .replace(/\bWebAssembly\b/g, 'NopAsmRuntime')
  );
}

function transpileAndMinify() {
  spawnFile('npx', [
    'babel',
    patchedPath,
    '--out-file',
    babelPath,
    '--config-file',
    babelConfigPath,
    '--compact',
    'true'
  ], { cwd: loginRoot });

  spawnFile('npx', [
    'terser',
    babelPath,
    '--compress',
    'ecma=5',
    '--mangle',
    '--format',
    'ecma=5,comments=false',
    '-o',
    outputPath
  ], { cwd: loginRoot });
}

function writeManifest() {
  const packageInfo = readPackageLock();
  const inputFiles = [
    path.join(sourceDir, 'hash-wasm.h'),
    path.join(sourceDir, 'argon2.c'),
    path.join(sourceDir, 'blake2b.c'),
    argonBridgePath,
    wrapperPath,
    babelConfigPath,
    path.join(asmRoot, 'scripts/generate.mjs'),
    path.join(asmRoot, 'scripts/process.mjs'),
    path.join(asmRoot, 'scripts/check-compat.mjs')
  ];
  const inputs = inputFiles.map((filePath) => ({
    path: path.relative(loginRoot, filePath),
    sha256: sha256(filePath)
  }));

  const manifest = {
    artifact: 'dist/argon2id.asm.js',
    artifactSha256: sha256(outputPath),
    generator: {
      command: 'npm run argon2-asm:generate',
      cwd: path.relative(process.cwd(), loginRoot) || '.',
      emccPath: emccPath(),
      emccVersion: emccVersion(),
      emccLinkFlags: [
        '-O2',
        '-sWASM=0',
        '-sMINIMAL_RUNTIME=1',
        '-sLEGACY_VM_SUPPORT=1',
        '-sENVIRONMENT=web',
        '-sFILESYSTEM=0',
        '-sINITIAL_MEMORY=134217728',
        "-sINCOMING_MODULE_JS_API=[]",
        `-sEXPORTED_FUNCTIONS=${JSON.stringify(exportedFunctions)}`
      ],
      postProcessing: [
        'remove Emscripten empty ready hook so the wrapper owns initialization',
        'replace local WebAssembly runtime identifier with NopAsmRuntime',
        'Babel preset-env forceAllTransforms for iOS 9.3 / Safari 9.1',
        'terser ecma=5 minification'
      ]
    },
    upstream: {
      package: 'hash-wasm',
      version: packageInfo.version,
      resolved: packageInfo.resolved,
      integrity: packageInfo.integrity,
      license: 'MIT'
    },
    argon2: {
      variant: 'argon2id',
      version: '0x13',
      exportedNamespace: 'NoPressureArgon2id',
      exportedFunction: 'deriveArgon2id'
    },
    inputs
  };

  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
}

ensureCleanBuild();
compileObjects();
linkRawArtifact();
patchRuntimeNames();
transpileAndMinify();
writeManifest();
console.log(`Generated ${path.relative(loginRoot, outputPath)}`);
