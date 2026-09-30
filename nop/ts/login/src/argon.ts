// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { argon2id } from 'hash-wasm';
import type { PasswordFrontEndParams } from './types';

interface Argon2AsmApi {
  deriveArgon2id(
    password: string | Uint8Array,
    salt: string | Uint8Array,
    params: {
      memoryKib: number;
      iterations: number;
      parallelism: number;
      outputLen: number;
    }
  ): string;
}

declare global {
  interface Window {
    NoPressureArgon2id?: Argon2AsmApi;
    nopLoginArgon2idFallbackPath?: string;
  }
}

let asmLoadPromise: Promise<Argon2AsmApi> | null = null;

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error('Invalid salt length');
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    const value = Number.parseInt(hex.slice(i, i + 2), 16);
    if (Number.isNaN(value)) {
      throw new Error('Invalid salt hex');
    }
    bytes[i / 2] = value;
  }
  return bytes;
}

function hasWebAssembly(): boolean {
  return (
    typeof window.WebAssembly === 'object' &&
    typeof window.WebAssembly.instantiate === 'function'
  );
}

function getFallbackPath(): string {
  if (window.nopLoginArgon2idFallbackPath) {
    return window.nopLoginArgon2idFallbackPath;
  }

  const scripts = document.getElementsByTagName('script');
  for (let i = scripts.length - 1; i >= 0; i -= 1) {
    const src = scripts[i].getAttribute('src') ?? '';
    const loginIndex = src.lastIndexOf('/login.js');
    if (loginIndex >= 0) {
      return `${src.slice(0, loginIndex + 1)}argon2id.asm.js`;
    }
  }

  return '/builtin/login-dev/argon2id.asm.js';
}

function loadAsmArgon2id(): Promise<Argon2AsmApi> {
  if (window.NoPressureArgon2id) {
    return Promise.resolve(window.NoPressureArgon2id);
  }
  if (asmLoadPromise) {
    return asmLoadPromise;
  }

  asmLoadPromise = new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.async = true;
    script.src = getFallbackPath();
    script.onload = () => {
      if (window.NoPressureArgon2id) {
        resolve(window.NoPressureArgon2id);
      } else {
        reject(new Error('Argon2id asm.js fallback did not initialize'));
      }
    };
    script.onerror = () => {
      reject(new Error('Argon2id asm.js fallback failed to load'));
    };
    document.head.appendChild(script);
  });

  return asmLoadPromise;
}

async function deriveWithAsmArgon2id(
  password: string,
  salt: Uint8Array,
  params: PasswordFrontEndParams
): Promise<string> {
  const asmArgon2id = await loadAsmArgon2id();
  return asmArgon2id.deriveArgon2id(password, salt, {
    memoryKib: params.memoryKib,
    iterations: params.iterations,
    parallelism: params.parallelism,
    outputLen: params.outputLen
  });
}

export async function deriveFrontEndHash(
  password: string,
  saltHex: string,
  params: PasswordFrontEndParams
): Promise<string> {
  const salt = hexToBytes(saltHex);
  if (!hasWebAssembly()) {
    return deriveWithAsmArgon2id(password, salt, params);
  }

  try {
    return await argon2id({
      password,
      salt,
      parallelism: params.parallelism,
      iterations: params.iterations,
      memorySize: params.memoryKib,
      hashLength: params.outputLen,
      outputType: 'hex'
    });
  } catch {
    return deriveWithAsmArgon2id(password, salt, params);
  }
}
