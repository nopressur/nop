// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { PasswordFrontEndParams } from './types';

const argon2id = vi.hoisted(() => vi.fn());

vi.mock('hash-wasm', () => ({
  argon2id
}));

import { deriveFrontEndHash } from './argon';

describe('deriveFrontEndHash', () => {
  const originalWebAssembly = window.WebAssembly;

  const params: PasswordFrontEndParams = {
    memoryKib: 8,
    iterations: 2,
    parallelism: 1,
    outputLen: 32,
    saltLen: 16
  };

  beforeEach(() => {
    argon2id.mockReset();
    Object.defineProperty(window, 'WebAssembly', {
      configurable: true,
      value: {
        instantiate: vi.fn()
      }
    });
    delete window.NoPressureArgon2id;
    delete window.nopLoginArgon2idFallbackPath;
  });

  afterEach(() => {
    Object.defineProperty(window, 'WebAssembly', {
      configurable: true,
      value: originalWebAssembly
    });
    delete window.NoPressureArgon2id;
    delete window.nopLoginArgon2idFallbackPath;
    vi.restoreAllMocks();
  });

  it('throws on invalid hex salt length', async () => {
    await expect(
      deriveFrontEndHash('password', 'abc', params)
    ).rejects.toThrow('Invalid salt length');
  });

  it('throws on invalid hex salt content', async () => {
    await expect(
      deriveFrontEndHash('password', 'zzzz', params)
    ).rejects.toThrow('Invalid salt hex');
  });

  it('uses hash-wasm when WebAssembly is available', async () => {
    argon2id.mockResolvedValueOnce('deadbeef');

    const result = await deriveFrontEndHash('password', '0f0f', params);
    expect(result).toBe('deadbeef');

    expect(argon2id).toHaveBeenCalledTimes(1);
    const [options] = argon2id.mock.calls[0];
    expect(options).toMatchObject({
      password: 'password',
      iterations: params.iterations,
      parallelism: params.parallelism,
      memorySize: params.memoryKib,
      hashLength: params.outputLen,
      outputType: 'hex'
    });
    expect(Array.from(options.salt)).toEqual([15, 15]);
  });

  it('uses the asm.js fallback when WebAssembly is unavailable', async () => {
    Object.defineProperty(window, 'WebAssembly', {
      configurable: true,
      value: undefined
    });
    const deriveArgon2id = vi.fn().mockReturnValue('asmhash');
    window.NoPressureArgon2id = { deriveArgon2id };

    const result = await deriveFrontEndHash('password', '0f0f', params);

    expect(result).toBe('asmhash');
    expect(argon2id).not.toHaveBeenCalled();
    expect(deriveArgon2id).toHaveBeenCalledWith('password', new Uint8Array([15, 15]), {
      memoryKib: params.memoryKib,
      iterations: params.iterations,
      parallelism: params.parallelism,
      outputLen: params.outputLen
    });
  });

  it('falls back to asm.js when the WebAssembly hash path fails', async () => {
    argon2id.mockRejectedValueOnce(new Error('wasm argon2 failed'));
    const deriveArgon2id = vi.fn().mockReturnValue('asmhash');
    window.NoPressureArgon2id = { deriveArgon2id };

    const result = await deriveFrontEndHash('password', '0f0f', params);

    expect(result).toBe('asmhash');
    expect(argon2id).toHaveBeenCalledOnce();
    expect(deriveArgon2id).toHaveBeenCalledWith('password', new Uint8Array([15, 15]), {
      memoryKib: params.memoryKib,
      iterations: params.iterations,
      parallelism: params.parallelism,
      outputLen: params.outputLen
    });
  });

  it('reports fallback load failure when WebAssembly is unavailable and the script cannot load', async () => {
    Object.defineProperty(window, 'WebAssembly', {
      configurable: true,
      value: undefined
    });
    window.nopLoginArgon2idFallbackPath = '/builtin/login-test/argon2id.asm.js';
    const appendChild = vi
      .spyOn(document.head, 'appendChild')
      .mockImplementation((node: Node) => {
        setTimeout(() => {
          const script = node as HTMLScriptElement;
          script.onerror?.(new Event('error'));
        }, 0);
        return node;
      });

    await expect(
      deriveFrontEndHash('password', '0f0f', params)
    ).rejects.toThrow('Argon2id asm.js fallback failed to load');
    expect(appendChild).toHaveBeenCalledOnce();
  });
});
