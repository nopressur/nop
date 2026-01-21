// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { describe, expect, it, vi } from 'vitest';
import type { PasswordFrontEndParams } from './types';

const argon2id = vi.hoisted(() => vi.fn());

vi.mock('hash-wasm', () => ({
  argon2id
}));

import { deriveFrontEndHash } from './argon';

describe('deriveFrontEndHash', () => {
  const params: PasswordFrontEndParams = {
    memoryKib: 8,
    iterations: 2,
    parallelism: 1,
    outputLen: 32,
    saltLen: 16
  };

  it('throws on invalid hex salt length', async () => {
    await expect(
      deriveFrontEndHash('password', 'abc', params)
    ).rejects.toThrow('Invalid salt length');
  });

  it('passes parameters to argon2id and returns output', async () => {
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
});
