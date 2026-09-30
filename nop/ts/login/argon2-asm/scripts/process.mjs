// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { spawnSync } from 'node:child_process';

export function spawnFile(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    encoding: 'utf8',
    shell: options.shell ?? false,
    stdio: options.capture === false ? 'inherit' : 'pipe'
  });

  if (result.error) {
    throw result.error;
  }

  if (!options.allowFailure && result.status !== 0) {
    const rendered = [command, ...args].join(' ');
    const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
    throw new Error(`Command failed (${result.status}): ${rendered}\n${output}`);
  }

  return {
    status: result.status,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? ''
  };
}
