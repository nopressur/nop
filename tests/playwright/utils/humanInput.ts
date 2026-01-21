// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import type { Locator } from "@playwright/test";
import type { SeededRandom } from "./rng";

const DEFAULT_MIN_DELAY_MS = 40;
const DEFAULT_MAX_DELAY_MS = 120;

export async function humanType(
  locator: Locator,
  text: string,
  rng: SeededRandom,
  options?: { minDelayMs?: number; maxDelayMs?: number }
): Promise<void> {
  const minDelay = options?.minDelayMs ?? DEFAULT_MIN_DELAY_MS;
  const maxDelay = options?.maxDelayMs ?? DEFAULT_MAX_DELAY_MS;

  await locator.click();

  for (const char of text) {
    const delay = rng.intBetween(minDelay, maxDelay);
    await locator.type(char, { delay });
  }
}

export async function humanClick(
  locator: Locator,
  rng: SeededRandom,
  options?: { minDelayMs?: number; maxDelayMs?: number }
): Promise<void> {
  const minDelay = options?.minDelayMs ?? 20;
  const maxDelay = options?.maxDelayMs ?? 80;
  const delay = rng.intBetween(minDelay, maxDelay);

  await locator.click({ delay });
}

export async function humanClearAndType(
  locator: Locator,
  text: string,
  rng: SeededRandom,
  options?: { minDelayMs?: number; maxDelayMs?: number }
): Promise<void> {
  const modifier = process.platform === "darwin" ? "Meta" : "Control";

  await locator.click();
  await locator.press(`${modifier}+A`);
  await locator.press("Backspace");
  await humanType(locator, text, rng, options);
}
