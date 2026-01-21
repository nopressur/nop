// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import type { PasswordFrontEndParams } from "../types";

export type AdminRuntimeConfig = {
  adminPath: string;
  appName: string;
  csrfTokenPath: string;
  wsPath: string;
  wsTicketPath: string;
  userManagementEnabled: boolean;
  passwordFrontEnd: PasswordFrontEndParams;
};

type RuntimeOwner = {
  nopAdminConfig?: AdminRuntimeConfig;
  nopAdminBootstrap?: unknown;
  nopAdminCspNonce?: string;
};

let cachedConfig: AdminRuntimeConfig | null = null;

function getOwner(): RuntimeOwner {
  return globalThis as RuntimeOwner;
}

export function getAdminRuntimeConfig(): AdminRuntimeConfig {
  if (cachedConfig) {
    return cachedConfig;
  }
  const owner = getOwner();
  if (!owner.nopAdminConfig) {
    throw new Error("Admin runtime config not found");
  }
  cachedConfig = owner.nopAdminConfig;
  return cachedConfig;
}

export function getAdminBootstrap<T = unknown>(): T | null {
  const owner = getOwner();
  return (owner.nopAdminBootstrap as T | null) ?? null;
}

export function getAdminCspNonce(): string | null {
  const owner = getOwner();
  return owner.nopAdminCspNonce ?? null;
}

export function setAdminRuntimeConfig(config: AdminRuntimeConfig): void {
  const owner = getOwner();
  owner.nopAdminConfig = config;
  cachedConfig = config;
}

export function clearAdminRuntimeConfig(): void {
  const owner = getOwner();
  delete owner.nopAdminConfig;
  delete owner.nopAdminCspNonce;
  cachedConfig = null;
}
