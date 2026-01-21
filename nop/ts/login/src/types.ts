// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

export type LoginProvider = {
  id: string;
  label: string;
};

export type PasswordFrontEndParams = {
  memoryKib: number;
  iterations: number;
  parallelism: number;
  outputLen: number;
  saltLen: number;
};

export type LoginUser = {
  email: string;
  name: string;
};

export type LoginRuntimeConfig = {
  appName: string;
  loginPath: string;
  profilePath: string;
  profileApiPath: string;
  csrfTokenPath: string;
  initialRoute: string;
  returnPath?: string | null;
  providers: LoginProvider[];
  passwordFrontEnd: PasswordFrontEndParams;
  user?: LoginUser | null;
};

export type LoginBootstrapResponse = {
  login_session_id: string;
  expires_in_seconds: number;
  return_path?: string | null;
};

export type PasswordEmailResponse = {
  front_end_salt: string;
  expires_in_seconds: number;
};

export type LoginSuccessResponse = {
  return_path: string;
};

export type LoginErrorResponse = {
  code: string;
  message: string;
};

export type StatusResponse = {
  success: boolean;
  message: string;
};

export type ProfilePasswordSaltResponse = {
  change_token: string;
  current: { front_end_salt: string };
  next: { front_end_salt: string };
  expires_in_seconds: number;
};
