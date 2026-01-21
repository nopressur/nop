// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

export type UploadItemStatus =
  | "prechecking"
  | "ready"
  | "uploading"
  | "error"
  | "rejected";

export type UploadItem = {
  id: string;
  file: File;
  alias: string;
  title: string;
  tags: string[];
  status: UploadItemStatus;
  error?: string | null;
  progress?: {
    loaded: number;
    total: number;
  } | null;
};
