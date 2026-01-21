// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { get, writable } from "svelte/store";

export type ConfirmDialogTone = "primary" | "danger";

export type ConfirmDialogOptions = {
  title?: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  tone?: ConfirmDialogTone;
};

export type ConfirmDialogState = {
  title: string;
  message: string;
  confirmLabel: string;
  cancelLabel: string;
  tone: ConfirmDialogTone;
  resolve: (confirmed: boolean) => void;
};

const dialogStore = writable<ConfirmDialogState | null>(null);

export const confirmDialogState = {
  subscribe: dialogStore.subscribe,
};

export function confirmDialog(options: ConfirmDialogOptions): Promise<boolean> {
  const current = get(dialogStore);
  if (current) {
    current.resolve(false);
  }

  return new Promise((resolve) => {
    dialogStore.set({
      title: options.title ?? "Confirm",
      message: options.message,
      confirmLabel: options.confirmLabel ?? "Confirm",
      cancelLabel: options.cancelLabel ?? "Cancel",
      tone: options.tone ?? "primary",
      resolve,
    });
  });
}

export function resolveConfirmDialog(confirmed: boolean): void {
  dialogStore.update((state) => {
    state?.resolve(confirmed);
    return null;
  });
}
