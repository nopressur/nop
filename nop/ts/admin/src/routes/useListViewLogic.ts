// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { writable } from "svelte/store";
import { createListRowNavigation } from "../components/listRowNavigation";
import { confirmDialog } from "../stores/confirmDialog";
import { pushNotification } from "../stores/notifications";

type DeleteOutcome = { message: string; tone?: "success" | "error" };

type DeleteFlow = {
  confirmMessage: string;
  onDelete: () => Promise<void | DeleteOutcome>;
  successMessage?: string;
  errorMessage: string;
  onComplete?: () => Promise<void> | void;
};

export function useListViewLogic(params: { onOpen: (index: number) => void }) {
  const loading = writable(false);
  const rowNavigation = createListRowNavigation({ onOpen: params.onOpen });
  const { selectedIndex } = rowNavigation;

  function syncRowNavigation(listRef: HTMLTableSectionElement | null, count: number): void {
    rowNavigation.setItemCount(count);
    rowNavigation.setListRef(listRef);
  }

  function notifyError(error: unknown, fallback: string): void {
    const message = error instanceof Error ? error.message : fallback;
    pushNotification(message, "error");
  }

  async function runWithLoading<T>(
    action: () => Promise<T>,
    errorMessage: string,
  ): Promise<T | null> {
    loading.set(true);
    try {
      return await action();
    } catch (error) {
      notifyError(error, errorMessage);
      return null;
    } finally {
      loading.set(false);
    }
  }

  async function confirmAndDelete(params: DeleteFlow): Promise<void> {
    const confirmed = await confirmDialog({
      title: "Delete",
      message: params.confirmMessage,
      confirmLabel: "Delete",
      tone: "danger",
    });
    if (!confirmed) {
      return;
    }
    try {
      const outcome = await params.onDelete();
      if (params.successMessage) {
        pushNotification(params.successMessage, "success");
      } else if (outcome?.message) {
        pushNotification(outcome.message, outcome.tone ?? "success");
      }
      if (params.onComplete) {
        await params.onComplete();
      }
    } catch (error) {
      notifyError(error, params.errorMessage);
    }
  }

  return {
    loading,
    rowNavigation,
    selectedIndex,
    syncRowNavigation,
    notifyError,
    runWithLoading,
    confirmAndDelete,
  };
}
