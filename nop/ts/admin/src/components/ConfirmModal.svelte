<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->

<script lang="ts">
  import { onDestroy } from "svelte";
  import Button from "./Button.svelte";
  import {
    confirmDialogState,
    resolveConfirmDialog,
    type ConfirmDialogState,
  } from "../stores/confirmDialog";

  let dialog: ConfirmDialogState | null = null;
  let container: HTMLDivElement | null = null;

  const unsubscribe = confirmDialogState.subscribe((value) => {
    dialog = value;
  });

  onDestroy(() => {
    unsubscribe();
  });

  $: if (dialog && container) {
    container.focus();
  }

  function handleKeydown(event: KeyboardEvent): void {
    if (!dialog) {
      return;
    }
    if (event.metaKey || event.ctrlKey || event.altKey) {
      return;
    }
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      resolveConfirmDialog(false);
      return;
    }
    if (event.key === "Enter") {
      event.preventDefault();
      event.stopPropagation();
      resolveConfirmDialog(true);
    }
  }
</script>

{#if dialog}
  <div class="fixed inset-0 z-[60] bg-black/40" aria-hidden="true"></div>
  <div
    class="fixed left-1/2 top-1/2 z-[70] w-[94vw] max-w-lg -translate-x-1/2 -translate-y-1/2 rounded-lg border border-border bg-surface p-5 shadow-soft"
    role="dialog"
    aria-modal="true"
    aria-label={dialog.title}
    tabindex="-1"
    bind:this={container}
    on:keydown={handleKeydown}
  >
    <div class="space-y-2">
      <p class="text-[11px] uppercase tracking-[0.3em] text-muted">{dialog.title}</p>
      <p class="text-sm text-text">{dialog.message}</p>
    </div>
    <div class="mt-5 flex flex-wrap justify-end gap-2">
      <Button
        variant="outline"
        size="sm"
        on:click={() => resolveConfirmDialog(false)}
      >
        {dialog.cancelLabel}
      </Button>
      <Button
        variant={dialog.tone === "danger" ? "danger" : "primary"}
        size="sm"
        on:click={() => resolveConfirmDialog(true)}
      >
        {dialog.confirmLabel}
      </Button>
    </div>
  </div>
{/if}
