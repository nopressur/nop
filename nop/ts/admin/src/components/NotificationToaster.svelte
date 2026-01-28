<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->

<script lang="ts">
  import { notifications, removeNotification } from "../stores/notifications";

  const toneStyles: Record<string, string> = {
    info: "bg-[var(--toast-info-bg)] text-[var(--toast-text)]",
    success: "bg-[var(--toast-success-bg)] text-[var(--toast-text)]",
    error: "bg-[var(--toast-error-bg)] text-[var(--toast-text)]"
  };
</script>

<div
  class="pointer-events-none fixed left-1/2 top-4 z-50 flex w-[90vw] max-w-[400px] -translate-x-1/2 flex-col gap-2"
>
  {#each $notifications as note (note.id)}
    <div
      class={`pointer-events-auto flex items-center gap-2 rounded-sm px-3 py-1 shadow-soft ${
        toneStyles[note.tone] || toneStyles.info
      }`}
    >
      <div class="min-w-0 flex-1 truncate text-xs leading-tight">{note.message}</div>
      <button
        class="ml-auto flex-none text-xs text-[var(--toast-text)]"
        on:click={() => removeNotification(note.id)}
        aria-label="Dismiss notification"
      >
        X
      </button>
    </div>
  {/each}
</div>
