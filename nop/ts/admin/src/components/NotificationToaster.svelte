<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->

<script lang="ts">
  import { notifications, removeNotification } from "../stores/notifications";

  const toneStyles: Record<string, string> = {
    info: "border-accent text-text",
    success: "border-success text-text",
    error: "border-danger text-text"
  };
</script>

<div class="pointer-events-none fixed right-4 top-4 z-50 flex w-[320px] flex-col gap-2">
  {#each $notifications as note (note.id)}
    <div
      class={`pointer-events-auto flex items-start gap-2 rounded-md border border-border bg-surface px-4 py-3 shadow-soft ${
        toneStyles[note.tone] || toneStyles.info
      }`}
    >
      <div class="text-sm leading-snug">{note.message}</div>
      <button
        class="ml-auto text-xs uppercase tracking-[0.2em] text-muted"
        on:click={() => removeNotification(note.id)}
        aria-label="Dismiss notification"
      >
        Close
      </button>
    </div>
  {/each}
</div>
