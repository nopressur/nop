<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->

<script lang="ts">
  import { createEventDispatcher } from "svelte";
  import Button from "./Button.svelte";

  export let open = false;
  export let saving = false;

  const dispatch = createEventDispatcher<{
    save: void;
    discard: void;
    cancel: void;
  }>();

  let container: HTMLDivElement | null = null;

  $: if (open && container) {
    container.focus();
  }

  function handleKeydown(event: KeyboardEvent): void {
    if (saving) {
      return;
    }
    if (event.metaKey || event.ctrlKey || event.altKey) {
      return;
    }
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      dispatch("cancel");
      return;
    }
    if (event.key === "Enter") {
      event.preventDefault();
      event.stopPropagation();
      dispatch("save");
      return;
    }
    if (event.key === "d" || event.key === "D") {
      event.preventDefault();
      event.stopPropagation();
      dispatch("discard");
    }
  }
</script>

{#if open}
  <div class="fixed inset-0 z-40 bg-black/40" aria-hidden="true"></div>
  <div
    class="fixed left-1/2 top-1/2 z-50 w-[94vw] max-w-lg -translate-x-1/2 -translate-y-1/2 rounded-lg border border-border bg-surface p-5 shadow-soft"
    role="dialog"
    aria-modal="true"
    aria-label="Unsaved changes"
    tabindex="-1"
    bind:this={container}
    on:keydown={handleKeydown}
  >
    <div class="space-y-2">
      <p class="text-[11px] uppercase tracking-[0.3em] text-muted">Unsaved changes</p>
      <p class="text-sm text-text">
        You have unsaved changes. Save before leaving this page?
      </p>
    </div>
    <div class="mt-5 flex flex-wrap justify-end gap-2">
      <Button variant="outline" size="sm" disabled={saving} on:click={() => dispatch("cancel")}>
        Cancel
      </Button>
      <Button variant="danger" size="sm" disabled={saving} on:click={() => dispatch("discard")}>
        Discard
      </Button>
      <Button variant="primary" size="sm" disabled={saving} on:click={() => dispatch("save")}>
        Save
      </Button>
    </div>
  </div>
{/if}
