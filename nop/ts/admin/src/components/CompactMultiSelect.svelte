<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->

<script lang="ts">
  import { createEventDispatcher, onMount } from "svelte";
  import { getDocument } from "../services/browser";

  export let options: string[] = [];
  export let selected: string[] = [];
  export let disabled = false;
  export let placeholder = "All tags";
  export let emptyLabel = "No tags available";
  export let id = "";

  let open = false;
  let container: HTMLDivElement | null = null;

  const dispatch = createEventDispatcher<{ change: string[] }>();

  $: selectionLabel = selected.length > 0 ? selected.join(", ") : placeholder;
  $: if (selected.some((value) => !options.includes(value))) {
    selected = selected.filter((value) => options.includes(value));
    dispatch("change", [...selected]);
  }

  function toggleOpen(): void {
    if (disabled) {
      return;
    }
    open = !open;
  }

  function close(): void {
    open = false;
  }

  function handleOutsideClick(event: MouseEvent): void {
    if (!open || !container) {
      return;
    }
    if (!container.contains(event.target as Node)) {
      close();
    }
  }

  function handleEscape(event: KeyboardEvent): void {
    if (!open) {
      return;
    }
    if (event.key === "Escape") {
      close();
    }
  }

  function toggleValue(value: string): void {
    if (disabled) {
      return;
    }
    const next = selected.includes(value)
      ? selected.filter((item) => item !== value)
      : [...selected, value];
    selected = options.filter((option) => next.includes(option));
    dispatch("change", [...selected]);
  }

  function clearSelection(event: MouseEvent): void {
    event.stopPropagation();
    if (disabled) {
      return;
    }
    selected = [];
    dispatch("change", []);
  }

  onMount(() => {
    const doc = getDocument();
    if (!doc) {
      return;
    }
    doc.addEventListener("click", handleOutsideClick);
    doc.addEventListener("keydown", handleEscape);
    return () => {
      doc.removeEventListener("click", handleOutsideClick);
      doc.removeEventListener("keydown", handleEscape);
    };
  });
</script>

<div class="relative" bind:this={container}>
  <button
    type="button"
    {id}
    class="flex h-[var(--control-height)] w-full items-center rounded-sm border border-border bg-surface px-[var(--control-padding-x)] pr-12 text-left text-sm text-text focus:border-accent focus:outline-none disabled:cursor-not-allowed disabled:text-muted"
    disabled={disabled}
    aria-haspopup="listbox"
    aria-expanded={open}
    on:click={toggleOpen}
  >
    <span class={`block truncate ${selected.length === 0 ? "text-muted" : "text-text"}`}>
      {selectionLabel}
    </span>
  </button>
  {#if selected.length > 0 && !disabled}
    <button
      type="button"
      class="absolute right-7 top-1/2 -translate-y-1/2 text-xs text-muted hover:text-text"
      aria-label="Clear tags"
      on:click={clearSelection}
    >
      x
    </button>
  {/if}
  <span
    class="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 text-[10px] text-muted"
    aria-hidden="true"
  >
    v
  </span>

  {#if open}
    <div class="absolute z-20 mt-1 w-full rounded-sm border border-border bg-surface shadow-soft">
      <div class="max-h-48 overflow-y-auto py-1">
        {#if options.length === 0}
          <p class="px-3 py-2 text-xs text-muted">{emptyLabel}</p>
        {:else}
          {#each options as option}
            <button
              type="button"
              class={`flex w-full items-center justify-between px-3 py-2 text-xs ${
                selected.includes(option)
                  ? "bg-surface-2 text-text"
                  : "text-muted hover:bg-surface-2 hover:text-text"
              }`}
              on:click={() => toggleValue(option)}
              aria-pressed={selected.includes(option)}
            >
              <span class="truncate">{option}</span>
              {#if selected.includes(option)}
                <span class="text-success" aria-hidden="true">✓</span>
              {/if}
            </button>
          {/each}
        {/if}
      </div>
    </div>
  {/if}
</div>
