<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->

<script lang="ts">
  import Select from "./Select.svelte";

  export let options: string[] = [];
  export let selected: string[] = [];
  export let disabled = false;
  export let placeholder = "Select";
  export let emptyLabel = "None";
  export let id = "";

  let selectedOption = "";

  $: availableOptions = options.filter((option) => !selected.includes(option));
  $: if (selectedOption) {
    addSelected(selectedOption);
  }

  function addSelected(value: string): void {
    if (!value) {
      return;
    }
    if (selected.includes(value)) {
      selectedOption = "";
      return;
    }
    selected = [...selected, value];
    selectedOption = "";
  }

  function removeSelected(value: string): void {
    selected = selected.filter((item) => item !== value);
  }
</script>

<div class="flex flex-col gap-2">
  <div class="flex flex-wrap gap-2">
    {#if selected.length === 0}
      <span class="text-xs text-muted">{emptyLabel}</span>
    {:else}
      {#each selected as item}
        <span class="inline-flex items-center gap-2 rounded-sm border border-border bg-surface-2 px-2 py-1 text-xs text-text">
          {item}
          <button
            type="button"
            class="text-muted hover:text-text"
            aria-label={`Remove ${item}`}
            on:click={() => removeSelected(item)}
            disabled={disabled}
          >
            x
          </button>
        </span>
      {/each}
    {/if}
  </div>

  <div class="max-w-sm">
    <Select
      {id}
      bind:value={selectedOption}
      disabled={disabled || availableOptions.length === 0}
    >
      <option value="">{placeholder}</option>
      {#each availableOptions as option}
        <option value={option}>{option}</option>
      {/each}
    </Select>
  </div>
</div>
