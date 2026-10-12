<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->

<script lang="ts">
  import { onMount, tick } from "svelte";
  import SearchInput from "./SearchInput.svelte";
  import { getWindow } from "../services/browser";
  import {
    CHIP_ROW_GAP_PX,
    filterChips,
    fitsSingleRow,
    fitChipCount,
    sortAlphabetical,
    topChips,
    unselectedOptions,
  } from "./chipSelect";

  export let options: string[] = [];
  export let selected: string[] = [];
  export let counts: Record<string, number> | undefined = undefined;
  export let disabled = false;
  export let placeholder = "Filter";
  export let emptyLabel = "None";
  export let id = "";

  const activeChipClass =
    "inline-flex items-center gap-2 rounded-sm border border-success bg-transparent px-2 py-1 text-xs text-success";
  const passiveChipClass =
    "inline-flex shrink-0 items-center rounded-sm border border-border bg-surface-2 px-2 py-1 text-xs text-muted hover:text-text disabled:cursor-not-allowed";

  let filter = "";
  let collapsed = false;
  let measured = false;
  let visibleTopCount = 0;
  let measureQueued = false;
  let root: HTMLDivElement | null = null;
  let rowContainer: HTMLDivElement | null = null;
  let filterWrap: HTMLDivElement | null = null;
  let measureRow: HTMLDivElement | null = null;
  let alphaRow: HTMLDivElement | null = null;

  $: unselected = unselectedOptions(options, selected);
  $: candidates = topChips(options, selected, counts);
  $: alphabetical = sortAlphabetical(unselected);
  $: shown = filter ? filterChips(options, selected, filter) : alphabetical;
  $: visibleCandidates = measured ? candidates.slice(0, visibleTopCount) : candidates;
  $: hasPassive = unselected.length > 0;
  $: showFilter = hasPassive && (!collapsed || filter.length > 0);
  $: showTopRow = showFilter && !filter && visibleCandidates.length > 0;
  $: {
    // Re-measure after anything affecting layout settles.
    filter;
    candidates;
    alphabetical;
    void measureSoon();
  }

  function addSelected(value: string): void {
    if (!value || disabled) {
      return;
    }
    if (selected.includes(value)) {
      return;
    }
    selected = [...selected, value];
  }

  function removeSelected(value: string): void {
    selected = selected.filter((item) => item !== value);
  }

  function measureSoon(): Promise<void> {
    if (measureQueued) {
      return Promise.resolve();
    }
    measureQueued = true;
    return tick().then(() => {
      measureQueued = false;
      measure();
    });
  }

  function measure(): void {
    if (alphaRow && hasPassive) {
      collapsed = !filter && fitsSingleRow(alphaRow.clientWidth, alphaRow.scrollWidth);
    } else if (!hasPassive) {
      collapsed = true;
    }
    if (rowContainer && filterWrap && measureRow) {
      const available = rowContainer.clientWidth - filterWrap.offsetWidth;
      const widths = Array.from(measureRow.children).map(
        (child) => (child as HTMLElement).offsetWidth,
      );
      visibleTopCount = fitChipCount(available, widths, CHIP_ROW_GAP_PX);
    } else {
      visibleTopCount = candidates.length;
    }
    measured = true;
  }

  onMount(() => {
    void measureSoon();
    const ResizeObserverCtor = getWindow()?.ResizeObserver;
    if (!root || !ResizeObserverCtor) {
      return;
    }
    const observer = new ResizeObserverCtor(() => {
      void measureSoon();
    });
    observer.observe(root);
    return () => observer.disconnect();
  });
</script>

<div class="relative flex min-w-0 w-full flex-col gap-2" bind:this={root}>
  <div class="flex flex-wrap gap-2">
    {#if selected.length === 0}
      <span class="text-xs text-muted">{emptyLabel}</span>
    {:else}
      {#each selected as item}
        <span class={activeChipClass}>
          {item}
          <button
            type="button"
            class="text-success hover:opacity-80"
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

  {#if showFilter}
    <div class="flex min-w-0 w-full items-center gap-2 py-0.5" bind:this={rowContainer}>
      <div class="w-full max-w-[150px] shrink-0" bind:this={filterWrap}>
        <SearchInput {id} bind:value={filter} {placeholder} {disabled} selectOnFocus compact />
      </div>
      {#if showTopRow}
        <div class="flex min-w-0 flex-1 items-center gap-2 overflow-hidden">
          {#each visibleCandidates as candidate}
            <button
              type="button"
              class={passiveChipClass}
              aria-label={`Add ${candidate}`}
              on:click={() => addSelected(candidate)}
              disabled={disabled}
            >
              {candidate}
            </button>
          {/each}
        </div>
      {/if}
    </div>
  {/if}

  {#if hasPassive}
    <div
      class="flex min-w-0 w-full flex-nowrap gap-2 overflow-x-auto overflow-y-hidden overscroll-x-contain py-0.5"
      bind:this={alphaRow}
    >
      {#if shown.length === 0}
        <span class="text-xs text-muted">No matches</span>
      {:else}
        {#each shown as option}
          <button
            type="button"
            class={passiveChipClass}
            aria-label={`Add ${option}`}
            on:click={() => addSelected(option)}
            disabled={disabled}
          >
            {option}
          </button>
        {/each}
      {/if}
    </div>
  {/if}

  {#if candidates.length > 0 && !filter}
    <div
      aria-hidden="true"
      class="invisible absolute left-0 top-0 flex w-0 gap-2 overflow-hidden"
      bind:this={measureRow}
    >
      {#each candidates as candidate}
        <span class={passiveChipClass}>{candidate}</span>
      {/each}
    </div>
  {/if}
</div>
