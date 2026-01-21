<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->

<script lang="ts">
  import { createEventDispatcher, tick } from "svelte";
  import Button from "./Button.svelte";
  import Input from "./Input.svelte";
  import Select from "./Select.svelte";
  import { listContent } from "../services/content";
  import type { ContentListItem } from "../services/content";
  import {
    clearBrowserTimeout,
    getDocument,
    setBrowserTimeout,
  } from "../services/browser";
  import { pushNotification } from "../stores/notifications";

  type InsertMode = "link" | "image" | "video";

  export let open = false;
  export let tags: string[] = [];
  export let defaultTag = "";

  const dispatch = createEventDispatcher<{
    close: void;
    insert: { item: ContentListItem; mode: InsertMode };
  }>();

  let query = "";
  let tag = "";
  let items: ContentListItem[] = [];
  let total = 0;
  let page = 1;
  let loading = false;
  let selectedIndex = -1;
  let mode: InsertMode = "link";
  let searchTimer: number | null = null;
  let wasOpen = false;
  let listRef: HTMLDivElement | null = null;
  let lastQuery = "";
  let lastTag = "";
  let tagInitialized = false;
  let lastSelectedId = "";

  const pageSize = 25;

  $: if (open && !wasOpen) {
    wasOpen = true;
    query = "";
    tag = tags.includes(defaultTag) ? defaultTag : "";
    tagInitialized = !defaultTag || tags.includes(defaultTag);
    page = 1;
    selectedIndex = -1;
    lastQuery = query;
    lastTag = tag;
    void loadResults();
    void focusSearch();
  }

  $: if (!open && wasOpen) {
    wasOpen = false;
    if (searchTimer) {
      clearBrowserTimeout(searchTimer);
      searchTimer = null;
    }
    items = [];
    total = 0;
    selectedIndex = -1;
    tagInitialized = false;
    lastSelectedId = "";
  }

  $: selectedItem = items[selectedIndex] ?? null;
  $: availableModes = selectedItem ? modesForItem(selectedItem) : ["link"];
  $: if (!availableModes.includes(mode)) {
    mode = availableModes[0];
  }
  $: if (selectedItem && selectedItem.id !== lastSelectedId) {
    lastSelectedId = selectedItem.id;
    mode = availableModes[0];
  } else if (!selectedItem && lastSelectedId) {
    lastSelectedId = "";
    mode = "link";
  }

  $: if (open && query !== lastQuery) {
    lastQuery = query;
    scheduleSearch();
  }

  $: if (open && tag !== lastTag) {
    lastTag = tag;
    page = 1;
    selectedIndex = -1;
    void loadResults();
  }

  $: if (open && !tagInitialized && defaultTag && tags.includes(defaultTag)) {
    tag = defaultTag;
    tagInitialized = true;
  }

  function handleClose(): void {
    open = false;
    dispatch("close");
  }

  function handleInsert(): void {
    if (!selectedItem) {
      return;
    }
    open = false;
    dispatch("insert", { item: selectedItem, mode });
    dispatch("close");
  }

  async function focusSearch(): Promise<void> {
    await tick();
    const doc = getDocument();
    const input = doc?.getElementById("insert-search");
    input?.focus();
  }

  function scheduleSearch(): void {
    if (searchTimer) {
      clearBrowserTimeout(searchTimer);
    }
    searchTimer = setBrowserTimeout(() => {
      page = 1;
      selectedIndex = -1;
      void loadResults();
      searchTimer = null;
    }, 300);
  }

  async function loadResults(): Promise<void> {
    if (!open) {
      return;
    }
    const selectedId = selectedItem?.id ?? null;
    loading = true;
    try {
      const response = await listContent({
        page,
        pageSize,
        sortField: "title",
        sortDirection: "asc",
        query: query.trim() ? query.trim() : null,
        tags: tag ? [tag] : null,
        markdownOnly: false,
      });
      items = response.items;
      total = response.total;
      page = response.page;
      if (items.length === 0) {
        selectedIndex = -1;
      } else if (selectedId) {
        const index = items.findIndex((item) => item.id === selectedId);
        selectedIndex = index >= 0 ? index : 0;
      } else if (selectedIndex < 0 || selectedIndex >= items.length) {
        selectedIndex = 0;
      }
      await scrollSelectionIntoView();
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to load content";
      pushNotification(message, "error");
    } finally {
      loading = false;
    }
  }

  function selectItem(index: number): void {
    if (index < 0 || index >= items.length) {
      return;
    }
    if (searchTimer) {
      clearBrowserTimeout(searchTimer);
      searchTimer = null;
    }
    selectedIndex = index;
    void scrollSelectionIntoView();
  }

  async function scrollSelectionIntoView(): Promise<void> {
    await tick();
    if (!listRef || selectedIndex < 0) {
      return;
    }
    const target = listRef.querySelector(`[data-index="${selectedIndex}"]`);
    if (target instanceof HTMLElement) {
      target.scrollIntoView({ block: "nearest" });
    }
  }

  function modesForItem(item: ContentListItem): InsertMode[] {
    if (item.mime.startsWith("image/")) {
      return ["image", "link"];
    }
    if (item.mime.startsWith("video/")) {
      return ["video", "link"];
    }
    return ["link"];
  }

  function handleModeKeydown(event: KeyboardEvent): void {
    if (availableModes.length < 2) {
      return;
    }
    if (event.key === "ArrowLeft" || event.key === "ArrowRight") {
      event.preventDefault();
      const direction = event.key === "ArrowRight" ? 1 : -1;
      const currentIndex = availableModes.indexOf(mode);
      const nextIndex =
        (currentIndex + direction + availableModes.length) % availableModes.length;
      mode = availableModes[nextIndex];
    }
  }

  function handleListKeydown(event: KeyboardEvent): void {
    if (items.length === 0) {
      return;
    }
    if (event.key === "ArrowDown") {
      event.preventDefault();
      const next = Math.min(items.length - 1, selectedIndex + 1);
      selectItem(next);
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      const next = Math.max(0, selectedIndex - 1);
      selectItem(next);
    } else if (event.key === "PageDown") {
      event.preventDefault();
      const totalPages = Math.max(1, Math.ceil(total / pageSize));
      if (page < totalPages) {
        page += 1;
        selectedIndex = -1;
        void loadResults();
      }
    } else if (event.key === "PageUp") {
      event.preventDefault();
      if (page > 1) {
        page -= 1;
        selectedIndex = -1;
        void loadResults();
      }
    }
  }

  function handleModalKeydown(event: KeyboardEvent): void {
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      handleClose();
      return;
    }
    if (event.key === "Enter" && selectedItem) {
      event.preventDefault();
      event.stopPropagation();
      handleInsert();
    }
  }

  function formatTitle(item: ContentListItem): string {
    return item.title || item.alias || item.id;
  }

  function formatAlias(item: ContentListItem): string {
    if (!item.alias) {
      return `/id/${item.id}`;
    }
    return item.alias.startsWith("/") ? item.alias : `/${item.alias}`;
  }
</script>

{#if open}
  <div class="fixed inset-0 z-40 bg-black/40" aria-hidden="true"></div>
  <div
    class="fixed left-1/2 top-1/2 z-50 w-[94vw] max-w-3xl -translate-x-1/2 -translate-y-1/2 rounded-lg border border-border bg-surface p-5 shadow-soft"
    role="dialog"
    aria-modal="true"
    aria-label="Insert content"
    tabindex="-1"
    on:keydown={handleModalKeydown}
  >
    <div>
      <p class="text-[11px] uppercase tracking-[0.3em] text-muted">Insert</p>
      <p class="mt-1 text-xs text-muted">
        Search content, choose an item, then select how to insert it.
      </p>
    </div>

    <div class="mt-4 grid gap-4 md:grid-cols-[1fr_200px]">
      <div>
        <label
          class="text-[11px] uppercase tracking-[0.3em] text-muted"
          for="insert-search"
        >
          Search
        </label>
        <Input
          id="insert-search"
          bind:value={query}
          className="mt-2"
          placeholder="Type to search titles"
        />
      </div>
      <div>
        <label
          class="text-[11px] uppercase tracking-[0.3em] text-muted"
          for="insert-tag"
        >
          Tag
        </label>
        <Select
          id="insert-tag"
          bind:value={tag}
          className="mt-2"
        >
          <option value="">All tags</option>
          {#each tags as option}
            <option value={option}>{option}</option>
          {/each}
        </Select>
      </div>
    </div>

    <div class="mt-4">
      <div class="flex items-center justify-between text-[10px] uppercase tracking-[0.3em] text-muted">
        <span>Results</span>
        <span>{total} total</span>
      </div>
      <div
        class="mt-2 max-h-[320px] overflow-y-auto rounded-lg border border-border bg-surface-2 p-1"
        role="listbox"
        aria-label="Content results"
        tabindex="0"
        bind:this={listRef}
        on:keydown={handleListKeydown}
      >
        {#if loading}
          <div class="px-3 py-4 text-sm text-muted">Loading content...</div>
        {:else if items.length === 0}
          <div class="px-3 py-4 text-sm text-muted">No content matches this filter.</div>
        {:else}
          {#each items as item, index}
            <button
              type="button"
              class={`w-full rounded-md px-3 py-2 text-left text-sm transition ${
                index === selectedIndex
                  ? "bg-surface text-text"
                  : "text-muted hover:bg-surface hover:text-text"
              }`}
              role="option"
              aria-selected={index === selectedIndex}
              data-index={index}
              on:click={() => selectItem(index)}
            >
              <div class="font-semibold">{formatTitle(item)}</div>
              <div class="mt-1 text-[10px] uppercase tracking-[0.28em] text-muted">
                {formatAlias(item)}
              </div>
            </button>
          {/each}
        {/if}
      </div>
    </div>

    <div class="mt-4 flex flex-wrap items-center justify-between gap-3">
      <div>
        <div class="text-[10px] uppercase tracking-[0.3em] text-muted">Insert as</div>
        <div
          class={`mt-2 inline-flex items-center gap-2 rounded-md border border-border px-2 py-1 ${
            availableModes.length < 2 ? "opacity-60" : ""
          }`}
          role="radiogroup"
          aria-label="Insertion type"
          aria-disabled={availableModes.length < 2}
          tabindex={availableModes.length < 2 ? -1 : 0}
          on:keydown={handleModeKeydown}
        >
          {#each availableModes as option}
            <button
              type="button"
              class={`rounded-sm px-3 py-1 text-[10px] uppercase tracking-[0.22em] ${
                option === mode
                  ? "bg-accent text-surface"
                  : "text-muted hover:text-text"
              }`}
              role="radio"
              aria-checked={option === mode}
              tabindex="-1"
              disabled={availableModes.length < 2}
              on:click={() => (mode = option)}
            >
              {option === "image" ? "Image" : option === "video" ? "Video" : "Link"}
            </button>
          {/each}
        </div>
      </div>
      <div class="flex items-center gap-2">
        <Button variant="outline" size="sm" on:click={handleClose}>Cancel</Button>
        <Button
          variant="primary"
          size="sm"
          disabled={!selectedItem}
          on:click={handleInsert}
        >
          Insert
        </Button>
      </div>
    </div>
  </div>
{/if}
