<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->

<script lang="ts">
  import { onMount } from "svelte";
  import Button from "../components/Button.svelte";
  import CompactMultiSelect from "../components/CompactMultiSelect.svelte";
  import Input from "../components/Input.svelte";
  import Pagination from "../components/Pagination.svelte";
  import UploadOverlay from "../components/UploadOverlay.svelte";
  import UploadQueueModal from "../components/UploadQueueModal.svelte";
  import { get } from "svelte/store";
  import { contentListState, setContentListState } from "../stores/contentListState";
  import { pushNotification } from "../stores/notifications";
  import { useListViewLogic } from "./useListViewLogic";
  import { clearBrowserTimeout, setBrowserTimeout, writeClipboardText } from "../services/browser";
  import type { ContentSortField } from "../protocol/content";
  import {
    buildContentPublicUrl,
    defaultAliasForFile,
    deleteContent,
    listContent,
    prevalidateBinaryUpload,
  } from "../services/content";
  import { listTags } from "../services/tags";
  import { navigate } from "../stores/router";
  import type { UploadItem } from "../types/uploads";

  const savedState = get(contentListState);

  let items = [] as Awaited<ReturnType<typeof listContent>>["items"];
  let total = 0;
  let page = savedState.page;
  let pageSize = savedState.pageSize;
  let query = savedState.query;
  let markdownOnly = savedState.markdownOnly;
  let selectedTags = savedState.tags ?? [];
  let sortField = savedState.sortField;
  let sortDirection = savedState.sortDirection;
  let ready = false;
  let searchTimer: number | null = null;
  let requestId = 0;
  let initialLoad = true;
  let lastQuery = query;
  let lastTagSignature = selectedTags.join("|");

  let uploadOverlayOpen = false;
  let uploadModalOpen = false;
  let uploadItems: UploadItem[] = [];
  let tagsLoading = false;
  let availableTags: string[] = [];
  let listRef: HTMLTableSectionElement | null = null;

  const {
    loading,
    rowNavigation,
    selectedIndex,
    syncRowNavigation,
    notifyError,
    confirmAndDelete,
  } = useListViewLogic({
    onOpen: (index) => openItem(index),
  });

  onMount(() => {
    ready = true;
    void loadPage(page);
    void loadTags();
  });

  $: if (ready && query !== lastQuery) {
    lastQuery = query;
    if (searchTimer) {
      clearBrowserTimeout(searchTimer);
    }
    searchTimer = setBrowserTimeout(() => {
      void loadPage(1);
    }, 400);
    setContentListState({
      query,
      page: 1,
      pageSize,
      markdownOnly,
      tags: selectedTags,
      sortField,
      sortDirection,
    });
  }

  async function loadPage(nextPage: number): Promise<void> {
    const current = ++requestId;
    loading.set(true);
    try {
      const response = await listContent({
        page: nextPage,
        pageSize,
        sortField,
        sortDirection,
        query: query.trim() || null,
        markdownOnly,
        tags: selectedTags.length > 0 ? selectedTags : null,
      });
      if (current !== requestId) {
        return;
      }
      items = response.items;
      total = response.total;
      page = response.page;
      pageSize = response.pageSize;
      setContentListState({
        query,
        page,
        pageSize,
        markdownOnly,
        tags: selectedTags,
        sortField,
        sortDirection,
      });
    } catch (error) {
      if (current !== requestId) {
        return;
      }
      notifyError(error, "Failed to load content");
    } finally {
      if (current === requestId) {
        loading.set(false);
        if (initialLoad) {
          initialLoad = false;
        }
      }
    }
  }

  function toggleMarkdownOnly(): void {
    markdownOnly = !markdownOnly;
    void loadPage(1);
    setContentListState({
      query,
      page: 1,
      pageSize,
      markdownOnly,
      tags: selectedTags,
      sortField,
      sortDirection,
    });
  }

  $: if (ready) {
    const tagSignature = selectedTags.join("|");
    if (tagSignature !== lastTagSignature) {
      lastTagSignature = tagSignature;
      void loadPage(1);
      setContentListState({
        query,
        page: 1,
        pageSize,
        markdownOnly,
        tags: selectedTags,
        sortField,
        sortDirection,
      });
    }
  }

  $: if (uploadModalOpen && uploadItems.length === 0) {
    uploadModalOpen = false;
  }

  function createUploadId(): string {
    return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  }

  function buildUploadItem(file: File): UploadItem {
    return {
      id: createUploadId(),
      file,
      alias: defaultAliasForFile(file),
      title: file.name.replace(/\.[^/.]+$/, ""),
      tags: selectedTags.length > 0 ? [...selectedTags] : [],
      status: "prechecking",
      error: null,
      progress: null
    };
  }

  function updateUploadItem(id: string, updates: Partial<UploadItem>): void {
    uploadItems = uploadItems.map((item) =>
      item.id === id ? { ...item, ...updates } : item,
    );
  }

  async function prevalidateUploadItem(item: UploadItem): Promise<void> {
    try {
      const result = await prevalidateBinaryUpload({
        filename: item.file.name,
        mime: item.file.type || "application/octet-stream",
        sizeBytes: item.file.size
      });
      if (result.accepted) {
        updateUploadItem(item.id, { status: "ready", error: null });
      } else {
        updateUploadItem(item.id, { status: "rejected", error: result.message });
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : "Pre-validation failed";
      updateUploadItem(item.id, { status: "rejected", error: message });
    }
  }

  function openUploadOverlay(): void {
    uploadOverlayOpen = true;
  }

  function closeUploadOverlay(): void {
    uploadOverlayOpen = false;
  }

  function handleOverlayFiles(files: File[]): void {
    if (files.length === 0) {
      return;
    }
    const items = files.map(buildUploadItem);
    uploadItems = [...uploadItems, ...items];
    uploadOverlayOpen = false;
    uploadModalOpen = true;
    items.forEach((item) => {
      void prevalidateUploadItem(item);
    });
  }

  function closeUploadModal(): void {
    uploadModalOpen = false;
    uploadItems = [];
  }

  function handleUploadComplete(): void {
    void loadPage(page);
  }

  async function loadTags(): Promise<void> {
    tagsLoading = true;
    try {
      const tags = await listTags();
      availableTags = tags.map((tag) => tag.id).sort((a, b) => a.localeCompare(b));
      if (selectedTags.length > 0) {
        const filtered = selectedTags.filter((tag) => availableTags.includes(tag));
        if (filtered.length !== selectedTags.length) {
          selectedTags = filtered;
        }
      }
    } catch (error) {
      notifyError(error, "Failed to load tags");
    } finally {
      tagsLoading = false;
    }
  }

  async function handleDelete(id: string): Promise<void> {
    await confirmAndDelete({
      confirmMessage: "Delete this content? This cannot be undone.",
      onDelete: () => deleteContent(id),
      successMessage: "Content deleted",
      errorMessage: "Failed to delete content",
      onComplete: () => loadPage(page),
    });
  }

  function formatAlias(item: { alias: string; id: string }): string {
    const alias = item.alias?.trim();
    if (!alias) {
      return `/id/${item.id}`;
    }
    return alias.startsWith("/") ? alias : `/${alias}`;
  }

  function openItem(index: number): void {
    const item = items[index];
    if (!item) {
      return;
    }
    navigate(`/pages/edit/${encodeURIComponent(item.id)}`);
  }

  function hasAlias(item: { alias: string }): boolean {
    return Boolean(item.alias?.trim());
  }

  async function copyItemUrl(item: { id: string; alias: string }, useAlias: boolean): Promise<void> {
    const url = buildContentPublicUrl({
      id: item.id,
      alias: useAlias ? item.alias : null,
    });
    try {
      const success = await writeClipboardText(url);
      if (!success) {
        throw new Error("copy failed");
      }
      pushNotification(useAlias ? "Alias URL copied" : "ID URL copied", "success");
    } catch {
      pushNotification(useAlias ? "Failed to copy alias URL" : "Failed to copy ID URL", "error");
    }
  }

  function handleSort(field: ContentSortField): void {
    if (sortField === field) {
      sortDirection = sortDirection === "asc" ? "desc" : "asc";
    } else {
      sortField = field;
      sortDirection = "asc";
    }
    void loadPage(1);
    setContentListState({
      query,
      page: 1,
      pageSize,
      markdownOnly,
      tags: selectedTags,
      sortField,
      sortDirection,
    });
  }

  function sortAria(field: ContentSortField): "ascending" | "descending" | "none" {
    if (sortField !== field) {
      return "none";
    }
    return sortDirection === "asc" ? "ascending" : "descending";
  }

  $: syncRowNavigation(listRef, items.length);
</script>

<section class="flex flex-col gap-5">
  <header class="sticky top-14 z-20 -mx-6 border-b border-border bg-background/95 px-4 py-3 backdrop-blur md:static md:mx-0 md:border-none md:bg-transparent md:px-0 md:py-0 flex flex-wrap items-center justify-between gap-3">
    <div>
      <p class="text-[11px] uppercase tracking-[0.35em] text-muted">Content</p>
      <h2 class="mt-2 text-xl">Content Library</h2>
    </div>
    <div class="flex items-center gap-2">
      <Button variant="outline" size="sm" on:click={openUploadOverlay}>Upload</Button>
      <Button variant="primary" size="sm" on:click={() => navigate("/pages/new")}>
        New Page
      </Button>
    </div>
  </header>

  <div class="-mx-6 bg-surface px-4 py-4 md:mx-0 md:rounded-lg md:border md:border-border md:shadow-soft">
    <div class="flex flex-wrap items-end gap-3">
      <div class="flex-1 min-w-[220px]">
        <Input bind:value={query} placeholder="Search titles" />
      </div>
      <div class="min-w-[200px]">
        <label
          class="text-[10px] uppercase tracking-[0.3em] text-muted"
          for="content-tags-filter"
        >
          Tags
        </label>
        <div class="mt-2">
          <CompactMultiSelect
            id="content-tags-filter"
            bind:selected={selectedTags}
            options={availableTags}
            placeholder="All tags"
            disabled={tagsLoading || availableTags.length === 0}
          />
        </div>
      </div>
      <Button
        variant={markdownOnly ? "primary" : "outline"}
        size="sm"
        on:click={toggleMarkdownOnly}
      >
        <span aria-hidden="true">MD</span>
        <span class="sr-only">Markdown only</span>
      </Button>
    </div>

    <div class="mt-4 md:hidden">
      {#if $loading && items.length === 0 && initialLoad}
        <p class="py-6 text-sm text-muted">Loading content...</p>
      {:else if items.length === 0}
        <p class="py-6 text-sm text-muted">No content matches this filter.</p>
      {:else}
        <div class="divide-y divide-border">
          {#each items as item}
            <div class="flex items-start justify-between gap-4 py-4">
              <div class="min-w-0">
                <button
                  type="button"
                  class="w-full text-left text-sm font-semibold leading-snug text-text break-words"
                  on:click={() => navigate(`/pages/edit/${encodeURIComponent(item.id)}`)}
                >
                  {item.title ?? "Untitled"}
                </button>
                <div class="mt-1 flex flex-wrap items-center gap-2 text-[10px] tracking-[0.28em] text-muted break-words">
                  {#if item.alias === "index"}
                    <span class="inline-flex items-center rounded-full bg-danger px-1.5 py-0 text-[8px] uppercase tracking-[0.12em] text-surface">
                      Index
                    </span>
                  {:else}
                    <span class="font-semibold uppercase">{formatAlias(item)}</span>
                  {/if}
                  {#if item.navTitle}
                    <span class="inline-flex items-center rounded-full bg-accent px-1 py-0 text-[8px] uppercase tracking-[0.04em] text-black">
                      Navbar
                    </span>
                  {/if}
                </div>
                {#if item.tags.length > 0}
                  <div class="mt-1 text-[10px] uppercase tracking-[0.22em] text-muted break-words">
                    {item.tags.join(", ")}
                  </div>
                {:else}
                  <div class="mt-1 text-[10px] uppercase tracking-[0.22em] text-muted break-words">
                    —
                  </div>
                {/if}
              </div>
              <div class="flex items-center gap-2 shrink-0">
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 px-2 text-[10px] tracking-[0.12em]"
                  aria-label="Copy ID URL"
                  on:click={() => copyItemUrl(item, false)}
                >
                  ID
                </Button>
                {#if hasAlias(item)}
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-7 px-2 text-[10px] tracking-[0.12em]"
                    aria-label="Copy alias URL"
                    on:click={() => copyItemUrl(item, true)}
                  >
                    Alias
                  </Button>
                {/if}
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 w-7 px-0 text-[10px] tracking-[0.12em] text-accent border-accent"
                  on:click={() => navigate(`/pages/edit/${encodeURIComponent(item.id)}`)}
                >
                  <span aria-hidden="true">E</span>
                  <span class="sr-only">Edit</span>
                </Button>
                <Button
                  variant="danger"
                  size="sm"
                  className="h-7 w-7 px-0 text-[10px] tracking-[0.12em]"
                  on:click={() => handleDelete(item.id)}
                >
                  <span aria-hidden="true">D</span>
                  <span class="sr-only">Delete</span>
                </Button>
              </div>
            </div>
          {/each}
        </div>
      {/if}
    </div>

    <div class="mt-4 hidden md:block md:overflow-x-auto">
      <table class="w-full text-left text-sm">
        <thead class="text-[10px] uppercase tracking-[0.3em] text-muted">
          <tr>
            <th class="py-2" scope="col" aria-sort={sortAria("title")}>
              <button
                type="button"
                class="inline-flex w-full items-center gap-1 justify-start text-left cursor-pointer"
                class:text-text={sortField === "title"}
                class:text-muted={sortField !== "title"}
                on:click={() => handleSort("title")}
              >
                <span>Title</span>
                {#if sortField === "title"}
                  <span class="text-[9px] tracking-normal">
                    {sortDirection === "asc" ? "↑" : "↓"}
                  </span>
                {/if}
              </button>
            </th>
            <th class="py-2" scope="col" aria-sort={sortAria("alias")}>
              <button
                type="button"
                class="inline-flex w-full items-center gap-1 justify-start text-left cursor-pointer"
                class:text-text={sortField === "alias"}
                class:text-muted={sortField !== "alias"}
                on:click={() => handleSort("alias")}
              >
                <span>Alias</span>
                {#if sortField === "alias"}
                  <span class="text-[9px] tracking-normal">
                    {sortDirection === "asc" ? "↑" : "↓"}
                  </span>
                {/if}
              </button>
            </th>
            <th class="py-2" scope="col" aria-sort={sortAria("tags")}>
              <button
                type="button"
                class="inline-flex w-full items-center gap-1 justify-start text-left cursor-pointer"
                class:text-text={sortField === "tags"}
                class:text-muted={sortField !== "tags"}
                on:click={() => handleSort("tags")}
              >
                <span>Tags</span>
                {#if sortField === "tags"}
                  <span class="text-[9px] tracking-normal">
                    {sortDirection === "asc" ? "↑" : "↓"}
                  </span>
                {/if}
              </button>
            </th>
            <th class="py-2" scope="col" aria-sort={sortAria("mime")}>
              <button
                type="button"
                class="inline-flex w-full items-center gap-1 justify-start text-left cursor-pointer"
                class:text-text={sortField === "mime"}
                class:text-muted={sortField !== "mime"}
                on:click={() => handleSort("mime")}
              >
                <span>Type</span>
                {#if sortField === "mime"}
                  <span class="text-[9px] tracking-normal">
                    {sortDirection === "asc" ? "↑" : "↓"}
                  </span>
                {/if}
              </button>
            </th>
            <th class="py-2 text-right" scope="col" aria-sort={sortAria("nav_title")}>
              <button
                type="button"
                class="inline-flex w-full items-center gap-1 justify-end text-right cursor-pointer"
                class:text-text={sortField === "nav_title"}
                class:text-muted={sortField !== "nav_title"}
                on:click={() => handleSort("nav_title")}
              >
                <span>Nav</span>
                {#if sortField === "nav_title"}
                  <span class="text-[9px] tracking-normal">
                    {sortDirection === "asc" ? "↑" : "↓"}
                  </span>
                {/if}
              </button>
            </th>
            <th class="py-2 text-right" scope="col">Actions</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-border" bind:this={listRef}>
          {#if $loading && items.length === 0 && initialLoad}
            <tr>
              <td class="py-6 text-sm text-muted" colspan="6">Loading content...</td>
            </tr>
          {:else if items.length === 0}
            <tr>
              <td class="py-6 text-sm text-muted" colspan="6">
                No content matches this filter.
              </td>
            </tr>
          {:else}
            {#each items as item, index}
              <tr
                class="cursor-pointer hover:bg-surface-2 focus:bg-surface-2 focus:outline-none"
                data-row-index={index}
                tabindex={$selectedIndex === index ? 0 : -1}
                aria-selected={$selectedIndex === index}
                on:click={() => rowNavigation.handleRowClick(index)}
                on:focus={() => rowNavigation.handleRowFocus(index)}
                on:keydown={rowNavigation.handleKeydown}
              >
                <td class="py-3 font-medium">
                  {item.title ?? "Untitled"}
                </td>
                <td class="py-3 text-muted">
                  {#if item.alias === "index"}
                    <span class="inline-flex items-center rounded-full bg-danger px-2 py-1 text-[10px] uppercase tracking-[0.18em] text-surface">
                      Index
                    </span>
                  {:else}
                    <span>{formatAlias(item)}</span>
                  {/if}
                </td>
                <td class="py-3">
                  {#if item.tags.length === 0}
                    <span class="text-[10px] uppercase tracking-[0.3em] text-muted">—</span>
                  {:else}
                    <span class="text-muted">{item.tags.join(", ")}</span>
                  {/if}
                </td>
                <td class="py-3 text-muted">{item.mime}</td>
                <td class="py-3 text-right">
                  {#if item.navTitle}
                    <span class="text-[11px] text-muted">
                      {item.navTitle}
                    </span>
                  {:else}
                    <span class="text-[10px] uppercase tracking-[0.3em] text-muted">—</span>
                  {/if}
                </td>
                <td
                  class="py-3 text-right"
                  data-row-actions
                  on:click|stopPropagation
                  on:keydown|stopPropagation
                >
                  <Button
                    variant="ghost"
                    size="sm"
                    aria-label="Copy ID URL"
                    on:click={() => copyItemUrl(item, false)}
                  >
                    ID
                  </Button>
                  {#if hasAlias(item)}
                    <Button
                      variant="ghost"
                      size="sm"
                      aria-label="Copy alias URL"
                      on:click={() => copyItemUrl(item, true)}
                    >
                      Alias
                    </Button>
                  {/if}
                  <Button
                    variant="ghost"
                    size="sm"
                    on:click={() => handleDelete(item.id)}
                  >
                    Delete
                  </Button>
                </td>
              </tr>
            {/each}
          {/if}
        </tbody>
      </table>
    </div>

    {#if $loading && items.length > 0}
      <p class="mt-3 text-xs uppercase tracking-[0.3em] text-muted">Updating results...</p>
    {/if}

    <div class="mt-4">
      <Pagination
        {page}
        {pageSize}
        {total}
        on:pageChange={(event) => loadPage(event.detail)}
      />
    </div>
  </div>

  <UploadOverlay
    open={uploadOverlayOpen}
    title="Drop files to upload"
    description="Upload one or more files. You can update aliases, titles, and tags before saving."
    on:close={closeUploadOverlay}
    on:files={(event) => handleOverlayFiles(event.detail.files)}
  />
  <UploadQueueModal
    open={uploadModalOpen}
    bind:items={uploadItems}
    availableTags={availableTags}
    title="Upload Content"
    on:close={closeUploadModal}
    on:uploaded={(event) => handleUploadComplete(event.detail.upload, event.detail.item)}
  />
</section>
