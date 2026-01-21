<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->

<script lang="ts">
  import { onMount } from "svelte";
  import Button from "../components/Button.svelte";
  import { useListViewLogic } from "./useListViewLogic";
  import { navigate } from "../stores/router";
  import { deleteTag, listTags } from "../services/tags";

  let tags: Awaited<ReturnType<typeof listTags>> = [];
  let listRef: HTMLTableSectionElement | null = null;

  const {
    loading,
    rowNavigation,
    selectedIndex,
    syncRowNavigation,
    runWithLoading,
    confirmAndDelete,
  } = useListViewLogic({
    onOpen: (index) => openTag(index),
  });

  onMount(() => {
    void loadTags();
  });

  async function loadTags(): Promise<void> {
    const result = await runWithLoading(listTags, "Failed to load tags");
    if (result) {
      tags = result;
    }
  }

  async function removeTag(id: string): Promise<void> {
    await confirmAndDelete({
      confirmMessage: `Delete tag '${id}'? This will remove the tag from all content, may change access, and cannot be undone.`,
      onDelete: () => deleteTag(id),
      successMessage: "Tag deleted",
      errorMessage: "Failed to delete tag",
      onComplete: () => loadTags(),
    });
  }

  function openTag(index: number): void {
    const tag = tags[index];
    if (!tag) {
      return;
    }
    navigate(`/tags/edit?id=${encodeURIComponent(tag.id)}`);
  }

  $: syncRowNavigation(listRef, tags.length);
</script>

<section class="flex flex-col gap-5">
  <header class="sticky top-14 z-20 -mx-6 border-b border-border bg-background/95 px-4 py-3 backdrop-blur md:static md:mx-0 md:border-none md:bg-transparent md:px-0 md:py-0 flex flex-wrap items-center justify-between gap-3">
    <div>
      <p class="text-[11px] uppercase tracking-[0.35em] text-muted">Tags</p>
      <h2 class="mt-2 text-xl">Tag Catalog</h2>
    </div>
    <Button variant="primary" size="sm" on:click={() => navigate("/tags/new")}>
      New Tag
    </Button>
  </header>

  <div class="-mx-6 bg-surface px-4 py-2 md:mx-0 md:rounded-lg md:border md:border-border md:px-4 md:py-4 md:shadow-soft">
    <div class="md:hidden">
      {#if $loading}
        <p class="py-6 text-sm text-muted">Loading tags...</p>
      {:else if tags.length === 0}
        <p class="py-6 text-sm text-muted">No tags found.</p>
      {:else}
        <div class="divide-y divide-border">
          {#each tags as tag}
            <div class="flex items-start justify-between gap-4 py-4">
              <div class="min-w-0">
                <button
                  type="button"
                  class="w-full text-left text-sm font-semibold leading-snug text-text break-words"
                  on:click={() => navigate(`/tags/edit?id=${encodeURIComponent(tag.id)}`)}
                >
                  {tag.name}
                </button>
                <div class="mt-1 text-[10px] uppercase tracking-[0.28em] text-muted font-semibold break-words">
                  {tag.id}
                </div>
              </div>
              <div class="flex items-center gap-2 shrink-0">
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 w-7 px-0 text-[10px] tracking-[0.12em] text-accent border-accent"
                  on:click={() => navigate(`/tags/edit?id=${encodeURIComponent(tag.id)}`)}
                >
                  <span aria-hidden="true">E</span>
                  <span class="sr-only">Edit</span>
                </Button>
                <Button
                  variant="danger"
                  size="sm"
                  className="h-7 w-7 px-0 text-[10px] tracking-[0.12em]"
                  on:click={() => removeTag(tag.id)}
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

    <div class="hidden md:block">
      <table class="w-full text-left text-sm">
        <thead class="text-[10px] uppercase tracking-[0.3em] text-muted">
          <tr>
            <th class="py-2">ID</th>
            <th class="py-2">Name</th>
            <th class="py-2 text-right">Actions</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-border" bind:this={listRef}>
          {#if $loading}
            <tr>
              <td class="py-6 text-sm text-muted" colspan="3">Loading tags...</td>
            </tr>
          {:else if tags.length === 0}
            <tr>
              <td class="py-6 text-sm text-muted" colspan="3">No tags found.</td>
            </tr>
          {:else}
            {#each tags as tag, index}
              <tr
                class="cursor-pointer hover:bg-surface-2 focus:bg-surface-2 focus:outline-none"
                data-row-index={index}
                tabindex={$selectedIndex === index ? 0 : -1}
                aria-selected={$selectedIndex === index}
                on:click={() => rowNavigation.handleRowClick(index)}
                on:focus={() => rowNavigation.handleRowFocus(index)}
                on:keydown={rowNavigation.handleKeydown}
              >
                <td class="py-3 font-medium">{tag.id}</td>
                <td class="py-3 text-muted">{tag.name}</td>
                <td
                  class="py-3 text-right"
                  data-row-actions
                  on:click|stopPropagation
                  on:keydown|stopPropagation
                >
                  <Button
                    variant="ghost"
                    size="sm"
                    on:click={() => navigate(`/tags/edit?id=${encodeURIComponent(tag.id)}`)}
                  >
                    Edit
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    on:click={() => removeTag(tag.id)}
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
  </div>
</section>
