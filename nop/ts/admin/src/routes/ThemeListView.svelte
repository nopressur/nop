<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->

<script lang="ts">
  import { onMount } from "svelte";
  import Button from "../components/Button.svelte";
  import { getAdminBootstrap } from "../config/runtime";
  import { reloadWindow } from "../services/browser";
  import { useListViewLogic } from "./useListViewLogic";
  import { navigate } from "../stores/router";
  import { deleteTheme } from "../services/themes";

  type ThemeListItem = {
    name: string;
    is_default: boolean;
    file_size: number;
    file_size_formatted: string;
    customize_url: string;
  };

  const bootstrap = getAdminBootstrap<{ themes?: ThemeListItem[] }>();
  const themes = bootstrap?.themes ?? [];
  let listRef: HTMLTableSectionElement | null = null;

  const { rowNavigation, selectedIndex, syncRowNavigation, confirmAndDelete } =
    useListViewLogic({
      onOpen: (index) => openTheme(index),
    });

  onMount(() => {
    if (!bootstrap || bootstrap.themes === undefined) {
      reloadWindow();
    }
  });

  async function removeTheme(themeName: string): Promise<void> {
    await confirmAndDelete({
      confirmMessage: `Delete theme '${themeName}'?`,
      onDelete: async () => {
        const response = await deleteTheme(themeName);
        return { message: response.message, tone: response.success ? "success" : "error" };
      },
      errorMessage: "Failed to delete theme",
      onComplete: () => reloadWindow(),
    });
  }

  function openTheme(index: number): void {
    const theme = themes[index];
    if (!theme) {
      return;
    }
    navigate(`/themes/customize/${theme.name}`);
  }

  $: syncRowNavigation(listRef, themes.length);
</script>

<section class="flex flex-col gap-5">
  <header class="sticky top-14 z-20 -mx-6 border-b border-border bg-background/95 px-4 py-3 backdrop-blur md:static md:mx-0 md:border-none md:bg-transparent md:px-0 md:py-0 flex flex-wrap items-center justify-between gap-3">
    <div>
      <p class="text-[11px] uppercase tracking-[0.35em] text-muted">Themes</p>
      <h2 class="mt-2 text-xl">Theme Library</h2>
    </div>
    <Button variant="primary" size="sm" on:click={() => navigate("/themes/new")}>
      New Theme
    </Button>
  </header>

  <div class="-mx-6 bg-surface px-4 py-2 md:mx-0 md:rounded-lg md:border md:border-border md:px-4 md:py-4 md:shadow-soft">
    <div class="md:hidden">
      {#if themes.length === 0}
        <p class="py-6 text-sm text-muted">No themes found.</p>
      {:else}
        <div class="divide-y divide-border">
          {#each themes as theme}
            <div class="flex items-start justify-between gap-4 py-4">
              <div class="min-w-0">
                <button
                  type="button"
                  class="w-full text-left text-sm font-semibold leading-snug text-text break-words"
                  on:click={() => navigate(`/themes/customize/${theme.name}`)}
                >
                  <span class="inline-flex items-center gap-2">
                    <span>{theme.name}</span>
                    {#if theme.is_default}
                      <span class="text-success text-xs" aria-label="Default theme">✓</span>
                    {/if}
                  </span>
                </button>
                <div class="mt-1 text-[10px] uppercase tracking-[0.24em] text-muted">
                  {theme.file_size_formatted}
                </div>
              </div>
              <div class="flex items-center gap-2 shrink-0">
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 w-7 px-0 text-[10px] tracking-[0.12em] text-accent border-accent"
                  on:click={() => navigate(`/themes/customize/${theme.name}`)}
                >
                  <span aria-hidden="true">E</span>
                  <span class="sr-only">Edit</span>
                </Button>
                <Button
                  variant="danger"
                  size="sm"
                  disabled={theme.is_default}
                  className="h-7 w-7 px-0 text-[10px] tracking-[0.12em]"
                  on:click={() => removeTheme(theme.name)}
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
            <th class="py-2">Theme</th>
            <th class="py-2">Size</th>
            <th class="py-2 text-right">Actions</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-border" bind:this={listRef}>
          {#if themes.length === 0}
            <tr>
              <td class="py-6 text-sm text-muted" colspan="3">
                No themes found.
              </td>
            </tr>
          {:else}
            {#each themes as theme, index}
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
                  <div class="inline-flex items-center gap-2">
                    <span>{theme.name}</span>
                    {#if theme.is_default}
                      <span class="text-success text-xs" aria-label="Default theme">✓</span>
                    {/if}
                  </div>
                </td>
                <td class="py-3 text-muted">{theme.file_size_formatted}</td>
                <td
                  class="py-3 text-right"
                  data-row-actions
                  on:click|stopPropagation
                  on:keydown|stopPropagation
                >
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled={theme.is_default}
                    on:click={() => removeTheme(theme.name)}
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
