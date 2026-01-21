<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->

<script lang="ts">
  import { onDestroy, onMount } from "svelte";
  import AceEditor from "../components/AceEditor.svelte";
  import Button from "../components/Button.svelte";
  import Input from "../components/Input.svelte";
  import { getAdminBootstrap } from "../config/runtime";
  import {
    addWindowListener,
    reloadWindow,
    removeWindowListener,
    setLocationHref,
  } from "../services/browser";
  import { pushNotification } from "../stores/notifications";
  import { navigate } from "../stores/router";
  import { createTheme, saveTheme } from "../services/themes";
  import { validateFileName } from "../validation/filename";

  type ThemeBootstrap = {
    theme?: {
      mode: "new" | "customize";
      name: string | null;
      content: string;
    };
    error?: {
      code: string;
      message: string;
      theme?: string;
    };
  };

  const bootstrap = getAdminBootstrap<ThemeBootstrap>();
  const theme = bootstrap?.theme;
  const error = bootstrap?.error;
  let themeName = theme?.name ?? "";
  let content = theme?.content ?? "";
  let saving = false;

  onMount(() => {
    if (!theme && !error) {
      reloadWindow();
    }
    addWindowListener("keydown", handleKeydown);
  });

  onDestroy(() => {
    removeWindowListener("keydown", handleKeydown);
  });

  function cancelEdit(): void {
    navigate("/themes");
  }

  function handleKeydown(event: KeyboardEvent): void {
    const isSaveKey =
      (event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "s";
    if (isSaveKey) {
      event.preventDefault();
      void handleSave();
      return;
    }
    if (event.key === "Escape") {
      event.preventDefault();
      cancelEdit();
    }
  }

  async function handleSave(): Promise<void> {
    if (!theme) {
      return;
    }
    if (theme.mode === "new") {
      const nameValue = themeName.trim();
      const validation = validateFileName(nameValue);
      if (!validation.valid) {
        pushNotification(validation.error, "error");
        return;
      }
      saving = true;
      try {
        const response = await createTheme(nameValue, content);
        pushNotification(response.message, response.success ? "success" : "error");
        if (response.redirect) {
          setLocationHref(response.redirect);
        } else {
          navigate("/themes");
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : "Failed to create theme";
        pushNotification(message, "error");
      } finally {
        saving = false;
      }
      return;
    }

    if (!theme.name) {
      pushNotification("Theme name missing", "error");
      return;
    }
    saving = true;
    try {
      const response = await saveTheme(theme.name, content);
      pushNotification(response.message, response.success ? "success" : "error");
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to save theme";
      pushNotification(message, "error");
    } finally {
      saving = false;
    }
  }
</script>

<section class="flex flex-1 flex-col gap-5 min-h-0">
  <header class="flex flex-wrap items-center justify-between gap-3">
    <div>
      <p class="text-[11px] uppercase tracking-[0.35em] text-muted">Themes</p>
      <h2 class="mt-2 text-xl">
        {#if theme?.mode === "new"}
          Create Theme
        {:else if theme?.name}
          Customize {theme.name}
        {:else}
          Customize Theme
        {/if}
      </h2>
    </div>
    <div class="flex items-center gap-2">
      <Button variant="outline" size="sm" on:click={() => navigate("/themes")}>
        Cancel
      </Button>
      <Button variant="primary" size="sm" on:click={handleSave} disabled={saving}>
        {saving ? "Saving" : "Save"}
      </Button>
    </div>
  </header>

  {#if error}
    <div class="rounded-lg border border-danger bg-surface px-4 py-4 text-sm text-danger">
      {error.message}
    </div>
  {:else if theme}
    <div class="flex flex-1 flex-col rounded-lg border border-border bg-surface px-4 py-4 shadow-soft min-h-0">
      <p class="text-[11px] uppercase tracking-[0.3em] text-muted">HTML</p>
      {#if theme.mode === "new"}
        <div class="mt-3 max-w-sm">
          <label for="theme-name" class="text-[11px] uppercase tracking-[0.3em] text-muted">Theme Name</label>
          <Input id="theme-name" bind:value={themeName} className="mt-2" />
        </div>
      {/if}
      <div class="mt-4 flex-1 min-h-[280px] rounded-lg border border-border bg-surface-2">
        <AceEditor bind:value={content} mode="html" />
      </div>
    </div>
  {:else}
    <div class="rounded-lg border border-border bg-surface px-4 py-4 text-sm text-muted">
      Theme data will load here.
    </div>
  {/if}
</section>
