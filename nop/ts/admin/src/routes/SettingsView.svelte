<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->

<script lang="ts">
  import { onMount } from "svelte";
  import Button from "../components/Button.svelte";
  import Input from "../components/Input.svelte";
  import {
    WEBSITE_DESCRIPTION_MAX_CHARS,
    WEBSITE_NAME_MAX_CHARS,
    WEBSITE_TITLE_MAX_CHARS,
  } from "../protocol/settings";
  import type { SettingsResponse } from "../protocol/settings";
  import {
    fetchSettings,
    updateWebsiteDescription,
    updateWebsiteName,
    updateWebsiteTitle,
  } from "../services/settings";
  import { pushNotification } from "../stores/notifications";

  let loading = false;
  let saving = false;
  let settings: SettingsResponse | null = null;
  let websiteName = "";
  let websiteTitle = "";
  let websiteDescription = "";

  $: savedWebsiteName = settings?.name ?? "";
  $: savedWebsiteTitle = settings?.title ?? "";
  $: savedWebsiteDescription = settings?.description ?? "";
  $: normalizedWebsiteName = normalizeInput(websiteName);
  $: normalizedWebsiteTitle = normalizeInput(websiteTitle);
  $: normalizedWebsiteDescription = normalizeInput(websiteDescription);
  $: nameError = validateRequired("Website Name", normalizedWebsiteName, WEBSITE_NAME_MAX_CHARS);
  $: titleError = validateOptional("Website Title", normalizedWebsiteTitle, WEBSITE_TITLE_MAX_CHARS);
  $: descriptionError = validateOptional(
    "Website Description",
    normalizedWebsiteDescription,
    WEBSITE_DESCRIPTION_MAX_CHARS,
  );
  $: hasChanges =
    settings !== null &&
    (normalizedWebsiteName !== normalizeInput(savedWebsiteName) ||
      normalizedWebsiteTitle !== normalizeInput(savedWebsiteTitle) ||
      normalizedWebsiteDescription !== normalizeInput(savedWebsiteDescription));

  onMount(() => {
    void loadSettings();
  });

  async function loadSettings(): Promise<void> {
    loading = true;
    try {
      settings = await fetchSettings();
      syncInputs();
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to load settings";
      pushNotification(message, "error");
    } finally {
      loading = false;
    }
  }

  async function saveSettings(): Promise<void> {
    if (!settings || nameError || titleError || descriptionError) {
      return;
    }
    saving = true;
    try {
      let next = settings;
      if (normalizedWebsiteName !== normalizeInput(settings.name)) {
        next = await updateWebsiteName(normalizedWebsiteName);
      }
      if (normalizedWebsiteTitle !== normalizeInput(next.title ?? "")) {
        next = await updateWebsiteTitle(
          normalizedWebsiteTitle.length > 0 ? normalizedWebsiteTitle : null,
        );
      }
      if (normalizedWebsiteDescription !== normalizeInput(next.description ?? "")) {
        next = await updateWebsiteDescription(
          normalizedWebsiteDescription.length > 0 ? normalizedWebsiteDescription : null,
        );
      }
      settings = next;
      syncInputs();
      pushNotification("Website settings updated", "success");
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Failed to update Website Settings";
      pushNotification(message, "error");
    } finally {
      saving = false;
    }
  }

  function cancelChanges(): void {
    if (!settings) {
      return;
    }
    syncInputs();
  }

  function syncInputs(): void {
    if (!settings) {
      return;
    }
    websiteName = settings.name;
    websiteTitle = settings.title ?? "";
    websiteDescription = settings.description ?? "";
  }

  function normalizeInput(value: string): string {
    return value.trim();
  }

  function validateRequired(label: string, normalized: string, maxChars: number): string {
    if (normalized.length === 0) {
      return `${label} is required`;
    }
    return validateOptional(label, normalized, maxChars);
  }

  function validateOptional(label: string, normalized: string, maxChars: number): string {
    if (normalized.length > maxChars) {
      return `${label} must be at most ${maxChars} characters`;
    }
    if (/[\u0000-\u001f\u007f]/.test(normalized)) {
      return `${label} must not contain control characters`;
    }
    return "";
  }
</script>

<section class="flex flex-col gap-5">
  <header class="sticky top-14 z-20 -mx-6 border-b border-border bg-background/95 px-4 py-3 backdrop-blur md:static md:mx-0 md:border-none md:bg-transparent md:px-0 md:py-0 flex flex-wrap items-center justify-between gap-3">
    <div>
      <p class="text-[11px] uppercase tracking-[0.35em] text-muted">Settings</p>
      <h2 class="mt-2 text-xl">Website</h2>
    </div>
  </header>

  <div class="-mx-6 bg-surface px-4 py-4 md:mx-0 md:rounded-lg md:border md:border-border md:px-5 md:py-5 md:shadow-soft">
    <div class="flex items-start justify-between gap-4">
      <div>
        <p class="text-[11px] uppercase tracking-[0.3em] text-muted">Website Identity</p>
        <h3 class="mt-2 text-lg">Display and metadata</h3>
      </div>
    </div>

    {#if loading && !settings}
      <p class="py-6 text-sm text-muted">Loading settings...</p>
    {:else if !settings}
      <p class="py-6 text-sm text-muted">Unable to load settings.</p>
    {:else}
      <div class="mt-4 grid max-w-xl gap-4">
        <div>
          <label for="website-name" class="text-[11px] uppercase tracking-[0.3em] text-muted">
            Website Name
          </label>
          <Input
            id="website-name"
            bind:value={websiteName}
            className="mt-2"
            placeholder="NoPressure"
            error={nameError}
            disabled={saving || loading}
          />
        </div>

        <div>
        <label for="website-title" class="text-[11px] uppercase tracking-[0.3em] text-muted">
          Website Title
        </label>
        <Input
          id="website-title"
          bind:value={websiteTitle}
          className="mt-2"
          placeholder="Example Site"
          error={titleError}
          disabled={saving || loading}
        />
        </div>

        <div>
          <label for="website-description" class="text-[11px] uppercase tracking-[0.3em] text-muted">
            Website Description
          </label>
          <Input
            id="website-description"
            bind:value={websiteDescription}
            className="mt-2"
            placeholder="A concise public page description"
            error={descriptionError}
            disabled={saving || loading}
          />
        </div>
      </div>

      <div class="mt-5 flex flex-wrap items-center justify-between gap-3 border-t border-border pt-4">
        <div class="text-xs text-muted">
          {settings.name}
        </div>
        <div class="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            on:click={cancelChanges}
            disabled={!hasChanges || saving || loading}
          >
            Cancel
          </Button>
          <Button
            variant="primary"
            size="sm"
            on:click={saveSettings}
            disabled={!hasChanges || Boolean(nameError || titleError || descriptionError) || saving || loading}
          >
            {saving ? "Saving" : "Save"}
          </Button>
        </div>
      </div>
    {/if}
  </div>
</section>
