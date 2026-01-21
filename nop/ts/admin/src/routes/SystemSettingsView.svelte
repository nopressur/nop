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
  import type { LoggingConfigResponse } from "../protocol/system";
  import { confirmDialog } from "../stores/confirmDialog";
  import { clearLogs, fetchLoggingConfig, updateLoggingConfig } from "../services/system";
  import { pushNotification } from "../stores/notifications";

  let loading = false;
  let saving = false;
  let clearing = false;
  let loggingConfig: LoggingConfigResponse | null = null;
  let maxSizeMb = "";
  let maxFiles = "";

  $: hasLoggingChanges = (() => {
    if (!loggingConfig) {
      return false;
    }
    const sizeValue = String(maxSizeMb).trim();
    const fileValue = String(maxFiles).trim();
    return (
      sizeValue !== String(loggingConfig.rotation_max_size_mb) ||
      fileValue !== String(loggingConfig.rotation_max_files)
    );
  })();

  $: showForegroundNotice =
    loggingConfig !== null &&
    (loggingConfig.run_mode !== "daemon" || !loggingConfig.file_logging_active);

  onMount(() => {
    void loadLoggingConfig();
  });

  async function loadLoggingConfig(): Promise<void> {
    loading = true;
    try {
      loggingConfig = await fetchLoggingConfig();
      maxSizeMb = String(loggingConfig.rotation_max_size_mb);
      maxFiles = String(loggingConfig.rotation_max_files);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Failed to load system settings";
      pushNotification(message, "error");
    } finally {
      loading = false;
    }
  }

  async function saveLoggingConfig(): Promise<void> {
    if (!loggingConfig) {
      return;
    }
    const size = Number(maxSizeMb);
    const files = Number(maxFiles);
    if (!Number.isInteger(size) || size < 1 || size > 1024) {
      pushNotification("Max size must be an integer between 1 and 1024", "error");
      return;
    }
    if (!Number.isInteger(files) || files < 1 || files > 100) {
      pushNotification("Max files must be an integer between 1 and 100", "error");
      return;
    }

    saving = true;
    try {
      loggingConfig = await updateLoggingConfig({
        rotationMaxSizeMb: size,
        rotationMaxFiles: files,
      });
      maxSizeMb = String(loggingConfig.rotation_max_size_mb);
      maxFiles = String(loggingConfig.rotation_max_files);
      pushNotification("Logging settings updated", "success");
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Failed to update logging settings";
      pushNotification(message, "error");
    } finally {
      saving = false;
    }
  }

  function cancelLoggingChanges(): void {
    if (!loggingConfig) {
      return;
    }
    maxSizeMb = String(loggingConfig.rotation_max_size_mb);
    maxFiles = String(loggingConfig.rotation_max_files);
  }

  async function handleClearLogs(): Promise<void> {
    const confirmed = await confirmDialog({
      title: "Clear logs",
      message: "Clear all log files? This cannot be undone.",
      confirmLabel: "Clear logs",
      tone: "danger",
    });
    if (!confirmed) {
      return;
    }
    clearing = true;
    try {
      const response = await clearLogs();
      pushNotification(response.message, "success");
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Failed to clear logs";
      pushNotification(message, "error");
    } finally {
      clearing = false;
    }
  }
</script>

<section class="flex flex-col gap-5">
  <header class="sticky top-14 z-20 -mx-6 border-b border-border bg-background/95 px-4 py-3 backdrop-blur md:static md:mx-0 md:border-none md:bg-transparent md:px-0 md:py-0 flex flex-wrap items-center justify-between gap-3">
    <div>
      <p class="text-[11px] uppercase tracking-[0.35em] text-muted">System</p>
      <h2 class="mt-2 text-xl">Runtime Settings</h2>
    </div>
  </header>

  <div class="-mx-6 bg-surface px-4 py-4 md:mx-0 md:rounded-lg md:border md:border-border md:px-5 md:py-5 md:shadow-soft">
    <div class="flex items-start justify-between gap-4">
      <div>
        <p class="text-[11px] uppercase tracking-[0.3em] text-muted">Logging</p>
        <h3 class="mt-2 text-lg">Rotation</h3>
      </div>
      {#if loggingConfig}
        <div class="text-[10px] uppercase tracking-[0.3em] text-muted text-right">
          <div>Run mode: {loggingConfig.run_mode}</div>
          <div>
            File logging: {loggingConfig.file_logging_active ? "active" : "inactive"}
          </div>
        </div>
      {/if}
    </div>

    {#if loading && !loggingConfig}
      <p class="py-6 text-sm text-muted">Loading logging settings...</p>
    {:else if !loggingConfig}
      <p class="py-6 text-sm text-muted">Unable to load logging settings.</p>
    {:else}
      <div class="mt-4 grid gap-4 md:grid-cols-2">
        <div>
          <label for="logging-size" class="text-[11px] uppercase tracking-[0.3em] text-muted">
            Max size (MB)
          </label>
          <Input
            id="logging-size"
            type="number"
            bind:value={maxSizeMb}
            className="mt-2"
            placeholder="16"
            disabled={saving || loading}
          />
        </div>
        <div>
          <label for="logging-files" class="text-[11px] uppercase tracking-[0.3em] text-muted">
            Max files
          </label>
          <Input
            id="logging-files"
            type="number"
            bind:value={maxFiles}
            className="mt-2"
            placeholder="10"
            disabled={saving || loading}
          />
        </div>
      </div>

      {#if showForegroundNotice}
        <div class="mt-4 rounded-md border border-border bg-surface-2 px-4 py-3 text-xs text-muted">
          Log files are inactive because the server is running in the foreground. Changes
          will apply the next time the daemon starts.
        </div>
      {/if}

      <div class="mt-5 flex flex-wrap items-center justify-between gap-3 border-t border-border pt-4">
        <div class="text-xs text-muted">
          Changes apply to future rotations and do not resize existing files.
        </div>
        <div class="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            on:click={cancelLoggingChanges}
            disabled={!hasLoggingChanges || saving || loading}
          >
            Cancel
          </Button>
          <Button
            variant="primary"
            size="sm"
            on:click={saveLoggingConfig}
            disabled={!hasLoggingChanges || saving || loading}
          >
            {saving ? "Saving" : "Save"}
          </Button>
        </div>
      </div>

      <div class="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-border pt-4">
        <div class="text-xs text-muted">Delete all existing log files.</div>
        <Button
          variant="danger"
          size="sm"
          on:click={handleClearLogs}
          disabled={clearing || loading}
        >
          {clearing ? "Clearing" : "Clear Logs"}
        </Button>
      </div>
    {/if}
  </div>
</section>
