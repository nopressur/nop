<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->

<script lang="ts">
  import { createEventDispatcher } from "svelte";
  import Button from "./Button.svelte";
  import CompactMultiSelect from "./CompactMultiSelect.svelte";
  import Input from "./Input.svelte";
  import { pushNotification } from "../stores/notifications";
  import { confirmDialog } from "../stores/confirmDialog";
  import { uploadBinaryFile } from "../services/content";
  import type { UploadItem } from "../types/uploads";

  export let open = false;
  export let items: UploadItem[] = [];
  export let title = "Upload Assets";
  export let availableTags: string[] = [];

  const dispatch = createEventDispatcher<{
    close: void;
    uploaded: { upload: { id: string; alias: string; mime: string }; item: UploadItem };
  }>();

  let container: HTMLDivElement | null = null;

  const busyStates = new Set<UploadItem["status"]>(["prechecking", "uploading"]);

  $: showSaveAll = items.length > 1;
  $: anyUploading = items.some((item) =>
    item.status === "uploading" || item.status === "prechecking"
  );

  $: if (open && container) {
    container.focus();
  }

  function updateItem(id: string, updates: Partial<UploadItem>): void {
    items = items.map((item) => (item.id === id ? { ...item, ...updates } : item));
  }

  function removeItem(id: string): void {
    items = items.filter((item) => item.id !== id);
  }

  function handleFieldChange(
    id: string,
    field: "alias" | "title",
    value: string,
  ): void {
    const updates: Partial<UploadItem> = { error: null, status: "ready" };
    if (field === "alias") {
      updates.alias = value;
    } else if (field === "title") {
      updates.title = value;
    }
    updateItem(id, updates);
  }

  function handleTagsChange(id: string, tags: string[]): void {
    updateItem(id, { tags, error: null, status: "ready" });
  }

  async function handleClose(): Promise<void> {
    if (items.length > 0) {
      const confirmed = await confirmDialog({
        title: "Discard uploads",
        message: "Discard pending uploads?",
        confirmLabel: "Discard",
        tone: "danger",
      });
      if (!confirmed) {
        return;
      }
    }
    dispatch("close");
  }

  function handleKeydown(event: KeyboardEvent): void {
    if (event.key !== "Escape") {
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    void handleClose();
  }

  function formatSize(bytes: number): string {
    if (!Number.isFinite(bytes) || bytes <= 0) {
      return "0 B";
    }
    const units = ["B", "KB", "MB", "GB"];
    let value = bytes;
    let idx = 0;
    while (value >= 1024 && idx < units.length - 1) {
      value /= 1024;
      idx += 1;
    }
    return `${value.toFixed(value >= 10 || idx === 0 ? 0 : 1)} ${units[idx]}`;
  }

  async function saveItem(id: string): Promise<void> {
    const item = items.find((entry) => entry.id === id);
    if (!item || busyStates.has(item.status) || item.status === "rejected") {
      return;
    }

    const tags = item.tags;

    try {
      updateItem(id, {
        status: "uploading",
        error: null,
        progress: { loaded: 0, total: item.file.size }
      });
      const upload = await uploadBinaryFile({
        alias: item.alias.trim() || null,
        title: item.title.trim() || null,
        tags,
        file: item.file,
        onProgress: (loaded, total) => {
          updateItem(id, { progress: { loaded, total } });
        }
      });
      pushNotification("Upload complete", "success");
      removeItem(id);
      dispatch("uploaded", { upload, item });
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to upload";
      updateItem(id, { status: "error", error: message, progress: null });
    }
  }

  async function saveAll(): Promise<void> {
    if (items.length === 0) {
      return;
    }
    const ids = items
      .filter((item) => item.status === "ready" || item.status === "error")
      .map((item) => item.id);
    for (const id of ids) {
      await saveItem(id);
    }
  }

  function progressPercent(item: UploadItem): number {
    if (!item.progress || item.progress.total <= 0) {
      return 0;
    }
    return Math.min(100, Math.round((item.progress.loaded / item.progress.total) * 100));
  }
</script>

{#if open}
  <div class="fixed inset-0 z-40 bg-black/40" aria-hidden="true"></div>
  <div
    class="fixed left-1/2 top-1/2 z-50 w-[94vw] max-w-3xl -translate-x-1/2 -translate-y-1/2 rounded-lg border border-border bg-surface p-5 shadow-soft"
    role="dialog"
    aria-modal="true"
    aria-label={title}
    tabindex="-1"
    bind:this={container}
    on:keydown={handleKeydown}
  >
    <div class="flex items-center justify-between gap-3">
      <div>
        <p class="text-[11px] uppercase tracking-[0.3em] text-muted">{title}</p>
        <p class="mt-1 text-xs text-muted">
          Edit aliases, titles, and tags before saving each file.
        </p>
      </div>
      <Button variant="outline" size="sm" on:click={() => void handleClose()}>Close</Button>
    </div>

    {#if showSaveAll}
      <div class="mt-4 flex justify-end">
        <Button
          variant="primary"
          size="sm"
          disabled={anyUploading}
          on:click={saveAll}
        >
          Save all
        </Button>
      </div>
    {/if}

    <div class="mt-4 max-h-[60vh] space-y-4 overflow-y-auto pr-1">
      {#each items as item (item.id)}
        <div class="rounded-lg border border-border bg-surface-2 p-4">
          <div class="flex flex-wrap items-center justify-between gap-2">
            <div class="text-sm font-semibold text-text">{item.file.name}</div>
            <div class="text-[10px] uppercase tracking-[0.2em] text-muted">
              {formatSize(item.file.size)}
            </div>
          </div>
          {#if item.status === "prechecking"}
            <p class="mt-3 text-xs uppercase tracking-[0.3em] text-muted">
              Checking file...
            </p>
          {:else if item.status === "rejected"}
            <p class="mt-3 text-xs text-danger">
              {item.error ?? "This file cannot be uploaded."}
            </p>
            <div class="mt-4 flex justify-end">
              <Button variant="outline" size="sm" on:click={() => removeItem(item.id)}>
                Remove
              </Button>
            </div>
          {:else if item.status === "uploading"}
            <div class="mt-3">
              <div class="flex items-center justify-between text-[11px] text-muted">
                <span class="uppercase tracking-[0.2em]">Uploading</span>
                <span>{progressPercent(item)}%</span>
              </div>
              <div class="mt-2 h-2 w-full rounded-full bg-border/40">
                <div
                  class="h-2 rounded-full bg-accent"
                  style={`width: ${progressPercent(item)}%`}
                ></div>
              </div>
              {#if item.progress}
                <div class="mt-2 text-[11px] text-muted">
                  {formatSize(item.progress.loaded)} / {formatSize(item.progress.total)}
                </div>
              {/if}
            </div>
          {:else}
            {#if item.error}
              <p class="mt-3 text-xs text-danger">{item.error}</p>
            {/if}
            <form
              class="mt-3"
              on:submit|preventDefault={() => saveItem(item.id)}
              aria-label="Upload metadata"
            >
              <div class="grid gap-3 md:grid-cols-2" role="group">
                <div>
                  <label
                    class="text-[11px] uppercase tracking-[0.3em] text-muted"
                    for={`upload-alias-${item.id}`}
                  >
                    Alias
                  </label>
                  <Input
                    id={`upload-alias-${item.id}`}
                    value={item.alias}
                    className="mt-2"
                    on:input={(event) =>
                      handleFieldChange(item.id, "alias", (event as CustomEvent<string>).detail)
                    }
                  />
                </div>
                <div>
                  <label
                    class="text-[11px] uppercase tracking-[0.3em] text-muted"
                    for={`upload-title-${item.id}`}
                  >
                    Title
                  </label>
                  <Input
                    id={`upload-title-${item.id}`}
                    value={item.title}
                    className="mt-2"
                    on:input={(event) =>
                      handleFieldChange(item.id, "title", (event as CustomEvent<string>).detail)
                    }
                  />
                </div>
                <div class="md:col-span-2">
                  <label
                    class="text-[11px] uppercase tracking-[0.3em] text-muted"
                    for={`upload-tags-${item.id}`}
                  >
                    Tags
                  </label>
                  <div class="mt-2">
                    <CompactMultiSelect
                      id={`upload-tags-${item.id}`}
                      selected={item.tags}
                      options={availableTags}
                      placeholder="Select tags"
                      emptyLabel="No tags"
                      on:change={(event) =>
                        handleTagsChange(item.id, (event as CustomEvent<string[]>).detail)
                      }
                    />
                  </div>
                </div>
              </div>
              <div class="mt-4 flex justify-end gap-2">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  disabled={busyStates.has(item.status)}
                  on:click={() => removeItem(item.id)}
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  variant="primary"
                  size="sm"
                  disabled={busyStates.has(item.status)}
                >
                  Save
                </Button>
              </div>
            </form>
          {/if}
        </div>
      {/each}
    </div>

    {#if showSaveAll}
      <div class="mt-4 flex justify-end">
        <Button
          variant="primary"
          size="sm"
          disabled={anyUploading}
          on:click={saveAll}
        >
          Save all
        </Button>
      </div>
    {/if}
  </div>
{/if}
