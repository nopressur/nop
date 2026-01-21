<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->

<script lang="ts">
  import { createEventDispatcher } from "svelte";
  import Button from "./Button.svelte";

  export let open = false;
  export let title = "Drop files to upload";
  export let description = "Drop files anywhere or choose files to upload.";

  const dispatch = createEventDispatcher<{
    close: void;
    files: { files: File[] };
  }>();

  let dragDepth = 0;
  let dragActive = false;
  let fileInput: HTMLInputElement | null = null;
  let container: HTMLDivElement | null = null;

  $: if (!open) {
    dragDepth = 0;
    dragActive = false;
  }

  $: if (open && container) {
    container.focus();
  }

  function openPicker(): void {
    fileInput?.click();
  }

  function handleClose(): void {
    dispatch("close");
  }

  function handleFiles(files: File[]): void {
    if (files.length === 0) {
      return;
    }
    dispatch("files", { files });
  }

  function handleFileChange(event: Event): void {
    const target = event.target as HTMLInputElement | null;
    const files = target?.files ? Array.from(target.files) : [];
    if (target) {
      target.value = "";
    }
    handleFiles(files);
  }

  function handleDragEnter(event: DragEvent): void {
    event.preventDefault();
    dragDepth += 1;
    dragActive = true;
  }

  function handleDragOver(event: DragEvent): void {
    event.preventDefault();
  }

  function handleDragLeave(event: DragEvent): void {
    event.preventDefault();
    dragDepth = Math.max(0, dragDepth - 1);
    if (dragDepth === 0) {
      dragActive = false;
    }
  }

  function handleDrop(event: DragEvent): void {
    event.preventDefault();
    dragDepth = 0;
    dragActive = false;
    const files = event.dataTransfer ? Array.from(event.dataTransfer.files) : [];
    handleFiles(files);
  }

  function handleKeydown(event: KeyboardEvent): void {
    if (event.key !== "Escape") {
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    handleClose();
  }
</script>

{#if open}
  <div class="fixed inset-0 z-40 bg-black/50" aria-hidden="true"></div>
  <div
    class="fixed inset-0 z-50 flex items-center justify-center p-6"
    role="region"
    aria-label="Upload drop zone"
    on:dragenter={handleDragEnter}
    on:dragover={handleDragOver}
    on:dragleave={handleDragLeave}
    on:drop={handleDrop}
  >
    <div
      class={`flex w-full max-w-2xl flex-col items-center gap-4 rounded-lg border-2 border-dashed px-6 py-10 text-center transition ${
        dragActive ? "border-accent bg-surface" : "border-border bg-surface/95"
      }`}
      role="dialog"
      aria-modal="true"
      aria-label={title}
      tabindex="-1"
      bind:this={container}
      on:keydown={handleKeydown}
    >
      <div class="text-[11px] uppercase tracking-[0.35em] text-muted">Upload</div>
      <div class="text-lg">{title}</div>
      <div class="max-w-lg text-sm text-muted">{description}</div>
      <input
        bind:this={fileInput}
        type="file"
        class="sr-only"
        multiple
        on:change={handleFileChange}
      />
      <div class="flex items-center gap-3">
        <Button variant="primary" size="sm" on:click={openPicker}>Select files</Button>
        <Button variant="outline" size="sm" on:click={handleClose}>Cancel</Button>
      </div>
    </div>
  </div>
{/if}
