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
  import ChipSelect from "../components/ChipSelect.svelte";
  import CompactButton from "../components/CompactButton.svelte";
  import Input from "../components/Input.svelte";
  import InsertContentModal from "../components/InsertContentModal.svelte";
  import UnsavedChangesModal from "../components/UnsavedChangesModal.svelte";
  import Select from "../components/Select.svelte";
  import UploadOverlay from "../components/UploadOverlay.svelte";
  import UploadQueueModal from "../components/UploadQueueModal.svelte";
  import {
    addWindowListener,
    removeWindowListener,
  } from "../services/browser";
  import { confirmDialog } from "../stores/confirmDialog";
  import { getAdminRuntimeConfig } from "../config/runtime";
  import { pushNotification } from "../stores/notifications";
  import { route, navigate } from "../stores/router";
  import {
    buildInsertSnippet,
    createMarkdownStream,
    defaultAliasForFile,
    deleteContent,
    listNavIndex,
    parseContentTags,
    prevalidateBinaryUpload,
    readContent,
    updateContent,
    updateMarkdownStream,
  } from "../services/content";
  import type { ContentListItem, ContentNavIndexItem } from "../services/content";
  import { listTags } from "../services/tags";
  import { listThemes } from "../services/themes";
  import { normalizeAlias } from "../validation/alias";
  import type { UploadItem } from "../types/uploads";
  import {
    buildEditorSnapshot,
    isEditorDirty,
    normalizeNavOrderValue,
    type ContentEditorSnapshot,
  } from "./contentEditorState";

  let alias = "";
  let title = "";
  let selectedTags: string[] = [];
  let availableTags: string[] = [];
  let navTitle = "";
  let navParentId = "";
  let navOrder = "";
  let theme = "";
  let availableThemes: string[] = [];
  let mime = "text/markdown";
  let originalFilename = "";
  let isMarkdown = true;
  let contentValue = "# New Page\n";
  let currentAlias = "";
  let contentId = "";
  let loading = false;
  let tagsLoading = false;
  let themesLoading = false;
  let detailsOpen = false;
  let navIndexLoading = false;
  let navIndexItems: ContentNavIndexItem[] = [];
  let navParentOptions: { value: string; label: string }[] = [];
  let hasNavChildren = false;

  let initialState: ContentEditorSnapshot = buildEditorSnapshot({
    alias: "",
    title: "",
    selectedTags: [],
    navTitle: "",
    navParentId: "",
    navOrder: "",
    theme: "",
    contentValue: "",
    isMarkdown: true,
  });
  let currentState: ContentEditorSnapshot = initialState;

  let editorRef: AceAjax.Editor | null = null;

  let uploadOverlayOpen = false;
  let uploadModalOpen = false;
  let uploadItems: UploadItem[] = [];
  let dragActive = false;
  let dragDepth = 0;
  let insertModalOpen = false;
  let isDirty = false;
  let unsavedModalOpen = false;
  let unsavedModalSaving = false;
  let editorFocused = false;

  $: currentPath = $route.path;
  $: isNew = currentPath.startsWith("/pages/new");
  $: idParam =
    currentPath.startsWith("/pages/edit/")
      ? decodeURIComponent(currentPath.replace("/pages/edit/", ""))
      : "";
  $: aliasLocked = !isNew && currentAlias === "index";

  onMount(() => {
    void loadTags();
    void loadThemes();
    void loadNavIndex();
    if (isNew) {
      resetForm();
    } else if (idParam) {
      void loadContent(idParam);
    }
    addWindowListener("keydown", handleKeydown);
  });

  onDestroy(() => {
    removeWindowListener("keydown", handleKeydown);
  });

  $: if (isNew) {
    resetForm();
  }

  $: if (!isNew && idParam && idParam !== contentId) {
    void loadContent(idParam);
  }

  $: if (!navTitle.trim()) {
    navParentId = "";
    navOrder = "";
  }

  $: downloadPath = currentAlias
    ? `/${currentAlias}`
    : contentId
      ? `/id/${contentId}`
      : "#";

  $: navParentOptions = buildNavParentOptions(navIndexItems, contentId, navParentId);
  $: hasNavChildren = !!contentId && navIndexItems.some((item) => item.navParentId === contentId);
  $: currentState = buildEditorSnapshot({
    alias,
    title,
    selectedTags,
    navTitle,
    navParentId,
    navOrder,
    theme,
    contentValue,
    isMarkdown,
  });
  $: isDirty = !loading && isEditorDirty(initialState, currentState);

  function setInitialState(): void {
    initialState = buildEditorSnapshot({
      alias,
      title,
      selectedTags,
      navTitle,
      navParentId,
      navOrder,
      theme,
      contentValue,
      isMarkdown,
    });
  }

  function syncTagsWithAvailable(): void {
    if (availableTags.length === 0 || selectedTags.length === 0) {
      return;
    }
    const known = new Set(availableTags);
    const missing = selectedTags.filter((tag) => !known.has(tag));
    if (missing.length === 0) {
      return;
    }
    selectedTags = selectedTags.filter((tag) => known.has(tag));
    detailsOpen = true;
    pushNotification(
      `Removed missing tags: ${missing.join(", ")}`,
      "error",
    );
  }

  function syncThemesWithSelection(): void {
    if (!theme || theme === "default") {
      return;
    }
    if (availableThemes.includes(theme)) {
      return;
    }
    availableThemes = [...availableThemes, theme].sort((a, b) => a.localeCompare(b));
  }

  async function loadTags(): Promise<void> {
    tagsLoading = true;
    try {
      const tags = await listTags();
      availableTags = tags.map((tag) => tag.id).sort((a, b) => a.localeCompare(b));
      syncTagsWithAvailable();
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to load tags";
      pushNotification(message, "error");
    } finally {
      tagsLoading = false;
    }
  }

  async function loadThemes(): Promise<void> {
    themesLoading = true;
    try {
      const response = await listThemes();
      availableThemes = response
        .map((theme) => theme.name)
        .filter((name) => name !== "default")
        .sort((a, b) => a.localeCompare(b));
      syncThemesWithSelection();
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to load themes";
      pushNotification(message, "error");
    } finally {
      themesLoading = false;
    }
  }

  async function loadNavIndex(): Promise<void> {
    navIndexLoading = true;
    try {
      navIndexItems = await listNavIndex();
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to load navbar data";
      pushNotification(message, "error");
    } finally {
      navIndexLoading = false;
    }
  }

  function formatNavLabel(item: ContentNavIndexItem): string {
    const title = item.navTitle || item.title || item.alias || item.id;
    const aliasPath = item.alias ? `/${item.alias}` : `/id/${item.id}`;
    return `${title} ${aliasPath}`;
  }

  function buildNavParentOptions(
    items: ContentNavIndexItem[],
    currentId: string,
    selectedId: string,
  ): { value: string; label: string }[] {
    const options = items
      .filter((item) => !!item.navTitle && !item.navParentId && item.id !== currentId)
      .map((item) => ({ value: item.id, label: formatNavLabel(item) }));
    if (selectedId && !options.some((option) => option.value === selectedId)) {
      options.unshift({ value: selectedId, label: `Unknown (${selectedId})` });
    }
    return options;
  }

  function parseNavOrderInput(
    value: string | number | null | undefined,
  ): { value: number | null; error?: string } {
    const trimmed = normalizeNavOrderValue(value).trim();
    if (!trimmed) {
      return { value: null };
    }
    if (!/^-?\d+$/.test(trimmed)) {
      return { value: null, error: "Navbar order must be an integer" };
    }
    return { value: Number.parseInt(trimmed, 10) };
  }

  function navigateBackToList(): void {
    navigate("/pages");
  }

  function requestClose(): void {
    if (!isDirty) {
      navigateBackToList();
      return;
    }
    unsavedModalOpen = true;
  }

  function cancelEdit(): void {
    requestClose();
  }

  function handleCancelUnsavedModal(): void {
    unsavedModalOpen = false;
  }

  function handleDiscardUnsaved(): void {
    unsavedModalOpen = false;
    navigateBackToList();
  }

  function handleKeydown(event: KeyboardEvent): void {
    const isSaveKey =
      (event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "s";
    if (isSaveKey) {
      event.preventDefault();
      void saveContent();
      return;
    }
    const isInsertKey =
      (event.metaKey || event.ctrlKey) && event.shiftKey && event.key.toLowerCase() === "i";
    if (isInsertKey) {
      event.preventDefault();
      if (isMarkdown) {
        insertModalOpen = true;
      }
      return;
    }
    if (event.key === "Escape") {
      event.preventDefault();
      if (insertModalOpen) {
        insertModalOpen = false;
        return;
      }
      if (unsavedModalOpen) {
        handleCancelUnsavedModal();
        return;
      }
      requestClose();
    }
  }

  function resetForm(): void {
    alias = "";
    title = "";
    selectedTags = [];
    navTitle = "";
    navParentId = "";
    navOrder = "";
    theme = "";
    mime = "text/markdown";
    originalFilename = "";
    isMarkdown = true;
    contentValue = "# New Page\n";
    currentAlias = "";
    contentId = "";
    detailsOpen = false;
    editorFocused = false;
    setInitialState();
  }

  async function loadContent(requestedId: string): Promise<void> {
    loading = true;
    detailsOpen = false;
    editorFocused = false;
    try {
      const payload = await readContent(requestedId);
      contentId = payload.id;
      currentAlias = payload.alias;
      alias = payload.alias;
      title = payload.title || "";
      navTitle = payload.navTitle || "";
      navParentId = payload.navParentId || "";
      navOrder = payload.navOrder === null ? "" : payload.navOrder.toString();
      theme = payload.theme || "";
      mime = payload.mime;
      originalFilename = payload.originalFilename || "";
      isMarkdown = payload.mime === "text/markdown";
      contentValue = payload.content || "";
      selectedTags = payload.tags;
      syncTagsWithAvailable();
      syncThemesWithSelection();
      setInitialState();
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to load content";
      pushNotification(message, "error");
    } finally {
      loading = false;
    }
  }

  async function saveContent(
    options: { closeAfterSave?: boolean } = {},
  ): Promise<boolean> {
    const closeAfterSave = options.closeAfterSave ?? false;
    const trimmedAlias = alias.trim();
    let canonicalAlias: string | null = null;
    if (trimmedAlias) {
      const aliasResult = normalizeAlias(trimmedAlias, {
        adminPath: getAdminRuntimeConfig().adminPath,
      });
      if (!aliasResult.valid) {
        pushNotification(aliasResult.error, "error");
        return false;
      }
      canonicalAlias = aliasResult.value;
    }

    const { tags: tagList, error } = parseContentTags(selectedTags.join(", "));
    if (error) {
      pushNotification(error, "error");
      return false;
    }

    if (isMarkdown && !title.trim()) {
      pushNotification("Title is required for markdown", "error");
      return false;
    }

    const nextAlias = canonicalAlias ?? "";
    if (aliasLocked && nextAlias !== currentAlias) {
      pushNotification("The index alias cannot be changed", "error");
      return false;
    }

    const navTitleValue = navTitle.trim();
    const navParentValue = navParentId.trim();
    const navOrderResult = parseNavOrderInput(navOrder);
    if (navOrderResult.error) {
      pushNotification(navOrderResult.error, "error");
      return false;
    }
    const navOrderValue = navOrderResult.value;
    const clearingNavTitle = !!initialState.navTitle && !navTitleValue;
    if (!isNew && clearingNavTitle && hasNavChildren) {
      const confirmClear = await confirmDialog({
        title: "Remove navbar title",
        message:
          "Removing the navbar title from this page will also remove the navbar titles of its children.",
        confirmLabel: "Remove",
        tone: "danger",
      });
      if (!confirmClear) {
        return false;
      }
    }

    if (isNew) {
      try {
        const upload = await createMarkdownStream({
          alias: canonicalAlias,
          title: title.trim(),
          tags: tagList,
          navTitle: navTitleValue || null,
          navParentId: navTitleValue ? navParentValue || null : null,
          navOrder: navTitleValue ? navOrderValue : null,
          theme: theme.trim() || null,
          content: contentValue || ""
        });
        pushNotification("Content created", "success");
        if (closeAfterSave) {
          navigateBackToList();
        } else {
          navigate(`/pages/edit/${encodeURIComponent(upload.id)}`);
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : "Failed to create content";
        pushNotification(message, "error");
        return false;
      }
      return true;
    }

    try {
      if (!contentId) {
        pushNotification("Missing content ID", "error");
        return false;
      }
      const newAlias = nextAlias !== currentAlias ? nextAlias : null;
      if (isMarkdown) {
        await updateMarkdownStream({
          id: contentId,
          newAlias,
          title: title.trim() || null,
          tags: tagList,
          navTitle: navTitleValue,
          navParentId: navTitleValue ? navParentValue : "",
          navOrder: navTitleValue ? navOrderValue : null,
          theme: theme.trim() || null,
          content: contentValue || ""
        });
      } else {
        await updateContent({
          id: contentId,
          newAlias,
          title: title.trim() || null,
          tags: tagList,
          navTitle: navTitleValue,
          navParentId: navTitleValue ? navParentValue : "",
          navOrder: navTitleValue ? navOrderValue : null,
          theme: theme.trim() || null,
          content: null
        });
      }
      currentAlias = nextAlias;
      alias = nextAlias;
      pushNotification("Content saved", "success");
      setInitialState();
      if (closeAfterSave) {
        navigateBackToList();
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to save content";
      pushNotification(message, "error");
      return false;
    }
    return true;
  }

  async function handleSaveAndClose(): Promise<void> {
    if (unsavedModalSaving) {
      return;
    }
    unsavedModalSaving = true;
    const saved = await saveContent({ closeAfterSave: true });
    unsavedModalSaving = false;
    if (saved) {
      unsavedModalOpen = false;
    }
  }

  async function removeContent(): Promise<void> {
    if (!contentId) {
      return;
    }
    const confirmed = await confirmDialog({
      title: "Delete content",
      message: "Delete this content? This cannot be undone.",
      confirmLabel: "Delete",
      tone: "danger",
    });
    if (!confirmed) {
      return;
    }
    try {
      await deleteContent(contentId);
      pushNotification("Content deleted", "success");
      navigate("/pages");
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to delete content";
      pushNotification(message, "error");
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
      tags: [],
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

  function queueUploadFiles(files: File[]): void {
    if (files.length === 0) {
      return;
    }
    const items = files.map(buildUploadItem);
    uploadItems = [...uploadItems, ...items];
    uploadModalOpen = true;
    items.forEach((item) => {
      void prevalidateUploadItem(item);
    });
  }

  function openUploadOverlay(): void {
    uploadOverlayOpen = true;
  }

  function closeUploadOverlay(): void {
    uploadOverlayOpen = false;
  }

  function closeUploadModal(): void {
    uploadModalOpen = false;
    uploadItems = [];
  }

  function handleOverlayFiles(files: File[]): void {
    if (files.length === 0) {
      return;
    }
    queueUploadFiles(files);
    uploadOverlayOpen = false;
  }

  function handleUploadComplete(
    upload: { id: string; alias: string; mime: string },
    item: UploadItem,
  ): void {
    if (!editorRef) {
      return;
    }
    const snippet = buildInsertSnippet({
      mime: upload.mime,
      alias: upload.alias,
      id: upload.id,
      title: item.title,
      filename: item.file.name
    });
    editorRef.insert(snippet);
    editorRef.focus();
  }

  function isFileDrag(event: DragEvent): boolean {
    return !!event.dataTransfer && Array.from(event.dataTransfer.types).includes("Files");
  }

  function handleDragEnter(event: DragEvent): void {
    if (!isFileDrag(event)) {
      return;
    }
    event.preventDefault();
    dragDepth += 1;
    dragActive = true;
  }

  function handleDragOver(event: DragEvent): void {
    if (!isFileDrag(event)) {
      return;
    }
    event.preventDefault();
  }

  function handleDragLeave(event: DragEvent): void {
    if (!dragActive) {
      return;
    }
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
    queueUploadFiles(files);
  }

  type InsertMode = "link" | "image" | "video";

  function buildInsertSnippetForItem(item: ContentListItem, mode: InsertMode): string {
    const displayText = item.title?.trim() || item.alias || item.id;
    const aliasPath = item.alias ? `/${item.alias}` : `/id/${item.id}`;
    if (mode === "image") {
      return `![${displayText}](${aliasPath})`;
    }
    if (mode === "video") {
      return `((video src="${aliasPath}"))`;
    }
    return `[${displayText}](${aliasPath})`;
  }

  function handleInsertContent(event: CustomEvent<{ item: ContentListItem; mode: InsertMode }>): void {
    const { item, mode } = event.detail;
    const snippet = buildInsertSnippetForItem(item, mode);
    try {
      if (editorRef) {
        editorRef.insert(snippet);
        editorRef.focus();
      } else {
        pushNotification("Editor is not ready", "error");
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : "Insert failed";
      pushNotification(message, "error");
    } finally {
      insertModalOpen = false;
    }
  }

  function openInsertModal(): void {
    if (!isMarkdown) {
      return;
    }
    insertModalOpen = true;
  }

  $: if (!loading && isMarkdown && editorRef && !editorFocused) {
    editorRef.focus();
    editorFocused = true;
  }
</script>

<section class="flex flex-1 flex-col gap-5 min-h-0">
  <header class="flex flex-wrap items-center justify-between gap-3">
    <div>
      <p class="text-[11px] uppercase tracking-[0.35em] text-muted">Content</p>
      <h2 class="mt-2 text-xl">{isNew ? "Create Content" : "Edit Content"}</h2>
    </div>
    <div class="flex items-center gap-2">
      <Button variant="outline" size="sm" on:click={cancelEdit}>{isDirty ? "Cancel" : "Close"}</Button>
      {#if !isNew}
        <Button variant="danger" size="sm" on:click={removeContent}>Delete</Button>
      {/if}
      <Button variant="primary" size="sm" on:click={saveContent}>Save</Button>
    </div>
  </header>

  <div class="flex flex-1 flex-col rounded-lg border border-border bg-surface px-4 py-4 shadow-soft min-h-0">
    {#if loading}
      <p class="text-sm text-muted">Loading content...</p>
    {:else}
      <div class="flex items-end gap-3">
        <div class="flex-1">
          <label for="content-title" class="text-[11px] uppercase tracking-[0.3em] text-muted">Title</label>
          <Input id="content-title" bind:value={title} className="mt-2" />
        </div>
        <button
          type="button"
          class="h-[32px] w-[32px] rounded-sm border border-border text-xs uppercase tracking-[0.3em] text-muted hover:border-accent hover:text-text"
          on:click={() => (detailsOpen = !detailsOpen)}
          aria-label={detailsOpen ? "Collapse details" : "Expand details"}
        >
          {detailsOpen ? "v" : ">"}
        </button>
      </div>

      {#if detailsOpen}
        <div class="mt-4 grid gap-4 md:grid-cols-2">
          <div>
            <label for="content-alias" class="text-[11px] uppercase tracking-[0.3em] text-muted">Alias</label>
            {#if aliasLocked}
              <div class="mt-2">
                <span class="inline-flex items-center rounded-full bg-danger px-2 py-1 text-[9px] uppercase tracking-[0.2em] text-surface">
                  Index
                </span>
              </div>
            {:else}
              <Input id="content-alias" bind:value={alias} className="mt-2" />
            {/if}
          </div>
          <div>
            <label for="content-theme" class="text-[11px] uppercase tracking-[0.3em] text-muted">Theme</label>
            <Select id="content-theme" bind:value={theme} className="mt-2" disabled={themesLoading}>
              <option value="">Default</option>
              {#each availableThemes as option}
                <option value={option}>{option}</option>
              {/each}
            </Select>
          </div>
          <div class="md:col-span-2">
            <label for="content-tags" class="text-[11px] uppercase tracking-[0.3em] text-muted">Tags</label>
            <div class="mt-2">
              <ChipSelect
                id="content-tags"
                options={availableTags}
                bind:selected={selectedTags}
                placeholder={tagsLoading ? "Loading tags..." : "Select tag"}
                emptyLabel="No tags"
                disabled={tagsLoading}
              />
            </div>
          </div>
          <div class="md:col-span-2">
            <label for="content-nav-title" class="text-[11px] uppercase tracking-[0.3em] text-muted">
              Navbar title
            </label>
            <Input
              id="content-nav-title"
              bind:value={navTitle}
              className="mt-2"
              placeholder="Leave empty to hide from navbar"
            />
          </div>
          <div>
            <label for="content-nav-parent" class="text-[11px] uppercase tracking-[0.3em] text-muted">
              Navbar parent
            </label>
            <Select
              id="content-nav-parent"
              bind:value={navParentId}
              className="mt-2"
              disabled={navIndexLoading || !navTitle.trim()}
            >
              <option value="">No parent</option>
              {#each navParentOptions as option}
                <option value={option.value}>{option.label}</option>
              {/each}
            </Select>
          </div>
          <div>
            <label for="content-nav-order" class="text-[11px] uppercase tracking-[0.3em] text-muted">
              Navbar order
            </label>
            <Input
              id="content-nav-order"
              type="number"
              bind:value={navOrder}
              className="mt-2"
              placeholder="0"
              disabled={!navTitle.trim()}
            />
          </div>
          <div class="text-xs text-muted">
            <div>MIME: {mime || "—"}</div>
            <div>Original: {originalFilename || "—"}</div>
          </div>
        </div>
      {/if}

      <div class="mt-4 flex items-center gap-2">
        <CompactButton variant="outline" disabled={!isMarkdown} on:click={openInsertModal}>
          Insert
        </CompactButton>
        <CompactButton variant="outline" on:click={openUploadOverlay}>
          Upload
        </CompactButton>
        <span class="text-[9px] uppercase tracking-[0.28em] text-muted">
          or drop file(s) on the editor
        </span>
      </div>

      {#if isMarkdown}
        <div
          class="relative mt-4 flex-1 min-h-[280px] border border-border bg-surface-2"
          role="region"
          aria-label="Markdown editor"
          on:dragover={handleDragOver}
          on:dragenter={handleDragEnter}
          on:dragleave={handleDragLeave}
          on:drop={handleDrop}
        >
          <AceEditor bind:value={contentValue} bind:editor={editorRef} mode="markdown" />
          {#if dragActive}
            <div class="pointer-events-none absolute inset-0 flex items-center justify-center border-2 border-dashed border-accent bg-surface/90 text-xs uppercase tracking-[0.3em] text-muted">
              Drop files to upload
            </div>
          {/if}
        </div>
      {:else}
        <div class="mt-4 rounded-lg border border-border bg-surface-2 px-4 py-6 text-sm text-muted">
          This file is not markdown. <a class="underline" href={downloadPath}>Download</a>
        </div>
      {/if}
    {/if}
  </div>

  <InsertContentModal
    bind:open={insertModalOpen}
    tags={availableTags}
    defaultTag={selectedTags[0] ?? ""}
    on:close={() => (insertModalOpen = false)}
    on:insert={handleInsertContent}
  />
  <UnsavedChangesModal
    open={unsavedModalOpen}
    saving={unsavedModalSaving}
    on:save={handleSaveAndClose}
    on:discard={handleDiscardUnsaved}
    on:cancel={handleCancelUnsavedModal}
  />
  <UploadOverlay
    open={uploadOverlayOpen}
    title="Drop files to upload"
    description="Upload one or more files and insert snippets into the editor."
    on:close={closeUploadOverlay}
    on:files={(event) => handleOverlayFiles(event.detail.files)}
  />
  <UploadQueueModal
    open={uploadModalOpen}
    bind:items={uploadItems}
    availableTags={availableTags}
    title="Upload Asset"
    on:close={closeUploadModal}
    on:uploaded={(event) => handleUploadComplete(event.detail.upload, event.detail.item)}
  />
</section>
