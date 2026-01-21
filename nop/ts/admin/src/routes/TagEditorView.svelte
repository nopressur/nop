<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->

<script lang="ts">
  import { onDestroy, onMount } from "svelte";
  import Button from "../components/Button.svelte";
  import ChipSelect from "../components/ChipSelect.svelte";
  import Input from "../components/Input.svelte";
  import Select from "../components/Select.svelte";
  import { pushNotification } from "../stores/notifications";
  import { route, navigate } from "../stores/router";
  import { createTag, getTag, updateTag } from "../services/tags";
  import { listRoles } from "../services/roles";
  import { validateRoles, validateTagId, validateTagName } from "../validation/tags";
  import type { AccessRule } from "../protocol/tags";
  import { addWindowListener, removeWindowListener } from "../services/browser";

  let id = "";
  let name = "";
  let availableRoles: string[] = [];
  let selectedRoles: string[] = [];
  let accessRule: "none" | AccessRule = "none";
  let loading = false;
  let isNew = false;
  let loadedId: string | null = null;

  $: currentPath = $route.path;
  $: isNew = currentPath.startsWith("/tags/new");
  $: tagIdParam = $route.query.get("id") || "";

  onMount(() => {
    void loadRoles();
    if (!isNew && tagIdParam) {
      void loadTag(tagIdParam);
    } else if (isNew) {
      resetForm();
    }
    addWindowListener("keydown", handleKeydown);
  });

  onDestroy(() => {
    removeWindowListener("keydown", handleKeydown);
  });

  $: if (isNew) {
    resetForm();
  }

  $: if (!isNew && tagIdParam && tagIdParam !== loadedId) {
    void loadTag(tagIdParam);
  }

  async function loadRoles(): Promise<void> {
    try {
      availableRoles = await listRoles();
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to load roles";
      pushNotification(message, "error");
    } finally {
      syncRoleOptions();
    }
  }

  function syncRoleOptions(): void {
    const merged = new Set([...availableRoles, ...selectedRoles]);
    availableRoles = Array.from(merged.values()).sort((a, b) => a.localeCompare(b));
  }

  async function loadTag(tagId: string): Promise<void> {
    loading = true;
    try {
      const data = await getTag(tagId);
      id = data.id;
      name = data.name;
      selectedRoles = data.roles;
      accessRule = data.accessRule ?? "none";
      loadedId = data.id;
      syncRoleOptions();
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to load tag";
      pushNotification(message, "error");
    } finally {
      loading = false;
    }
  }

  function resetForm(): void {
    id = "";
    name = "";
    selectedRoles = [];
    accessRule = "none";
    loadedId = null;
  }

  function cancelEdit(): void {
    navigate("/tags");
  }

  function handleKeydown(event: KeyboardEvent): void {
    const isSaveKey =
      (event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "s";
    if (isSaveKey) {
      event.preventDefault();
      void saveTag();
      return;
    }
    if (event.key === "Enter") {
      event.preventDefault();
      if (!loading) {
        void saveTag();
      }
      return;
    }
    if (event.key === "Escape") {
      event.preventDefault();
      cancelEdit();
    }
  }

  async function saveTag(): Promise<void> {
    const trimmedId = id.trim();
    const idValidation = validateTagId(trimmedId);
    if (!idValidation.valid) {
      pushNotification(idValidation.error, "error");
      return;
    }

    const nameValidation = validateTagName(name.trim());
    if (!nameValidation.valid) {
      pushNotification(nameValidation.error, "error");
      return;
    }

    const rolesValidation = validateRoles(selectedRoles);
    if (!rolesValidation.valid) {
      pushNotification(rolesValidation.error, "error");
      return;
    }

    const originalId = loadedId ?? tagIdParam;
    if (!isNew && !originalId) {
      pushNotification("Missing original tag id", "error");
      return;
    }
    const newId =
      !isNew && originalId && trimmedId !== originalId ? trimmedId : null;

    loading = true;
    try {
      if (isNew) {
        await createTag({
          id: trimmedId,
          name: name.trim(),
          roles: selectedRoles,
          accessRule: accessRule === "none" ? null : accessRule
        });
        pushNotification("Tag created", "success");
      } else {
        await updateTag({
          id: originalId,
          newId,
          name: name.trim(),
          roles: selectedRoles,
          accessRule: accessRule === "none" ? null : accessRule,
          clearAccess: accessRule === "none"
        });
        pushNotification("Tag updated", "success");
      }
      navigate("/tags");
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to save tag";
      pushNotification(message, "error");
    } finally {
      loading = false;
    }
  }
</script>

<section class="flex flex-col gap-5">
  <header class="flex flex-wrap items-center justify-between gap-3">
    <div>
      <p class="text-[11px] uppercase tracking-[0.35em] text-muted">Tags</p>
      <h2 class="mt-2 text-xl">{isNew ? "Create Tag" : "Edit Tag"}</h2>
    </div>
    <div class="flex items-center gap-2">
      <Button variant="outline" size="sm" on:click={() => navigate("/tags")}
        >Cancel</Button
      >
      <Button variant="primary" size="sm" on:click={saveTag} disabled={loading}
        >Save</Button
      >
    </div>
  </header>

  <div class="rounded-lg border border-border bg-surface px-4 py-4 shadow-soft">
    {#if loading && !isNew}
      <p class="text-sm text-muted">Loading tag...</p>
    {:else}
      <div class="grid gap-4 md:grid-cols-2">
        <div>
          <label for="tag-id" class="text-[11px] uppercase tracking-[0.3em] text-muted">Tag ID</label>
          <Input id="tag-id" bind:value={id} disabled={loading} className="mt-2" />
          {#if !isNew}
            <p class="mt-2 text-xs text-muted">Renaming updates content tags that reference this ID.</p>
          {/if}
        </div>
        <div>
          <label for="tag-name" class="text-[11px] uppercase tracking-[0.3em] text-muted">Name</label>
          <Input id="tag-name" bind:value={name} className="mt-2" />
        </div>
      </div>

      <div class="mt-4">
        <label for="tag-roles" class="text-[11px] uppercase tracking-[0.3em] text-muted">Roles</label>
        <div class="mt-2">
          <ChipSelect
            id="tag-roles"
            options={availableRoles}
            bind:selected={selectedRoles}
            placeholder="Select role"
            emptyLabel="No roles"
          />
        </div>
      </div>

      <div class="mt-4 max-w-[240px]">
        <label for="tag-access" class="text-[11px] uppercase tracking-[0.3em] text-muted">Access Rule</label>
        <Select id="tag-access" bind:value={accessRule} className="mt-2">
          <option value="none">None</option>
          <option value="union">Union</option>
          <option value="intersect">Intersect</option>
        </Select>
      </div>
    {/if}
  </div>
</section>
