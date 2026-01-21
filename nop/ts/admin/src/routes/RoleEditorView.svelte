<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->

<script lang="ts">
  import { onDestroy, onMount } from "svelte";
  import Button from "../components/Button.svelte";
  import Input from "../components/Input.svelte";
  import { addWindowListener, removeWindowListener } from "../services/browser";
  import { pushNotification } from "../stores/notifications";
  import { route, navigate } from "../stores/router";
  import { createRole, getRole, renameRole } from "../services/roles";
  import { ADMIN_ROLE } from "../config/constants";
  import { validateRoleName } from "../validation/roles";
  let role = "";
  let newRole = "";
  let loading = false;
  let loadedRole: string | null = null;

  $: currentPath = $route.path;
  $: isNew = currentPath.startsWith("/roles/new");
  $: roleParam = $route.query.get("role") || "";
  $: isAdmin = !isNew && role === ADMIN_ROLE;

  onMount(() => {
    if (!isNew && roleParam) {
      void loadRole(roleParam);
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

  $: if (!isNew && roleParam && roleParam !== loadedRole) {
    void loadRole(roleParam);
  }

  async function loadRole(roleName: string): Promise<void> {
    loading = true;
    try {
      const data = await getRole(roleName);
      role = data.role;
      newRole = data.role;
      loadedRole = data.role;
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to load role";
      pushNotification(message, "error");
    } finally {
      loading = false;
    }
  }

  function resetForm(): void {
    role = "";
    newRole = "";
    loadedRole = null;
  }

  function cancelEdit(): void {
    navigate("/roles");
  }

  function handleKeydown(event: KeyboardEvent): void {
    const isSaveKey =
      (event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "s";
    if (isSaveKey) {
      event.preventDefault();
      void saveRole();
      return;
    }
    if (event.key === "Enter") {
      event.preventDefault();
      if (!loading) {
        void saveRole();
      }
      return;
    }
    if (event.key === "Escape") {
      event.preventDefault();
      cancelEdit();
    }
  }

  async function saveRole(): Promise<void> {
    if (loading) {
      return;
    }

    if (isNew) {
      const roleValue = role.trim();
      if (!roleValue) {
        pushNotification("Role name is required", "error");
        return;
      }
      const validation = validateRoleName(roleValue);
      if (!validation.valid) {
        pushNotification(validation.error, "error");
        return;
      }
      try {
        await createRole(roleValue);
        pushNotification("Role created", "success");
        navigate("/roles");
      } catch (error) {
        const message = error instanceof Error ? error.message : "Failed to create role";
        pushNotification(message, "error");
      }
      return;
    }

    if (isAdmin) {
      pushNotification("Admin role cannot be renamed", "error");
      return;
    }

    const newRoleValue = newRole.trim();
    const validation = validateRoleName(newRoleValue);
    if (!validation.valid) {
      pushNotification(validation.error, "error");
      return;
    }
    if (!role || !newRoleValue) {
      pushNotification("Role name is required", "error");
      return;
    }
    if (role === newRoleValue) {
      pushNotification("No changes to save", "info");
      return;
    }

    try {
      await renameRole(role, newRoleValue);
      pushNotification("Role updated", "success");
      navigate("/roles");
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to rename role";
      pushNotification(message, "error");
    }
  }
</script>

<section class="flex flex-col gap-5">
  <header class="flex flex-wrap items-center justify-between gap-3">
    <div>
      <p class="text-[11px] uppercase tracking-[0.35em] text-muted">Roles</p>
      <h2 class="mt-2 text-xl">{isNew ? "Create Role" : "Edit Role"}</h2>
    </div>
    <div class="flex items-center gap-2">
      <Button variant="outline" size="sm" on:click={() => navigate("/roles")}
        >Cancel</Button
      >
      <Button
        variant="primary"
        size="sm"
        on:click={saveRole}
        disabled={loading || isAdmin}
        >Save</Button
      >
    </div>
  </header>

  <div class="rounded-lg border border-border bg-surface px-4 py-4 shadow-soft">
    {#if loading && !isNew}
      <p class="text-sm text-muted">Loading role...</p>
    {:else}
      <div class="grid gap-4 md:grid-cols-2">
        <div>
          <label for="role-name" class="text-[11px] uppercase tracking-[0.3em] text-muted">Role</label>
          <Input id="role-name" bind:value={role} className="mt-2" disabled={!isNew} />
        </div>
        {#if !isNew}
          <div>
            <label for="role-new" class="text-[11px] uppercase tracking-[0.3em] text-muted">New Role</label>
            <Input id="role-new" bind:value={newRole} className="mt-2" disabled={isAdmin} />
          </div>
        {/if}
      </div>
      {#if isAdmin}
        <p class="mt-4 text-xs text-muted">
          The admin role cannot be renamed.
        </p>
      {/if}
    {/if}
  </div>
</section>
