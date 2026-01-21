<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->

<script lang="ts">
  import { onMount } from "svelte";
  import Button from "../components/Button.svelte";
  import { ADMIN_ROLE } from "../config/constants";
  import { useListViewLogic } from "./useListViewLogic";
  import { navigate } from "../stores/router";
  import { deleteRole, listRoles } from "../services/roles";

  let roles: string[] = [];
  let listRef: HTMLTableSectionElement | null = null;

  const {
    loading,
    rowNavigation,
    selectedIndex,
    syncRowNavigation,
    runWithLoading,
    confirmAndDelete,
  } = useListViewLogic({
    onOpen: (index) => openRole(index),
  });

  onMount(() => {
    void loadRoles();
  });

  async function loadRoles(): Promise<void> {
    const result = await runWithLoading(listRoles, "Failed to load roles");
    if (result) {
      roles = result;
    }
  }

  async function removeRole(role: string): Promise<void> {
    await confirmAndDelete({
      confirmMessage: `Delete role '${role}'? This will remove it from all tags and users, may change access, and cannot be undone.`,
      onDelete: () => deleteRole(role),
      successMessage: "Role deleted",
      errorMessage: "Failed to delete role",
      onComplete: () => loadRoles(),
    });
  }

  function openRole(index: number): void {
    const role = roles[index];
    if (!role || role === ADMIN_ROLE) {
      return;
    }
    navigate(`/roles/edit?role=${encodeURIComponent(role)}`);
  }

  $: syncRowNavigation(listRef, roles.length);
</script>

<section class="flex flex-col gap-5">
  <header class="sticky top-14 z-20 -mx-6 border-b border-border bg-background/95 px-4 py-3 backdrop-blur md:static md:mx-0 md:border-none md:bg-transparent md:px-0 md:py-0 flex flex-wrap items-center justify-between gap-3">
    <div>
      <p class="text-[11px] uppercase tracking-[0.35em] text-muted">Roles</p>
      <h2 class="mt-2 text-xl">Role Directory</h2>
    </div>
    <Button variant="primary" size="sm" on:click={() => navigate("/roles/new")}>
      New Role
    </Button>
  </header>

  <div class="-mx-6 bg-surface px-4 py-2 md:mx-0 md:rounded-lg md:border md:border-border md:px-4 md:py-4 md:shadow-soft">
    <div class="md:hidden">
      {#if $loading}
        <p class="py-6 text-sm text-muted">Loading roles...</p>
      {:else if roles.length === 0}
        <p class="py-6 text-sm text-muted">No roles found.</p>
      {:else}
        <div class="divide-y divide-border">
          {#each roles as role}
            <div class="flex items-start justify-between gap-4 py-4">
              <button
                type="button"
                class="min-w-0 text-left text-sm font-semibold leading-snug text-text break-words"
                on:click={() => {
                  if (role !== ADMIN_ROLE) {
                    navigate(`/roles/edit?role=${encodeURIComponent(role)}`);
                  }
                }}
              >
                {role}
              </button>
              <div class="flex items-center gap-2 shrink-0">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={role === ADMIN_ROLE}
                  className="h-7 w-7 px-0 text-[10px] tracking-[0.12em] text-accent border-accent"
                  on:click={() => navigate(`/roles/edit?role=${encodeURIComponent(role)}`)}
                >
                  <span aria-hidden="true">E</span>
                  <span class="sr-only">Edit</span>
                </Button>
                <Button
                  variant="danger"
                  size="sm"
                  disabled={role === ADMIN_ROLE}
                  className="h-7 w-7 px-0 text-[10px] tracking-[0.12em]"
                  on:click={() => removeRole(role)}
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
            <th class="py-2">Role</th>
            <th class="py-2 text-right">Actions</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-border" bind:this={listRef}>
          {#if $loading}
            <tr>
              <td class="py-6 text-sm text-muted" colspan="2">Loading roles...</td>
            </tr>
          {:else if roles.length === 0}
            <tr>
              <td class="py-6 text-sm text-muted" colspan="2">No roles found.</td>
            </tr>
          {:else}
            {#each roles as role, index}
              <tr
                class="hover:bg-surface-2 focus:bg-surface-2 focus:outline-none"
                class:cursor-pointer={role !== ADMIN_ROLE}
                data-row-index={index}
                tabindex={$selectedIndex === index ? 0 : -1}
                aria-selected={$selectedIndex === index}
                on:click={() => rowNavigation.handleRowClick(index)}
                on:focus={() => rowNavigation.handleRowFocus(index)}
                on:keydown={rowNavigation.handleKeydown}
              >
                <td class="py-3 font-medium">{role}</td>
                <td
                  class="py-3 text-right"
                  data-row-actions
                  on:click|stopPropagation
                  on:keydown|stopPropagation
                >
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled={role === ADMIN_ROLE}
                    on:click={() => navigate(`/roles/edit?role=${encodeURIComponent(role)}`)}
                  >
                    Edit
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled={role === ADMIN_ROLE}
                    on:click={() => removeRole(role)}
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
