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
  import { getSessionStorage } from "../services/browser";
  import { useListViewLogic } from "./useListViewLogic";
  import { navigate } from "../stores/router";
  import { deleteUser, getUser, listUsers } from "../services/users";

  type Bootstrap = {
    currentUserEmail?: string;
  };

  const bootstrap = getAdminBootstrap<Bootstrap>();
  const cachedEmail = getSessionStorage()?.getItem("nopAdminCurrentUserEmail") ?? null;
  const currentUserEmail = bootstrap?.currentUserEmail || cachedEmail || "";

  if (bootstrap?.currentUserEmail) {
    getSessionStorage()?.setItem("nopAdminCurrentUserEmail", bootstrap.currentUserEmail);
  }

  let users: Awaited<ReturnType<typeof listUsers>> = [];
  let rolesMap = new Map<string, string[]>();
  let listRef: HTMLTableSectionElement | null = null;

  const {
    loading,
    rowNavigation,
    selectedIndex,
    syncRowNavigation,
    notifyError,
    runWithLoading,
    confirmAndDelete,
  } = useListViewLogic({
    onOpen: (index) => openUser(index),
  });

  onMount(() => {
    void loadUsers();
  });

  async function loadUsers(): Promise<void> {
    const result = await runWithLoading(async () => {
      const list = await listUsers();
      const details = await Promise.allSettled(
        list.map((user) => getUser(user.email)),
      );
      let roleError: unknown = null;
      const rolesEntries = details.flatMap((detail, index) => {
        if (detail.status === "fulfilled") {
          return [[list[index].email, detail.value.roles]] as [string, string[]][];
        }
        if (!roleError) {
          roleError = detail.reason;
        }
        return [];
      });
      if (roleError) {
        notifyError(roleError, "Failed to load user roles");
      }
      return { list, rolesEntries };
    }, "Failed to load users");

    if (!result) {
      return;
    }
    users = result.list;
    rolesMap = new Map(result.rolesEntries);
  }

  async function removeUser(email: string): Promise<void> {
    if (email === currentUserEmail) {
      notifyError(null, "You cannot delete your own account");
      return;
    }
    await confirmAndDelete({
      confirmMessage: `Delete user '${email}'?`,
      onDelete: () => deleteUser(email),
      successMessage: "User deleted",
      errorMessage: "Failed to delete user",
      onComplete: () => loadUsers(),
    });
  }

  function openUser(index: number): void {
    const user = users[index];
    if (!user) {
      return;
    }
    navigate(`/users/edit/${encodeURIComponent(user.email)}`);
  }

  $: syncRowNavigation(listRef, users.length);
</script>

<section class="flex flex-col gap-5">
  <header class="sticky top-14 z-20 -mx-6 border-b border-border bg-background/95 px-4 py-3 backdrop-blur md:static md:mx-0 md:border-none md:bg-transparent md:px-0 md:py-0 flex flex-wrap items-center justify-between gap-3">
    <div>
      <p class="text-[11px] uppercase tracking-[0.35em] text-muted">Users</p>
      <h2 class="mt-2 text-xl">User Directory</h2>
    </div>
    <Button variant="primary" size="sm" on:click={() => navigate("/users/new")}
      >New User</Button
    >
  </header>

  <div class="-mx-6 bg-surface px-4 py-2 md:mx-0 md:rounded-lg md:border md:border-border md:px-4 md:py-4 md:shadow-soft">
    <div class="md:hidden">
      {#if $loading}
        <p class="py-6 text-sm text-muted">Loading users...</p>
      {:else if users.length === 0}
        <p class="py-6 text-sm text-muted">No users found.</p>
      {:else}
        <div class="divide-y divide-border">
          {#each users as user}
            <div class="flex items-start justify-between gap-4 py-4">
              <div class="min-w-0">
                <button
                  type="button"
                  class="w-full text-left text-sm font-semibold leading-snug text-text break-words"
                  on:click={() => navigate(`/users/edit/${encodeURIComponent(user.email)}`)}
                >
                  {user.email}
                </button>
                {#if user.name}
                  <div class="mt-1 text-xs text-muted break-words">{user.name}</div>
                {/if}
                <div class="mt-1 text-[10px] uppercase tracking-[0.2em] text-muted break-words">
                  {(rolesMap.get(user.email) || []).join(", ") || "No roles"}
                </div>
              </div>
              <div class="flex items-center gap-2 shrink-0">
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 w-7 px-0 text-[10px] tracking-[0.12em] text-accent border-accent"
                  on:click={() => navigate(`/users/edit/${encodeURIComponent(user.email)}`)}
                >
                  <span aria-hidden="true">E</span>
                  <span class="sr-only">Edit</span>
                </Button>
                <Button
                  variant="danger"
                  size="sm"
                  disabled={user.email === currentUserEmail}
                  className="h-7 w-7 px-0 text-[10px] tracking-[0.12em]"
                  on:click={() => removeUser(user.email)}
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
            <th class="py-2">Email</th>
            <th class="py-2">Name</th>
            <th class="py-2">Roles</th>
            <th class="py-2 text-right">Actions</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-border" bind:this={listRef}>
          {#if $loading}
            <tr>
              <td class="py-6 text-sm text-muted" colspan="4">Loading users...</td>
            </tr>
          {:else if users.length === 0}
            <tr>
              <td class="py-6 text-sm text-muted" colspan="4">No users found.</td>
            </tr>
          {:else}
            {#each users as user, index}
              <tr
                class="cursor-pointer hover:bg-surface-2 focus:bg-surface-2 focus:outline-none"
                data-row-index={index}
                tabindex={$selectedIndex === index ? 0 : -1}
                aria-selected={$selectedIndex === index}
                on:click={() => rowNavigation.handleRowClick(index)}
                on:focus={() => rowNavigation.handleRowFocus(index)}
                on:keydown={rowNavigation.handleKeydown}
              >
                <td class="py-3 font-medium">{user.email}</td>
                <td class="py-3 text-muted">{user.name}</td>
                <td class="py-3 text-muted">
                  {(rolesMap.get(user.email) || []).join(", ") || "—"}
                </td>
                <td
                  class="py-3 text-right"
                  data-row-actions
                  on:click|stopPropagation
                  on:keydown|stopPropagation
                >
                  <Button
                    variant="ghost"
                    size="sm"
                    on:click={() => navigate(`/users/edit/${encodeURIComponent(user.email)}`)}
                  >
                    Edit
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled={user.email === currentUserEmail}
                    on:click={() => removeUser(user.email)}
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
