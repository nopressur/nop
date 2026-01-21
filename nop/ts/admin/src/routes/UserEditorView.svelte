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
  import { getAdminBootstrap } from "../config/runtime";
  import { pushNotification } from "../stores/notifications";
  import { route, navigate } from "../stores/router";
  import {
    addUserRole,
    createUser,
    getUser,
    removeUserRole,
    updateUserName,
    updateUserPassword,
  } from "../services/users";
  import { createRole, listRoles } from "../services/roles";
  import { validateEmailAddress } from "../validation/email";
  import { validateRoleName } from "../validation/roles";
  import { addWindowListener, removeWindowListener } from "../services/browser";

  type Bootstrap = {
    currentUserEmail?: string;
  };

  const bootstrap = getAdminBootstrap<Bootstrap>();
  let email = "";
  let name = "";
  let password = "";
  let confirm = "";
  let newRole = "";

  let availableRoles: string[] = [];
  let selectedRoles = new Set<string>();
  let initialRoles = new Set<string>();
  let initialName = "";

  let loading = false;

  $: currentPath = $route.path;
  $: isNew = currentPath.startsWith("/users/new");
  $: editingEmail = currentPath.startsWith("/users/edit/")
    ? decodeURIComponent(currentPath.replace("/users/edit/", ""))
    : "";

  onMount(() => {
    void init();
    addWindowListener("keydown", handleKeydown);
  });

  onDestroy(() => {
    removeWindowListener("keydown", handleKeydown);
  });

  async function init(): Promise<void> {
    loading = true;
    try {
      availableRoles = await listRoles();
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to load roles";
      pushNotification(message, "error");
    }

    if (!isNew && editingEmail) {
      email = editingEmail;
      try {
        const user = await getUser(editingEmail);
        name = user.name;
        initialName = user.name;
        initialRoles = new Set(user.roles);
        user.roles.forEach((role) => {
          if (!availableRoles.includes(role)) {
            availableRoles.push(role);
          }
        });
        selectedRoles = new Set(user.roles);
      } catch (error) {
        const message = error instanceof Error ? error.message : "Failed to load user";
        pushNotification(message, "error");
      }
    }

    availableRoles = [...new Set(availableRoles)].sort((a, b) => a.localeCompare(b));
    loading = false;
  }

  function toggleRole(role: string): void {
    if (selectedRoles.has(role)) {
      selectedRoles.delete(role);
    } else {
      selectedRoles.add(role);
    }
    selectedRoles = new Set(selectedRoles);
  }

  function cancelEdit(): void {
    navigate("/users");
  }

  function handleKeydown(event: KeyboardEvent): void {
    const isSaveKey =
      (event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "s";
    if (isSaveKey) {
      event.preventDefault();
      void saveUser();
      return;
    }
    if (event.key === "Enter") {
      event.preventDefault();
      if (!loading) {
        void saveUser();
      }
      return;
    }
    if (event.key === "Escape") {
      event.preventDefault();
      cancelEdit();
    }
  }

  async function saveUser(): Promise<void> {
    if (loading) {
      return;
    }

    const nameValue = name.trim();
    const emailValue = email.trim();

    const newRoleValue = newRole.trim();
    const roleValidation = validateRoleName(newRoleValue);
    if (!roleValidation.valid) {
      pushNotification(roleValidation.error, "error");
      return;
    }

    const roles = new Set(selectedRoles);
    if (newRoleValue) {
      if (!availableRoles.includes(newRoleValue)) {
        try {
          await createRole(newRoleValue);
          availableRoles = [...availableRoles, newRoleValue].sort((a, b) => a.localeCompare(b));
        } catch (error) {
          const message = error instanceof Error ? error.message : "Failed to create role";
          pushNotification(message, "error");
          return;
        }
      }
      roles.add(newRoleValue);
    }
    const rolesList = Array.from(roles.values());

    let passwordValue: string | null = null;
    if (password || confirm) {
      if (password !== confirm) {
        pushNotification("Passwords do not match", "error");
        return;
      }
      passwordValue = password;
    }

    if (isNew) {
      if (!emailValue) {
        pushNotification("Email is required", "error");
        return;
      }
      const emailValidation = validateEmailAddress(emailValue);
      if (!emailValidation.valid) {
        pushNotification(emailValidation.error, "error");
        return;
      }
      if (!passwordValue) {
        pushNotification("Password is required", "error");
        return;
      }
      try {
        const message = await createUser({
          email: emailValue,
          name: nameValue,
          password: passwordValue,
          roles: rolesList
        });
        pushNotification(message, "success");
        navigate("/users");
      } catch (error) {
        const message = error instanceof Error ? error.message : "Failed to create user";
        pushNotification(message, "error");
      }
      return;
    }

    if (!emailValue) {
      pushNotification("Unable to identify user", "error");
      return;
    }

    let updated = false;
    let lastMessage = "User updated";

    try {
      if (nameValue && nameValue !== initialName) {
        lastMessage = await updateUserName(emailValue, nameValue);
        updated = true;
      }

      if (passwordValue) {
        lastMessage = await updateUserPassword(emailValue, passwordValue);
        updated = true;
      }

      const rolesToAdd = rolesList.filter((role) => !initialRoles.has(role));
      const rolesToRemove = Array.from(initialRoles).filter((role) => !roles.has(role));

      for (const role of rolesToAdd) {
        lastMessage = await addUserRole(emailValue, role);
        updated = true;
      }

      for (const role of rolesToRemove) {
        lastMessage = await removeUserRole(emailValue, role);
        updated = true;
      }

      if (!updated) {
        pushNotification("No changes to save", "info");
        return;
      }

      pushNotification(lastMessage, "success");
      navigate("/users");
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to save user";
      pushNotification(message, "error");
    }
  }
</script>

<section class="flex flex-col gap-5">
  <header class="flex flex-wrap items-center justify-between gap-3">
    <div>
      <p class="text-[11px] uppercase tracking-[0.35em] text-muted">Users</p>
      <h2 class="mt-2 text-xl">{isNew ? "Create User" : "Edit User"}</h2>
    </div>
    <div class="flex items-center gap-2">
      <Button variant="outline" size="sm" on:click={() => navigate("/users")}
        >Cancel</Button
      >
      <Button variant="primary" size="sm" on:click={saveUser} disabled={loading}
        >Save</Button
      >
    </div>
  </header>

  <div class="rounded-lg border border-border bg-surface px-4 py-4 shadow-soft">
    {#if loading}
      <p class="text-sm text-muted">Loading user...</p>
    {:else}
      <div class="grid gap-4 md:grid-cols-2">
        <div>
          <label for="user-email" class="text-[11px] uppercase tracking-[0.3em] text-muted">Email</label>
          <Input id="user-email" bind:value={email} className="mt-2" disabled={!isNew} />
        </div>
        <div>
          <label for="user-name" class="text-[11px] uppercase tracking-[0.3em] text-muted">Name</label>
          <Input id="user-name" bind:value={name} className="mt-2" />
        </div>
        <div>
          <label for="user-password" class="text-[11px] uppercase tracking-[0.3em] text-muted">Password</label>
          <Input id="user-password" type="password" bind:value={password} className="mt-2" />
        </div>
        <div>
          <label for="user-confirm" class="text-[11px] uppercase tracking-[0.3em] text-muted">Confirm Password</label>
          <Input id="user-confirm" type="password" bind:value={confirm} className="mt-2" />
        </div>
      </div>

      <div class="mt-4">
        <p class="text-[11px] uppercase tracking-[0.3em] text-muted">Roles</p>
        <div class="mt-2 grid gap-2 md:grid-cols-2">
          {#each availableRoles as role}
            <label class="flex items-center gap-2 text-sm text-muted">
              <input
                type="checkbox"
                checked={selectedRoles.has(role)}
                on:change={() => toggleRole(role)}
              />
              {role}
            </label>
          {/each}
        </div>
        <div class="mt-3 max-w-[240px]">
          <label for="user-role" class="text-[11px] uppercase tracking-[0.3em] text-muted">Add Role</label>
          <Input id="user-role" bind:value={newRole} className="mt-2" placeholder="new role" />
        </div>
      </div>
    {/if}
  </div>
</section>
