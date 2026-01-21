<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->

<script lang="ts">
  import { onMount } from "svelte";
  import { getAdminRuntimeConfig } from "../config/runtime";
  import NotificationToaster from "../components/NotificationToaster.svelte";
  import ConfirmModal from "../components/ConfirmModal.svelte";
  import ContentEditorView from "../routes/ContentEditorView.svelte";
  import ContentListView from "../routes/ContentListView.svelte";
  import RoleEditorView from "../routes/RoleEditorView.svelte";
  import RoleListView from "../routes/RoleListView.svelte";
  import TagEditorView from "../routes/TagEditorView.svelte";
  import TagListView from "../routes/TagListView.svelte";
  import ThemeEditorView from "../routes/ThemeEditorView.svelte";
  import ThemeListView from "../routes/ThemeListView.svelte";
  import UserEditorView from "../routes/UserEditorView.svelte";
  import UserListView from "../routes/UserListView.svelte";
  import SystemSettingsView from "../routes/SystemSettingsView.svelte";
  import { addWindowListener, removeWindowListener } from "../services/browser";
  import { route, isActiveRoute, navigate } from "../stores/router";

  const config = getAdminRuntimeConfig();
  const basePath = config.adminPath.replace(/\/$/, "");
  const navItems = [
    { label: "Content", path: "/pages" },
    { label: "Tags", path: "/tags" },
    { label: "Roles", path: "/roles" },
    { label: "Themes", path: "/themes" },
    { label: "Users", path: "/users", gated: true },
    { label: "System", path: "/system" }
  ];

  let navOpen = false;

  $: currentPath = $route.path;

  onMount(() => {
    if (currentPath === "/" || currentPath === "") {
      navigate("/pages", true);
    }
    const preventDefault = (event: DragEvent) => {
      if (!event.dataTransfer) {
        return;
      }
      const hasFiles = event.dataTransfer.files && event.dataTransfer.files.length > 0;
      const hasFileTypes = Array.from(event.dataTransfer.types).includes("Files");
      if (hasFiles || hasFileTypes) {
        event.preventDefault();
      }
    };
    addWindowListener("dragover", preventDefault);
    addWindowListener("drop", preventDefault);
    return () => {
      removeWindowListener("dragover", preventDefault);
      removeWindowListener("drop", preventDefault);
    };
  });

  $: if (!config.userManagementEnabled && currentPath.startsWith("/users")) {
    navigate("/pages", true);
  }

  function href(path: string): string {
    return `${basePath}${path}`;
  }
</script>

<div class="flex min-h-screen flex-col bg-background text-text">
  <NotificationToaster />
  <ConfirmModal />

  <header class="sticky top-0 z-30 flex items-center justify-between border-b border-border bg-surface px-4 py-3 backdrop-blur">
    <div class="flex items-center gap-3">
      <button
        class="rounded-sm border border-border px-2 py-1 text-[10px] uppercase tracking-[0.3em] text-muted lg:hidden"
        on:click={() => (navOpen = !navOpen)}
        aria-label="Toggle navigation"
      >
        Menu
      </button>
      <div class="text-[11px] uppercase tracking-[0.4em] text-muted">
        {config.appName}
      </div>
    </div>
    <a
      class="text-[10px] uppercase tracking-[0.35em] text-muted hover:text-text"
      href="/"
    >
      View Site
    </a>
  </header>

  {#if navOpen}
    <button
      class="fixed inset-0 z-20 bg-black/40 lg:hidden"
      on:click={() => (navOpen = false)}
      aria-label="Close navigation"
    ></button>
  {/if}

  <div class="relative flex flex-1 min-h-0 items-stretch">
    <aside
      class={`fixed inset-y-0 left-0 z-30 w-[220px] border-r border-border bg-surface px-5 py-6 transition-transform lg:static lg:translate-x-0 lg:shrink-0 ${
        navOpen ? "translate-x-0" : "-translate-x-full"
      }`}
    >
      <div class="mb-3 text-[10px] uppercase tracking-[0.4em] text-muted">
        Admin
      </div>
      <nav class="flex flex-col gap-2">
        {#each navItems as item}
          {#if item.path !== "/users" || config.userManagementEnabled}
            <a
              class={`rounded-sm border px-4 py-2 text-xs uppercase tracking-[0.22em] transition ${
                isActiveRoute(item.path, currentPath)
                  ? "border-accent text-text"
                  : "border-border text-muted hover:border-accent hover:text-text"
              }`}
              href={href(item.path)}
              on:click|preventDefault={() => {
                navigate(item.path);
                navOpen = false;
              }}
            >
              {item.label}
            </a>
          {/if}
        {/each}
      </nav>
    </aside>

    <main class="relative flex min-w-0 flex-1 flex-col px-6 pb-8 pt-6 min-h-0">
      <div class="mx-auto flex w-full max-w-none flex-1 flex-col gap-6 min-h-0">
        {#if currentPath.startsWith("/pages/new") || currentPath.startsWith("/pages/edit")}
          <ContentEditorView />
        {:else if currentPath.startsWith("/pages") || currentPath === "/"}
          <ContentListView />
        {:else if currentPath.startsWith("/tags/new") || currentPath.startsWith("/tags/edit")}
          <TagEditorView />
        {:else if currentPath.startsWith("/tags")}
          <TagListView />
        {:else if currentPath.startsWith("/roles/new") || currentPath.startsWith("/roles/edit")}
          <RoleEditorView />
        {:else if currentPath.startsWith("/roles")}
          <RoleListView />
        {:else if currentPath.startsWith("/themes/new") || currentPath.startsWith("/themes/customize")}
          <ThemeEditorView />
        {:else if currentPath.startsWith("/themes")}
          <ThemeListView />
        {:else if currentPath.startsWith("/users/new") || currentPath.startsWith("/users/edit")}
          <UserEditorView />
        {:else if currentPath.startsWith("/users")}
          <UserListView />
        {:else if currentPath.startsWith("/system")}
          <SystemSettingsView />
        {:else}
          <ContentListView />
        {/if}
      </div>
    </main>
  </div>
</div>
