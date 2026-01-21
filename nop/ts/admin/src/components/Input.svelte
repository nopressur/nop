<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->

<script lang="ts">
  import { createEventDispatcher } from "svelte";

  export let value = "";
  export let placeholder = "";
  export let type = "text";
  export let disabled = false;
  export let className = "";
  export let id = "";

  const dispatch = createEventDispatcher();
</script>

<input
  {id}
  {type}
  {placeholder}
  {disabled}
  {...$$restProps}
  bind:value
  on:input={(event) => dispatch("input", (event.target as HTMLInputElement).value)}
  on:change={(event) => dispatch("change", (event.target as HTMLInputElement).value)}
  class={`h-[var(--control-height)] w-full rounded-sm border border-border bg-surface px-[var(--control-padding-x)] text-sm text-text placeholder:text-muted focus:border-accent focus:outline-none ${className}`}
/>
