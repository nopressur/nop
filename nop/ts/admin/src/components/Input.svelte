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
  export let error = "";
  export let invalid = false;

  let hasError = false;
  let isInvalid = false;
  let errorId = "";

  const dispatch = createEventDispatcher();

  $: hasError = Boolean(error);
  $: isInvalid = invalid || hasError;
  $: errorId = id ? `${id}-error` : "";
</script>

<div class="w-full">
  <input
    {id}
    {type}
    {placeholder}
    {disabled}
    aria-invalid={isInvalid ? "true" : undefined}
    aria-describedby={hasError && errorId ? errorId : undefined}
    {...$$restProps}
    bind:value
    on:input={(event) => dispatch("input", (event.target as HTMLInputElement).value)}
    on:change={(event) => dispatch("change", (event.target as HTMLInputElement).value)}
    class={`h-[var(--control-height)] w-full rounded-sm border bg-surface px-[var(--control-padding-x)] text-sm text-text placeholder:text-muted focus:outline-none ${isInvalid ? "border-danger focus:border-danger" : "border-border focus:border-accent"} ${className}`}
  />
  {#if hasError}
    <p id={errorId || undefined} class="mt-1 text-[10px] text-danger">
      {error}
    </p>
  {/if}
</div>
