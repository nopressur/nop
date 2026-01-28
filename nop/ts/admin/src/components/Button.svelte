<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->

<script lang="ts">
  import { createEventDispatcher } from "svelte";

  export let variant: "primary" | "outline" | "ghost" | "danger" = "primary";
  export let size: "sm" | "md" = "md";
  export let type: "button" | "submit" | "reset" = "button";
  export let disabled = false;
  export let className = "";

  const dispatch = createEventDispatcher();

  const base =
    "inline-flex items-center justify-center gap-2 rounded-sm border px-4 text-xs uppercase tracking-[0.2em] transition disabled:cursor-not-allowed disabled:opacity-40";

  const sizeMap = {
    sm: "h-[32px]",
    md: "h-[var(--control-height)]"
  } as const;

  const variantMap = {
    primary: "border-transparent bg-accent text-surface hover:bg-accent-strong",
    outline: "border-border bg-transparent text-text hover:bg-surface-2",
    ghost: "border-transparent bg-transparent text-muted hover:text-text",
    danger: "border-transparent bg-danger text-surface hover:opacity-90"
  } as const;

  function handleClick(event: MouseEvent): void {
    dispatch("click", event);
  }
</script>

<button
  {...$$restProps}
  {type}
  {disabled}
  class={`${base} ${sizeMap[size]} ${variantMap[variant]} ${className}`}
  on:click={handleClick}
>
  <slot />
</button>
