<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->

<script lang="ts">
  import { createEventDispatcher } from "svelte";

  export type StateToggleTone = "success" | "warning" | "danger";

  export type StateToggleOption = {
    value: string;
    label: string;
    tone: StateToggleTone;
  };

  export let value = "";
  export let options: StateToggleOption[] = [];
  export let disabled = false;
  export let ariaLabel: string | null = null;
  export let className = "";

  const dispatch = createEventDispatcher<{ change: string }>();

  const base =
    "inline-flex h-[32px] min-w-[132px] items-center justify-center rounded-sm border px-3 text-[10px] uppercase tracking-[0.2em] transition disabled:cursor-not-allowed disabled:opacity-40";

  const toneMap = {
    success: "border-success bg-transparent text-success hover:opacity-80",
    warning: "border-warning bg-transparent text-warning hover:opacity-80",
    danger: "border-danger bg-transparent text-danger hover:opacity-80",
  } as const;

  $: selectedIndex = Math.max(0, options.findIndex((option) => option.value === value));
  $: selected = options[selectedIndex] ?? options[0] ?? {
    value: "",
    label: "",
    tone: "success" as StateToggleTone,
  };

  function handleClick(): void {
    if (disabled || options.length === 0) {
      return;
    }
    const next = options[(selectedIndex + 1) % options.length];
    if (!next || next.value === value) {
      return;
    }
    dispatch("change", next.value);
  }
</script>

<button
  {...$$restProps}
  type="button"
  {disabled}
  aria-label={ariaLabel || undefined}
  class={`${base} ${toneMap[selected.tone]} ${className}`}
  on:click={handleClick}
>
  {selected.label}
</button>
