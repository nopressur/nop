<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->

<script lang="ts">
  export let value = "";
  export let disabled = false;
  export let className = "";
  export let id = "";
</script>

<select
  {id}
  bind:value
  {disabled}
  class={`h-[var(--control-height)] w-full rounded-sm border border-border bg-surface px-[var(--control-padding-x)] text-sm text-text focus:border-accent focus:outline-none ${className}`}
>
  <slot />
</select>
