<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->

<script lang="ts">
  export let rows = 3;
  export let className = "";
  export let rowClassName = "h-10";

  $: rowIndexes = Array.from({ length: rows }, (_, index) => index);
</script>

<div class={`space-y-2 ${className}`} aria-hidden="true" data-testid="loading-gradient">
  {#each rowIndexes as index}
    <div
      class={`np-loading-gradient rounded-sm ${rowClassName}`}
      style={`animation-delay: ${index * 80}ms`}
    ></div>
  {/each}
</div>
