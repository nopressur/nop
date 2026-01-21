<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->

<script lang="ts">
  import { createEventDispatcher } from "svelte";
  import Button from "./Button.svelte";

  export let page = 1;
  export let pageSize = 25;
  export let total = 0;

  const dispatch = createEventDispatcher<{ pageChange: number }>();

  $: totalPages = Math.max(1, Math.ceil(total / pageSize));

  function go(next: number): void {
    if (next < 1 || next > totalPages) {
      return;
    }
    dispatch("pageChange", next);
  }
</script>

<div class="flex items-center justify-between gap-3">
  <Button
    variant="outline"
    size="sm"
    disabled={page <= 1}
    on:click={() => go(page - 1)}
  >
    Prev
  </Button>
  <div class="text-[11px] uppercase tracking-[0.3em] text-muted">
    Page {page} of {totalPages}
  </div>
  <Button
    variant="outline"
    size="sm"
    disabled={page >= totalPages}
    on:click={() => go(page + 1)}
  >
    Next
  </Button>
</div>
