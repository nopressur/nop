<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->

<script lang="ts">
  import { onDestroy, onMount } from "svelte";
  import { loadAce } from "../services/ace";
  import { matchMediaQuery } from "../services/browser";

  export let value = "";
  export let mode: "markdown" | "html" = "markdown";
  export let editor: AceAjax.Editor | null = null;
  export let readOnly = false;

  let container: HTMLDivElement;
  let updating = false;
  let mediaQuery: MediaQueryList | null = null;

  function setTheme(): void {
    if (!editor) {
      return;
    }
    const query = matchMediaQuery("(prefers-color-scheme: dark)");
    const isDark = query ? query.matches : false;
    editor.setTheme(isDark ? "ace/theme/monokai" : "ace/theme/github");
  }

  onMount(async () => {
    await loadAce();
    const ace = (window as Window & { ace?: AceAjax.Ace }).ace;
    if (!ace) {
      throw new Error("Ace not available");
    }
    editor = ace.edit(container);
    editor.session.setUseWorker(false);
    editor.session.setMode(`ace/mode/${mode}`);
    editor.setValue(value || "", -1);
    editor.setFontSize(14);
    editor.setReadOnly(readOnly);

    editor.on("change", () => {
      updating = true;
      value = editor.getValue();
      updating = false;
    });

    setTheme();
    mediaQuery = matchMediaQuery("(prefers-color-scheme: dark)");
    mediaQuery?.addEventListener("change", setTheme);
  });

  $: if (editor && editor.session) {
    editor.session.setMode(`ace/mode/${mode}`);
    editor.setReadOnly(readOnly);
  }

  $: if (editor && !updating) {
    const current = editor.getValue();
    if (value !== current) {
      const cursor = editor.getCursorPosition();
      editor.setValue(value || "", -1);
      editor.moveCursorToPosition(cursor);
    }
  }

  onDestroy(() => {
    mediaQuery?.removeEventListener("change", setTheme);
    if (editor) {
      editor.destroy();
    }
  });
</script>

<div class="h-full w-full" bind:this={container}></div>
