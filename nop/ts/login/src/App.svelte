<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->

<script lang="ts">
  import type { LoginRuntimeConfig } from './types';
  import LoginView from './views/LoginView.svelte';
  import ProfileView from './views/ProfileView.svelte';

  export let config: LoginRuntimeConfig;

  const route = config.initialRoute === 'profile' ? 'profile' : 'login';
</script>

<main class="login-shell">
  <div class="login-card">
    <header class="login-header">
      <p class="app-name">{config.appName}</p>
      <h1 class="login-title">{route === 'profile' ? 'Profile' : 'Sign in'}</h1>
      <p class="login-subtitle">
        {#if route === 'profile'}
          Update your account details.
        {:else}
          Use your email and password to continue.
        {/if}
      </p>
    </header>

    <section class="login-body">
      {#if route === 'profile'}
        <ProfileView {config} />
      {:else}
        <LoginView {config} />
      {/if}
    </section>
  </div>
</main>
