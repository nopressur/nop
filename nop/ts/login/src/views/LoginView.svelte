<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->

<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { deriveFrontEndHash } from '../argon';
  import { postJson } from '../api';
  import type {
    LoginBootstrapResponse,
    LoginRuntimeConfig,
    LoginSuccessResponse,
    PasswordEmailResponse
  } from '../types';

  export let config: LoginRuntimeConfig;

  let email = '';
  let password = '';
  let frontEndSalt = '';
  let loginSessionId = '';
  let returnPath: string | null = config.returnPath ?? null;
  let step: 'email' | 'password' = 'email';
  let emailInput: HTMLInputElement | null = null;
  let passwordInput: HTMLInputElement | null = null;
  let lastFocusedStep: 'email' | 'password' | null = null;
  let error = '';
  let info = '';
  let busy = false;
  let hashing = false;

  async function focusStep(target: 'email' | 'password') {
    await tick();
    if (target === 'email') {
      emailInput?.focus();
    } else {
      passwordInput?.focus();
    }
    lastFocusedStep = target;
  }

  function resetToEmail(message: string) {
    error = message;
    info = '';
    busy = false;
    hashing = false;
    password = '';
    frontEndSalt = '';
    loginSessionId = '';
    step = 'email';
    email = '';
  }

  function sanitizeReturnPath(path: string | null | undefined): string | null {
    if (!path) {
      return null;
    }
    if (!path.startsWith('/') || path.startsWith('//') || path.includes('://')) {
      return null;
    }
    return path;
  }

  async function bootstrapSession() {
    busy = true;
    error = '';
    info = 'Preparing sign-in...';

    const { response, data, error: err } = await postJson<LoginBootstrapResponse>(
      `${config.loginPath}/bootstrap`,
      { return_path: sanitizeReturnPath(config.returnPath) }
    );

    if (!response.ok || !data) {
      error = err?.message ?? 'Unable to start a login session.';
      info = '';
      busy = false;
      return;
    }

    loginSessionId = data.login_session_id;
    returnPath = data.return_path ?? returnPath;
    step = 'email';
    info = '';
    busy = false;
  }

  async function submitEmail() {
    if (!email.trim()) {
      error = 'Email is required.';
      return;
    }
    if (!loginSessionId) {
      await bootstrapSession();
      if (!loginSessionId) {
        return;
      }
    }

    busy = true;
    error = '';
    info = 'Preparing password entry...';

    const { response, data, error: err } = await postJson<PasswordEmailResponse>(
      `${config.loginPath}/pwd/email`,
      { login_session_id: loginSessionId, email: email.trim() }
    );

    if (!response.ok || !data) {
      const message = err?.message ?? 'Unable to fetch salt.';
      if (err?.code === 'login_session_expired') {
        error = 'Session expired. Please start again.';
        await bootstrapSession();
      } else if (err?.code === 'login_rate_limited') {
        error = message;
      } else {
        error = message;
      }
      info = '';
      busy = false;
      return;
    }

    frontEndSalt = data.front_end_salt;
    step = 'password';
    info = '';
    busy = false;
  }

  async function submitPassword() {
    if (!password) {
      error = 'Password is required.';
      return;
    }
    if (!loginSessionId || !frontEndSalt) {
      error = 'Login session is missing. Please start again.';
      await bootstrapSession();
      return;
    }

    busy = true;
    hashing = true;
    error = '';
    info = 'Preparing sign-in...';

    let frontEndHash: string;
    try {
      frontEndHash = await deriveFrontEndHash(password, frontEndSalt, config.passwordFrontEnd);
    } catch (err) {
      error = 'Unable to prepare sign-in. Please refresh and try again.';
      busy = false;
      hashing = false;
      password = '';
      return;
    }

    hashing = false;
    info = 'Signing in...';

    const { response, data, error: err } = await postJson<LoginSuccessResponse>(
      `${config.loginPath}/pwd/password`,
      {
        login_session_id: loginSessionId,
        email: email.trim(),
        front_end_hash: frontEndHash
      }
    );

    password = '';

    if (!response.ok || !data) {
      const message = err?.message ?? 'Login failed.';
      if (err?.code === 'login_session_expired') {
        resetToEmail('Session expired. Please start again.');
      } else {
        resetToEmail(message);
      }
      return;
    }

    const redirect = data.return_path || returnPath || '/';
    window.location.assign(redirect);
  }

  function backToEmail() {
    step = 'email';
    password = '';
    error = '';
  }

  $: if (step !== lastFocusedStep) {
    void focusStep(step);
  }

  onMount(() => {
    void bootstrapSession();
  });
</script>

<div class="form-stack">
  <p class="helper-text">
    {#if step === 'email'}
      Enter your email to continue.
    {:else}
      Enter your password to finish signing in.
    {/if}
  </p>

  {#if error}
    <div class="callout callout-error">
      {error}
    </div>
  {/if}

  {#if info}
    <div class="callout callout-info">
      {info}
    </div>
  {/if}

  {#if step === 'email'}
    <form class="form" on:submit|preventDefault={submitEmail}>
      <label class="field">
        <span>Email</span>
        <input
          type="email"
          class="input"
          bind:value={email}
          bind:this={emailInput}
          autocomplete="email"
          placeholder="name@example.com"
        />
      </label>
      <button type="submit" class="button" disabled={busy}>
        {busy ? 'Starting…' : 'Continue'}
      </button>
    </form>
  {:else}
    <form class="form" on:submit|preventDefault={submitPassword}>
      <label class="field">
        <span>Password</span>
        <input
          type="password"
          class="input"
          bind:value={password}
          bind:this={passwordInput}
          autocomplete="current-password"
          placeholder="••••••••"
        />
      </label>
      <div class="row">
        <button type="button" class="button button-secondary" on:click={backToEmail} disabled={busy}>
          Back
        </button>
        <button type="submit" class="button" disabled={busy}>
          {hashing ? 'Preparing…' : busy ? 'Signing in…' : 'Sign in'}
        </button>
      </div>
    </form>
  {/if}
</div>
