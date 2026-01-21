<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->

<script lang="ts">
  import { deriveFrontEndHash } from '../argon';
  import { clearCsrfCache, csrfFetch, postJson } from '../api';
  import type {
    LoginErrorResponse,
    LoginRuntimeConfig,
    ProfilePasswordSaltResponse,
    StatusResponse
  } from '../types';

  export let config: LoginRuntimeConfig;

  let name = config.user?.name ?? '';
  const email = config.user?.email ?? 'unknown';
  const returnPath = config.returnPath ?? '/';

  let profileMessage = '';
  let profileSuccess = true;
  let profileBusy = false;

  let passwordVisible = false;
  let passwordBusy = false;
  let passwordMessage = '';
  let passwordSuccess = true;

  let currentPassword = '';
  let newPassword = '';
  let confirmPassword = '';

  let saltResponse: ProfilePasswordSaltResponse | null = null;
  let saltExpiresAt = 0;

  function resetPasswordFields() {
    currentPassword = '';
    newPassword = '';
    confirmPassword = '';
  }

  async function submitProfile() {
    profileBusy = true;
    profileMessage = '';

    try {
      const response = await csrfFetch(config, `${config.profileApiPath}/update`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ name })
      });

      const payload = await response.json();
      if (response.ok) {
        const data = payload as StatusResponse;
        profileSuccess = data.success;
        profileMessage = data.message ?? 'Profile update failed.';
        if (profileSuccess) {
          clearCsrfCache();
        }
      } else {
        const error = payload as LoginErrorResponse;
        profileSuccess = false;
        profileMessage = error.message ?? 'Profile update failed.';
      }
    } catch (err) {
      profileSuccess = false;
      profileMessage = err instanceof Error ? err.message : 'Profile update failed.';
    } finally {
      profileBusy = false;
    }
  }

  async function ensurePasswordSalts() {
    const now = Date.now();
    if (saltResponse && now < saltExpiresAt) {
      return;
    }

    const response = await csrfFetch(config, `${config.profileApiPath}/pwd/salt`, {
      method: 'POST'
    });

    const payload = await response.json();
    if (!response.ok) {
      const error = payload as LoginErrorResponse;
      throw new Error(error.message ?? 'Unable to fetch password salts.');
    }

    saltResponse = payload as ProfilePasswordSaltResponse;
    saltExpiresAt = now + saltResponse.expires_in_seconds * 1000;
  }

  async function togglePassword() {
    passwordMessage = '';
    passwordSuccess = true;
    if (!passwordVisible) {
      passwordBusy = true;
      try {
        await ensurePasswordSalts();
        passwordVisible = true;
      } catch (err) {
        passwordMessage = err instanceof Error ? err.message : 'Unable to load password module.';
        passwordSuccess = false;
      }
      passwordBusy = false;
      return;
    }

    passwordVisible = false;
    resetPasswordFields();
  }

  function cancelPasswordChange() {
    passwordVisible = false;
    resetPasswordFields();
    passwordMessage = '';
    passwordSuccess = true;
  }

  async function submitPassword() {
    if (!saltResponse) {
      passwordMessage = 'Password salts are missing. Try again.';
      passwordSuccess = false;
      resetPasswordFields();
      return;
    }
    if (!currentPassword || !newPassword) {
      passwordMessage = 'All password fields are required.';
      passwordSuccess = false;
      resetPasswordFields();
      return;
    }
    if (newPassword !== confirmPassword) {
      passwordMessage = 'New passwords do not match.';
      passwordSuccess = false;
      resetPasswordFields();
      return;
    }

    passwordBusy = true;
    passwordMessage = 'Hashing passwords locally...';
    passwordSuccess = true;

    try {
      const currentHash = await deriveFrontEndHash(
        currentPassword,
        saltResponse.current.front_end_salt,
        config.passwordFrontEnd
      );
      const newHash = await deriveFrontEndHash(
        newPassword,
        saltResponse.next.front_end_salt,
        config.passwordFrontEnd
      );

      const response = await csrfFetch(config, `${config.profileApiPath}/pwd/change`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          change_token: saltResponse.change_token,
          current_front_end_hash: currentHash,
          new_front_end_hash: newHash,
          new_front_end_salt: saltResponse.next.front_end_salt
        })
      });

      const payload = await response.json();
      if (response.ok) {
        const data = payload as StatusResponse;
        passwordSuccess = data.success;
        passwordMessage = data.message ?? 'Password update failed.';
      } else {
        const error = payload as LoginErrorResponse;
        passwordSuccess = false;
        passwordMessage = error.message ?? 'Password update failed.';
      }

      if (passwordSuccess) {
        saltResponse = null;
        saltExpiresAt = 0;
        clearCsrfCache();
      }
    } catch (err) {
      passwordSuccess = false;
      passwordMessage = err instanceof Error ? err.message : 'Password update failed.';
    } finally {
      passwordBusy = false;
      resetPasswordFields();
    }
  }

  async function logout() {
    const { response, data } = await postJson<{ redirect_url?: string }>(
      `${config.loginPath}/logout-api`,
      {}
    );
    if (response.ok) {
      clearCsrfCache();
      window.location.assign(data?.redirect_url ?? config.loginPath);
      return;
    }
    passwordMessage = 'Unable to log out right now.';
    passwordSuccess = false;
  }

  function goBack() {
    window.location.assign(returnPath || '/');
  }
</script>

<div class="form-stack">
  <div class="profile-card">
    <p class="profile-label">Signed in as</p>
    <p class="profile-value">{email}</p>
  </div>

  <form class="form" on:submit|preventDefault={submitProfile}>
    <label class="field">
      <span>Display name</span>
      <input
        type="text"
        class="input"
        bind:value={name}
        autocomplete="name"
        placeholder="Your name"
      />
    </label>
    <button type="submit" class="button" disabled={profileBusy}>
      {profileBusy ? 'Saving…' : 'Save profile'}
    </button>
    {#if profileMessage}
      <div class={`callout ${profileSuccess ? 'callout-success' : 'callout-error'}`}>
        {profileMessage}
      </div>
    {/if}
  </form>

  <div class="section">
    <div class="section-header">
      <div>
        <p class="section-title">Password</p>
        <p class="section-subtitle">Use your current password to set a new one.</p>
      </div>
      <button
        type="button"
        class="button button-secondary"
        on:click={togglePassword}
        disabled={passwordBusy}
      >
        {passwordVisible ? 'Hide' : 'Change'}
      </button>
    </div>

    {#if passwordVisible}
      <form class="form form-compact" on:submit|preventDefault={submitPassword}>
        <label class="field">
          <span>Current password</span>
          <input
            type="password"
            class="input"
            bind:value={currentPassword}
            autocomplete="current-password"
          />
        </label>
        <label class="field">
          <span>New password</span>
          <input
            type="password"
            class="input"
            bind:value={newPassword}
            autocomplete="new-password"
          />
        </label>
        <label class="field">
          <span>Confirm new password</span>
          <input
            type="password"
            class="input"
            bind:value={confirmPassword}
            autocomplete="new-password"
          />
        </label>
        <div class="row">
          <button type="button" class="button button-secondary" on:click={cancelPasswordChange}>
            Cancel
          </button>
          <button type="submit" class="button" disabled={passwordBusy}>
            {passwordBusy ? 'Updating…' : 'Update password'}
          </button>
        </div>
      </form>
    {/if}

    {#if passwordMessage}
      <div class={`callout ${passwordSuccess ? 'callout-success' : 'callout-error'}`}>
        {passwordMessage}
      </div>
    {/if}
  </div>

  <div class="row">
    <button type="button" class="button button-secondary" on:click={goBack}>
      Back
    </button>
    <button type="button" class="button button-muted" on:click={logout}>
      Log out
    </button>
  </div>
</div>
