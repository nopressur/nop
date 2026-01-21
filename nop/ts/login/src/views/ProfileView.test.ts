// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { render, screen, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { LoginRuntimeConfig, ProfilePasswordSaltResponse } from '../types';
import ProfileView from './ProfileView.svelte';

const apiMocks = vi.hoisted(() => ({
  csrfFetch: vi.fn(),
  postJson: vi.fn(),
  clearCsrfCache: vi.fn()
}));

const argonMocks = vi.hoisted(() => ({
  deriveFrontEndHash: vi.fn()
}));

vi.mock('../api', () => ({
  csrfFetch: apiMocks.csrfFetch,
  postJson: apiMocks.postJson,
  clearCsrfCache: apiMocks.clearCsrfCache
}));

vi.mock('../argon', () => ({
  deriveFrontEndHash: argonMocks.deriveFrontEndHash
}));

const config: LoginRuntimeConfig = {
  appName: 'Test App',
  loginPath: '/login',
  profilePath: '/login/profile',
  profileApiPath: '/profile',
  csrfTokenPath: '/login/csrf-token-api',
  initialRoute: 'profile',
  providers: [],
  passwordFrontEnd: {
    memoryKib: 65536,
    iterations: 2,
    parallelism: 1,
    outputLen: 32,
    saltLen: 16
  },
  returnPath: '/admin',
  user: {
    email: 'alpha@example.com',
    name: 'Alpha'
  }
};

const originalLocation = window.location;
const locationAssign = vi.fn();

function buildResponse(options: { ok: boolean; json?: unknown }): Response {
  return {
    ok: options.ok,
    json: async () => options.json
  } as Response;
}

const saltPayload: ProfilePasswordSaltResponse = {
  change_token: 'change-token',
  expires_in_seconds: 60,
  current: {
    front_end_salt: 'current-salt'
  },
  next: {
    front_end_salt: 'next-salt'
  }
};

describe('ProfileView', () => {
  beforeEach(() => {
    apiMocks.csrfFetch.mockReset();
    apiMocks.postJson.mockReset();
    apiMocks.clearCsrfCache.mockReset();
    argonMocks.deriveFrontEndHash.mockReset();
    locationAssign.mockReset();
    Object.defineProperty(window, 'location', {
      value: { assign: locationAssign },
      writable: true
    });
  });

  afterEach(() => {
    Object.defineProperty(window, 'location', {
      value: originalLocation,
      writable: true
    });
  });

  it('submits profile updates and clears CSRF cache', async () => {
    apiMocks.csrfFetch.mockResolvedValueOnce(
      buildResponse({ ok: true, json: { success: true, message: 'Saved.' } })
    );

    render(ProfileView, { props: { config } });

    await userEvent.clear(screen.getByLabelText('Display name'));
    await userEvent.type(screen.getByLabelText('Display name'), 'Beta');
    await userEvent.click(screen.getByRole('button', { name: 'Save profile' }));

    await waitFor(() => expect(screen.getByText('Saved.')).toBeInTheDocument());
    expect(apiMocks.clearCsrfCache).toHaveBeenCalledOnce();
  });

  it('changes password after fetching salts', async () => {
    apiMocks.csrfFetch.mockImplementation(async (_config, input) => {
      if (input === `${config.profileApiPath}/pwd/salt`) {
        return buildResponse({ ok: true, json: saltPayload });
      }
      if (input === `${config.profileApiPath}/pwd/change`) {
        return buildResponse({ ok: true, json: { success: true, message: 'Updated.' } });
      }
      return buildResponse({ ok: false, json: { message: 'Unexpected request' } });
    });
    argonMocks.deriveFrontEndHash
      .mockResolvedValueOnce('current-hash')
      .mockResolvedValueOnce('new-hash');

    render(ProfileView, { props: { config } });

    await userEvent.click(screen.getByRole('button', { name: 'Change' }));
    await waitFor(() => expect(screen.getByLabelText('Current password')).toBeInTheDocument());

    await userEvent.type(screen.getByLabelText('Current password'), 'current');
    await userEvent.type(screen.getByLabelText('New password'), 'next');
    await userEvent.type(screen.getByLabelText('Confirm new password'), 'next');
    await userEvent.click(screen.getByRole('button', { name: 'Update password' }));

    await waitFor(() => expect(screen.getByText('Updated.')).toBeInTheDocument());
    expect(apiMocks.clearCsrfCache).toHaveBeenCalledOnce();
  });

  it('logs out and redirects', async () => {
    apiMocks.postJson.mockResolvedValueOnce({
      response: buildResponse({ ok: true }),
      data: { redirect_url: '/login' }
    });

    render(ProfileView, { props: { config } });

    await userEvent.click(screen.getByRole('button', { name: 'Log out' }));
    await waitFor(() => expect(locationAssign).toHaveBeenCalledWith('/login'));
  });
});
