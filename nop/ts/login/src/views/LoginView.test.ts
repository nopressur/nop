// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { render, screen, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { LoginRuntimeConfig } from '../types';
import LoginView from './LoginView.svelte';

const apiMocks = vi.hoisted(() => ({
  postJson: vi.fn()
}));

const argonMocks = vi.hoisted(() => ({
  deriveFrontEndHash: vi.fn()
}));

vi.mock('../api', () => ({
  postJson: apiMocks.postJson
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
  initialRoute: 'login',
  providers: [],
  passwordFrontEnd: {
    memoryKib: 65536,
    iterations: 2,
    parallelism: 1,
    outputLen: 32,
    saltLen: 16
  },
  returnPath: null,
  user: null
};

const originalLocation = window.location;
const locationAssign = vi.fn();

function buildResponse(ok: boolean): Response {
  return { ok } as Response;
}

describe('LoginView', () => {
  beforeEach(() => {
    apiMocks.postJson.mockReset();
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

  it('shows an error when email is missing', async () => {
    apiMocks.postJson.mockResolvedValueOnce({
      response: buildResponse(true),
      data: { login_session_id: 'session', return_path: null }
    });

    render(LoginView, { props: { config } });

    await waitFor(() => expect(apiMocks.postJson).toHaveBeenCalledOnce());
    await userEvent.click(screen.getByRole('button', { name: 'Continue' }));

    expect(screen.getByText('Email is required.')).toBeInTheDocument();
  });

  it('focuses the email field on load', async () => {
    apiMocks.postJson.mockResolvedValueOnce({
      response: buildResponse(true),
      data: { login_session_id: 'session', return_path: null }
    });

    render(LoginView, { props: { config } });

    await waitFor(() => expect(apiMocks.postJson).toHaveBeenCalledOnce());

    const emailInput = screen.getByLabelText('Email');
    await waitFor(() => expect(document.activeElement).toBe(emailInput));
  });

  it('focuses the password field after submitting email', async () => {
    apiMocks.postJson
      .mockResolvedValueOnce({
        response: buildResponse(true),
        data: { login_session_id: 'session', return_path: null }
      })
      .mockResolvedValueOnce({
        response: buildResponse(true),
        data: { front_end_salt: 'salt' }
      });

    render(LoginView, { props: { config } });

    await waitFor(() => expect(apiMocks.postJson).toHaveBeenCalledOnce());

    await userEvent.type(screen.getByLabelText('Email'), 'user@example.com');
    await userEvent.click(screen.getByRole('button', { name: 'Continue' }));

    const passwordInput = await screen.findByLabelText('Password');
    await waitFor(() => expect(document.activeElement).toBe(passwordInput));
  });

  it('submits email and password then redirects', async () => {
    apiMocks.postJson
      .mockResolvedValueOnce({
        response: buildResponse(true),
        data: { login_session_id: 'session', return_path: '/admin' }
      })
      .mockResolvedValueOnce({
        response: buildResponse(true),
        data: { front_end_salt: 'salt' }
      })
      .mockResolvedValueOnce({
        response: buildResponse(true),
        data: { return_path: null }
      });
    argonMocks.deriveFrontEndHash.mockResolvedValueOnce('hash');

    render(LoginView, { props: { config } });

    await waitFor(() => expect(apiMocks.postJson).toHaveBeenCalledOnce());

    await userEvent.type(screen.getByLabelText('Email'), 'user@example.com');
    await userEvent.click(screen.getByRole('button', { name: 'Continue' }));

    await waitFor(() => expect(screen.getByLabelText('Password')).toBeInTheDocument());

    await userEvent.type(screen.getByLabelText('Password'), 'supersecret');
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));

    await waitFor(() => expect(locationAssign).toHaveBeenCalledWith('/admin'));
  });
});
