// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import './app.css';
import { mount } from 'svelte';
import App from './App.svelte';
import { getRuntimeConfig } from './runtime';

const target = document.getElementById('login-app');
if (target) {
  try {
    const config = getRuntimeConfig();
    mount(App, { target, props: { config } });
  } catch (err) {
    console.error('Failed to start login app', err);
    target.textContent = 'Login is unavailable. Please refresh and try again.';
  }
}
