// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import './app.css';
import App from './app/App.svelte';
import { mount } from 'svelte';

const target = document.getElementById('admin-app');

if (!target) {
  throw new Error('Admin SPA root element not found.');
}

const app = mount(App, { target });

export default app;
