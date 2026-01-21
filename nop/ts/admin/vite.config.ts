// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  base: '/builtin/admin/',
  plugins: [svelte()],
  server: {
    fs: {
      allow: [path.resolve(__dirname, '..')]
    }
  },
  build: {
    outDir: path.resolve(__dirname, '../../builtin/admin'),
    emptyOutDir: false,
    cssCodeSplit: false,
    rollupOptions: {
      output: {
        entryFileNames: 'admin-spa.js',
        chunkFileNames: 'admin-[name].js',
        assetFileNames: (assetInfo) => {
          if (assetInfo.name === 'style.css') {
            return 'admin-spa.css';
          }
          return 'admin-[name][extname]';
        }
      }
    }
  }
});
