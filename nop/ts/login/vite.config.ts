// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { defineConfig } from 'vitest/config';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const defaultOutDir = path.resolve(__dirname, '../../builtin/login-dev');
const defaultBase = '/builtin/login-dev/';
const outDir = process.env.LOGIN_SPA_OUT_DIR
  ? path.resolve(process.env.LOGIN_SPA_OUT_DIR)
  : defaultOutDir;
const base = process.env.LOGIN_SPA_BASE ?? defaultBase;

function copyFontsourceFiles(outputDir: string) {
  return {
    name: 'copy-fontsource-files',
    async closeBundle() {
      const sourceDir = path.resolve(__dirname, 'node_modules/@fontsource/space-grotesk/files');
      const targetDir = path.resolve(outputDir, 'files');
      await fs.mkdir(targetDir, { recursive: true });
      const entries = await fs.readdir(sourceDir);
      await Promise.all(
        entries
          .filter((entry) => entry.endsWith('.woff2') || entry.endsWith('.woff'))
          .map((entry) =>
            fs.copyFile(path.join(sourceDir, entry), path.join(targetDir, entry))
          )
      );
    }
  };
}

export default defineConfig({
  base,
  plugins: [svelte(), copyFontsourceFiles(outDir)],
  resolve: {
    conditions: ['browser']
  },
  server: {
    fs: {
      allow: [path.resolve(__dirname, '..')]
    }
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    globals: true,
    include: ['src/**/*.test.ts']
  },
  build: {
    outDir,
    emptyOutDir: true,
    cssCodeSplit: false,
    rollupOptions: {
      output: {
        entryFileNames: 'login.js',
        chunkFileNames: 'login-[name].js',
        assetFileNames: (assetInfo) => {
          if (assetInfo.name === 'style.css') {
            return 'login.css';
          }
          return 'login-[name][extname]';
        }
      }
    }
  }
});
