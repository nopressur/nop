// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { JSDOM, VirtualConsole } from 'jsdom';

const siteRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const bundle = path.resolve(siteRoot, '../../builtin/site.js');

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: siteRoot,
    encoding: 'utf8',
    stdio: 'inherit'
  });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} failed with status ${result.status}`);
  }
}

function htmlFixture() {
  return `<!doctype html>
    <html>
      <body>
        <div data-site-root>
          <button type="button" data-site-mobile-toggle class="navbar-burger" aria-expanded="false">Menu</button>
          <div data-site-mobile-menu class="navbar-menu"></div>
          <div data-site-dropdown>
            <button type="button" data-site-dropdown-toggle class="navbar-link" aria-expanded="false">More</button>
            <div class="navbar-dropdown"></div>
          </div>
          <div data-site-close-dropdowns></div>
          <button type="button" data-site-search-button>Search</button>
          <div data-site-search-overlay hidden>
            <div data-site-search-backdrop></div>
            <section data-site-search-panel>
              <button type="button" data-site-search-close>Close</button>
              <input data-site-search-input type="text" />
              <div data-site-search-status></div>
              <div data-site-search-results></div>
            </section>
          </div>
          <div class="navbar-end" data-site-content-id="0000000000000001">
            <div data-site-user-menu></div>
          </div>
          <figure data-site-code-block="true">
            <figcaption>
              <button type="button" data-site-code-copy="true" aria-label="Copy code block"><img src="/builtin/copy.svg" alt="" width="16" height="16"><span class="site-visually-hidden" data-site-code-copy-status="true"></span></button>
            </figcaption>
            <pre><code>echo hello</code></pre>
          </figure>
        </div>
      </body>
    </html>`;
}

function stripStringsAndComments(source) {
  let output = '';
  let i = 0;
  let state = 'code';
  let regexClass = false;
  function startsRegex() {
    const trimmed = output.replace(/\s+$/g, '');
    if (trimmed.length === 0) {
      return true;
    }
    const previous = trimmed[trimmed.length - 1];
    return '([{=,:;!&|?+-*~^<>'.includes(previous);
  }

  while (i < source.length) {
    const ch = source[i];
    const next = source[i + 1];
    if (state === 'code') {
      if (ch === '"' || ch === "'" || ch === '`') {
        state = ch;
        output += ' ';
      } else if (ch === '/' && next === '/') {
        state = 'line-comment';
        output += '  ';
        i += 1;
      } else if (ch === '/' && next === '*') {
        state = 'block-comment';
        output += '  ';
        i += 1;
      } else if (ch === '/' && startsRegex()) {
        state = 'regex';
        regexClass = false;
        output += ' ';
      } else {
        output += ch;
      }
    } else if (state === 'line-comment') {
      if (ch === '\n') {
        state = 'code';
        output += '\n';
      } else {
        output += ' ';
      }
    } else if (state === 'block-comment') {
      if (ch === '*' && next === '/') {
        state = 'code';
        output += '  ';
        i += 1;
      } else {
        output += ch === '\n' ? '\n' : ' ';
      }
    } else if (state === 'regex') {
      if (ch === '\\') {
        output += ' ';
        i += 1;
        output += source[i] === '\n' ? '\n' : ' ';
      } else if (ch === '[') {
        regexClass = true;
        output += ' ';
      } else if (ch === ']') {
        regexClass = false;
        output += ' ';
      } else if (ch === '/' && !regexClass) {
        state = 'regex-flags';
        output += ' ';
      } else {
        output += ch === '\n' ? '\n' : ' ';
      }
    } else if (state === 'regex-flags') {
      if (/[A-Za-z]/.test(ch)) {
        output += ' ';
      } else {
        state = 'code';
        output += ch;
      }
    } else if (ch === '\\') {
      output += ' ';
      i += 1;
      output += source[i] === '\n' ? '\n' : ' ';
    } else if (ch === state) {
      state = 'code';
      output += ' ';
    } else {
      output += ch === '\n' ? '\n' : ' ';
    }
    i += 1;
  }
  return output;
}

function assertNoBannedSyntax(source) {
  const code = stripStringsAndComments(source);
  const checks = [
    [/\bBigInt\b/, 'BigInt'],
    [/\bimport\s*\(/, 'dynamic import'],
    [/^\s*import\s/m, 'ES module import declaration'],
    [/^\s*export\s/m, 'ES module export declaration'],
    [/\?\./, 'optional chaining'],
    [/\?\?/, 'nullish coalescing']
  ];
  const failures = checks
    .filter(([pattern]) => pattern.test(code))
    .map(([, label]) => label);
  if (failures.length > 0) {
    throw new Error(`site.js contains unsupported Safari 12 syntax: ${failures.join(', ')}`);
  }
}

async function assertLegacyRuntimeSmoke(source, scenario) {
  const errors = [];
  const virtualConsole = new VirtualConsole();
  virtualConsole.on('error', (...args) => {
    errors.push(args.map((arg) => String(arg)).join(' '));
  });
  virtualConsole.on('jsdomError', (err) => {
    errors.push(err.message);
  });

  const dom = new JSDOM(htmlFixture(), {
    pretendToBeVisual: true,
    runScripts: 'outside-only',
    url: 'http://localhost/',
    virtualConsole
  });
  const { window } = dom;
  scenario.prepare(window);
  window.fetch = (input) => {
    const url = String(input);
    if (url.includes('/api/profile')) {
      return Promise.resolve({
        ok: true,
        json: async () => ({ authenticated: false })
      });
    }
    if (url.includes('/api/search')) {
      return Promise.resolve({
        ok: true,
        json: async () => []
      });
    }
    return Promise.resolve({
      ok: true,
      json: async () => ({})
    });
  };

  try {
    window.eval(source);
    window.document.dispatchEvent(new window.Event('DOMContentLoaded', { bubbles: true }));
    await new Promise((resolve) => window.setTimeout(resolve, 20));
    const toggle = window.document.querySelector('[data-site-mobile-toggle]');
    const menu = window.document.querySelector('[data-site-mobile-menu]');
    toggle.dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
    if (!toggle.classList.contains('is-active') || !menu.classList.contains('is-active')) {
      throw new Error('site navigation did not initialize');
    }
  } catch (err) {
    throw new Error(`site.js failed ${scenario.name} runtime smoke: ${err.message}`);
  } finally {
    window.close();
  }

  if (errors.length > 0) {
    throw new Error(`site.js failed ${scenario.name} runtime smoke: ${errors[0]}`);
  }
}

const legacyRuntimeScenarios = [
  {
    name: 'without EventTarget constructor',
    prepare(window) {
      Object.defineProperty(window, 'EventTarget', {
        configurable: true,
        value: undefined
      });
    }
  }
];

const source = await fs.readFile(bundle, 'utf8');
run('npx', ['es-check', 'es2019', bundle]);
assertNoBannedSyntax(source);
for (const scenario of legacyRuntimeScenarios) {
  await assertLegacyRuntimeSmoke(source, scenario);
}

console.log('Public site bundle compatibility checks passed.');
