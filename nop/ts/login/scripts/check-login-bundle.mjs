// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { JSDOM, VirtualConsole } from 'jsdom';

const loginRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const defaultOutDir = path.resolve(loginRoot, '../../builtin/login-dev');
const shellFixturePath = path.join(loginRoot, 'test-fixtures/login-shell.html');
const outDir = process.env.LOGIN_SPA_OUT_DIR
  ? path.resolve(process.env.LOGIN_SPA_OUT_DIR)
  : defaultOutDir;

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: loginRoot,
    encoding: 'utf8',
    stdio: 'inherit',
    env: {
      ...process.env,
      ...options.env
    }
  });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} failed with status ${result.status}`);
  }
}

async function listLoginScripts() {
  try {
    const entries = await fs.readdir(outDir, { withFileTypes: true });
    return entries
      .filter((entry) => entry.isFile() && /^login(?:-|\.js$)/.test(entry.name) && entry.name.endsWith('.js'))
      .map((entry) => path.join(outDir, entry.name))
      .sort();
  } catch (err) {
    if (err && err.code === 'ENOENT') {
      return [];
    }
    throw err;
  }
}

async function ensureBundle() {
  let scripts = await listLoginScripts();
  if (scripts.length > 0) {
    return scripts;
  }
  run('npm', ['run', 'build:vite']);
  run('npm', ['run', 'build:legacy']);
  scripts = await listLoginScripts();
  if (scripts.length === 0) {
    throw new Error(`No login JavaScript files found in ${outDir}`);
  }
  return scripts;
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
    if ('([{=,:;!&|?+-*~^<>'.includes(previous)) {
      return true;
    }
    return /\b(return|throw|case|delete|typeof|void|new|in|instanceof)$/.test(trimmed);
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

function assertNoBannedSyntax(source, file) {
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
    throw new Error(`${file} contains unsupported Safari 12 syntax: ${failures.join(', ')}`);
  }
}

async function loadShellFixture() {
  const html = await fs.readFile(shellFixturePath, 'utf8');
  const fixture = new JSDOM(html);
  try {
    const { document } = fixture.window;
    const target = document.getElementById('login-app');
    if (!target) {
      throw new Error('fixture is missing #login-app');
    }
    const rawConfig = target.getAttribute('data-login-config');
    if (!rawConfig) {
      throw new Error('fixture is missing data-login-config');
    }
    const config = JSON.parse(rawConfig);
    if (config.appName !== 'Compatibility Smoke' || config.initialRoute !== 'login') {
      throw new Error('fixture runtime config does not match the compatibility smoke contract');
    }
    if (html.includes('window.nopLoginConfig')) {
      throw new Error('fixture must not rely on window.nopLoginConfig');
    }
    const script = document.querySelector('script[src]');
    if (!script || script.getAttribute('type')) {
      throw new Error('fixture must load the login bundle as a classic script');
    }
    return html;
  } finally {
    fixture.window.close();
  }
}

function assertLoginShellMounted(window) {
  const target = window.document.getElementById('login-app');
  if (!target) {
    throw new Error('login shell target is missing after script execution');
  }
  const text = target.textContent ?? '';
  if (text.includes('Login is unavailable')) {
    throw new Error(`login unavailable fallback rendered: ${text}`);
  }
  if (!text.includes('Sign in')) {
    throw new Error(`login shell did not render the sign-in heading; rendered text: ${text}`);
  }
  if (!window.document.querySelector('#login-app input[type="email"]')) {
    throw new Error('login shell did not render the email input');
  }
  const continueButton = Array.from(window.document.querySelectorAll('#login-app button'))
    .find((button) => (button.textContent ?? '').includes('Continue'));
  if (!continueButton) {
    throw new Error('login shell did not render the Continue button');
  }
}

async function assertLegacyRuntimeSmoke(source, file, shellHtml, scenario) {
  const errors = [];
  const virtualConsole = new VirtualConsole();
  virtualConsole.on('error', (...args) => {
    errors.push(args.map((arg) => String(arg)).join(' '));
  });
  virtualConsole.on('jsdomError', (err) => {
    errors.push(err.message);
  });

  const dom = new JSDOM(
    shellHtml,
    {
      runScripts: 'outside-only',
      url: 'http://localhost/login',
      virtualConsole
    }
  );
  const { window } = dom;
  scenario.prepare(window);
  delete window.nopLoginConfig;
  window.fetch = () =>
    Promise.resolve({
      ok: false,
      headers: new window.Headers({
        'content-type': 'application/json'
      }),
      json: async () => ({
        message: 'Compatibility smoke response'
      })
    });

  try {
    window.eval(source);
    await new Promise((resolve) => {
      window.setTimeout(resolve, 0);
    });
    assertLoginShellMounted(window);
  } catch (err) {
    throw new Error(`${file} failed ${scenario.name} runtime smoke: ${err.message}`);
  } finally {
    window.close();
  }

  const startupFailure = errors.find((message) =>
    message.includes('Failed to start login app')
  );
  if (startupFailure) {
    throw new Error(`${file} failed ${scenario.name} runtime smoke: ${startupFailure}`);
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
  },
  {
    name: 'without queueMicrotask',
    prepare(window) {
      Object.defineProperty(window, 'queueMicrotask', {
        configurable: true,
        value: undefined
      });
    }
  },
  {
    name: 'without WebAssembly',
    prepare(window) {
      Object.defineProperty(window, 'WebAssembly', {
        configurable: true,
        value: undefined
      });
    }
  },
  {
    name: 'without String.prototype.replaceAll',
    prepare(window) {
      Object.defineProperty(window.String.prototype, 'replaceAll', {
        configurable: true,
        value: undefined
      });
    }
  },
  {
    name: 'with Safari 12 missing APIs together',
    prepare(window) {
      Object.defineProperty(window, 'EventTarget', {
        configurable: true,
        value: undefined
      });
      Object.defineProperty(window, 'queueMicrotask', {
        configurable: true,
        value: undefined
      });
      Object.defineProperty(window, 'WebAssembly', {
        configurable: true,
        value: undefined
      });
      Object.defineProperty(window.String.prototype, 'replaceAll', {
        configurable: true,
        value: undefined
      });
    }
  },
  {
    name: 'without ChildNode convenience methods',
    prepare(window) {
      for (const prototype of [
        window.Element?.prototype,
        window.CharacterData?.prototype,
        window.DocumentType?.prototype
      ]) {
        if (!prototype) {
          continue;
        }
        for (const method of ['before', 'after', 'remove', 'replaceWith']) {
          Object.defineProperty(prototype, method, {
            configurable: true,
            value: undefined
          });
        }
      }
      if (window.DocumentFragment?.prototype) {
        Object.defineProperty(window.DocumentFragment.prototype, 'append', {
          configurable: true,
          value: undefined
        });
      }
    }
  }
];

const scripts = await ensureBundle();
run('npx', ['es-check', 'es2019', ...scripts]);
const shellHtml = await loadShellFixture();

for (const script of scripts) {
  const source = await fs.readFile(script, 'utf8');
  assertNoBannedSyntax(source, path.relative(loginRoot, script));
  for (const scenario of legacyRuntimeScenarios) {
    await assertLegacyRuntimeSmoke(source, path.relative(loginRoot, script), shellHtml, scenario);
  }
}

console.log('Login SPA bundle compatibility checks passed.');
