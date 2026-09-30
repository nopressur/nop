// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('theme preset CSS', () => {
  it('disables floating navbar animation for reduced-motion users', () => {
    const css = readFileSync(resolve(process.cwd(), 'theme-preset.css'), 'utf8');

    expect(css).toContain('@media (prefers-reduced-motion: reduce)');
    expect(css).toContain('.navbar[data-site-navbar].is-site-navbar-revealed');
    expect(css).toContain('.site-navbar-flow-spacer');
    expect(css).toContain('animation: none');
  });

  it('shows document structure hugging the content in a centered grid at wide widths', () => {
    const css = readFileSync(resolve(process.cwd(), 'theme-preset.css'), 'utf8');

    expect(css).toContain('@media screen and (min-width: 1280px)');
    expect(css).toContain('.doc-layout');
    expect(css).toContain('display: grid');
    expect(css).toContain('--size-content-measure, 75ch');
    expect(css).toContain('justify-self: end');
    expect(css).toContain('position: -webkit-sticky');
    expect(css).toContain('position: sticky');
    expect(css).toContain('--size-doc-structure-width');
    expect(css).toContain('--size-doc-structure-gap');
    expect(css).toContain('.doc-layout--wide');
    expect(css).toContain('width: calc(100%');
    expect(css).toContain('max-width: min(calc(100%');
    expect(css).toContain('margin-left: var(--size-doc-structure-gap');
    expect(css).toContain('margin-top: calc(var(--size-content-margin-y');
  });

  it('lets escape bands span the full grid width with exact-width heroes', () => {
    const css = readFileSync(resolve(process.cwd(), 'theme-preset.css'), 'utf8');

    expect(css).toContain('.site-doc-band');
    expect(css).toContain('grid-column: 1 / -1');
    const heroRule = css.match(/\.sc-hero-img\s*\{[^}]*\}/)?.[0] ?? '';
    expect(heroRule).toContain('width: 100%');
    expect(heroRule).not.toContain('100vw');
  });

  it('shows a floating top bar with drawers below wide widths', () => {
    const css = readFileSync(resolve(process.cwd(), 'theme-preset.css'), 'utf8');

    expect(css).toContain('@media screen and (max-width: 1279px)');
    expect(css).toContain('.site-topbar');
    expect(css).toContain('.site-drawer--menu');
    expect(css).toContain('.site-drawer--structure');
    expect(css).toContain('[data-site-expander-chevron]');
  });
});
