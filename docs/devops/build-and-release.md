# Build & Release Engineering

Status: Developed

## Objectives

- Define the build, test, audit, and release pipeline for the `nop` binary and embedded frontend assets.
- Keep public-site browser compatibility enforceable by tooling, with iOS 12 / Safari 12 as the hard floor.
- Ensure all required Rust, Node, browser-test, and asset dependencies are installed automatically through controlled, repeatable commands.
- Reduce software supply-chain risk by using lockfile-based installs, dependency audits, vulnerability scans, and explicit upgrade review.
- Keep local, CI, container, and release workflows aligned so the same checks protect development and shipping.

## Technical Details

### Browser Floor: iOS 12 / Safari 12

The frontend compatibility floor is `iOS >= 12` / `Safari >= 12` (latest iOS 12 is 12.5.x, Safari 12.1-class WebKit), declared in the `browserslist` of `nop/ts/site/package.json` and `nop/ts/login/package.json`. The admin SPA is unaffected.

- Native at this floor, therefore unpolyfilled: all `core-js` modules, `regenerator-runtime` (`async`/`await` native since 10.1), `whatwg-fetch` (native 10.1), and `abortcontroller-polyfill` (native 11.1). Authored code may use `fetch`, `AbortController`, `URLSearchParams` (10.3), `Promise.finally` (11.1), and `replaceWith`/`append`/`prepend` (10) directly.
- Still missing at this floor, therefore kept: Babel lowering for `?.` / `??` (13.1), the `BigInt` ban, the `EventTarget`-constructor prelude and smoke scenario (native 14), the `navigator.clipboard` fallback (13.1), no `IntersectionObserver` without feature detection (12.1/12.2), and no flex `gap` or unprefixed `sticky` in CSS (14.1 and 13).
- `globalThis` needs 12.1 (iOS 12.2+); the prelude is kept as belt-and-braces for 12.0/12.1.
- The single classic IIFE model, `eslint-plugin-compat`, `es-check`, the banned-syntax scan, and the jsdom smoke harness all stay; only their targets and thresholds moved with the floor.
- The login SPA additionally keeps feature-detected `queueMicrotask`, DOM convenience-method, and `String.prototype.replaceAll` shims (compiled Svelte output needs `replaceAll` below Safari 13.1).

### Build Modes

- **Development (`scripts/crg.sh nop run`)**: Actix serves admin and login assets from the filesystem. The builtin crate build script at `nop/crates/nop-rt-builtin/build.rs` ensures the admin SPA is generated in `nop/builtin/admin`, the login SPA is generated in a versioned directory such as `nop/builtin/login-<hash>`, and the public site bundle is generated at `nop/builtin/site.js`.
- **Release (`scripts/crg.sh nop build --release`)**: the builtin crate build script walks `nop/builtin/`, gzip-compresses each asset, and generates the embedded builtin asset map used by release binaries. Release binaries do not need an external builtin asset directory at runtime.
- Cargo reruns the build script when frontend package metadata, frontend source files, or builtin assets change, ensuring embedded release assets stay synchronized with their source.

### Automatic Dependency Installation

Build and test automation prepares local dependencies in a repeatable way.

#### Prepared Frontend Assets

A release host build with `NOP_PREPARE_BUILTIN=1` builds all three frontends
using lockfile installs, performs their built-bundle checks, validates required builtin files,
and writes `nop/builtin/.release-assets.sha256`. The fingerprint covers the frontend sources,
configuration, lockfiles, static asset inputs, and generated builtin contents.

Subsequent target builds can use `NOP_USE_PREBUILT_BUILTIN=1`: the builtin build script validates
completeness and the fingerprint, then embeds those files without running npm or downloading
assets. Both flags are tracked as Cargo build inputs. Source and asset contents must stay
unchanged between preparation and target builds. Container builds must mount the checkout,
including asset inputs outside `nop/`, and pass through the prebuilt flag. The fingerprint
manifest is build metadata and is not embedded as a runtime asset.

- Rust dependencies are resolved by Cargo using `Cargo.lock` for the root package release build.
- Node package roots are `nop/ts/site`, `nop/ts/admin`, `nop/ts/login`, and `tests/playwright`.
- Before each required admin, login, or public-site frontend rebuild, the builtin crate build script runs `npm ci --include=dev --include=optional` when `package-lock.json` exists. This replaces stale or foreign-host `node_modules` with the locked dependencies for the executing host, including native Linux/macOS bindings and build tools even when npm defaults omit development or optional dependencies. Installation failure stops the build before frontend compilation.
- Frontends whose generated assets are up to date skip both dependency installation and compilation. Dependency preparation does not modify committed lockfiles; each required frontend rebuild incurs a clean installation.
- `npm install` is acceptable only as an explicit bootstrap fallback when a lockfile is intentionally absent; release and CI paths should not rely on that fallback.
- Playwright browser binaries are installed by `scripts/run-playwright.sh` into `tests/playwright/.cache/playwright-browsers` through `npx playwright install`.
- Builtin third-party static assets are installed through pinned repo scripts: `scripts/update-bulma.sh --ensure` reads `scripts/bulma-version.txt`, and `scripts/update-ace.sh --ensure` reads `scripts/ace-version.txt`.

### Squash Merge Version Bump

Release commits are normally created as one combined squash-merge and version-bump commit on
`master`.

Required flow:

1. Finish the feature worktree, commit its changes, and push the feature branch.
2. Ensure `_master` is clean and up to date with `origin/master`.
3. In `_master`, run `git merge --squash <feature-branch>` and do not commit the squash diff
   directly.
4. Run `scripts/check-caravaggio-status.sh` from the `_master` checkout and resolve every
   flagged document per the Caravaggio Merge Gate below. The gate scans the post-squash
   working tree, so it covers both the incoming diff and the current `master` content.
5. Run `private/scripts/bump-version.sh patch "<descriptive release commit message>"` from the
   `_master` checkout.

`private/scripts/bump-version.sh` intentionally consumes the pending squash diff. The script updates
all Cargo package versions under `nop/`, regenerates checked-in Cargo lockfiles next to those
manifests, stages the full working tree with `git add -A`, commits the combined feature and version
changes with the supplied message, creates an annotated `v<version>` tag, pushes the commit, and
pushes the tag.

Because the bump script stages the whole working tree, `_master` must be clean before the
`git merge --squash` step. Any unrelated local change present when the script runs will be included
in the release commit.

When a release manager explicitly decides that master has not changed since the feature branch was
cut, final master-side regression validation may be skipped after the squash merge. The feature
worktree must still have completed the applicable targeted and broader validation for the change.

### Caravaggio Merge Gate

`master` must never receive a Caravaggio document with `Status: In Progress`: an action plan
merged to `master` reads as a promise the release already kept. Step 4 of the flow above
enforces this with `scripts/check-caravaggio-status.sh`, which fails while listing every
document under `docs/` and `private/docs/` still marked `In Progress`.

When the gate fails, the release manager must choose one of these before running
`private/scripts/bump-version.sh`:

- Finish the Caravaggio: complete the remaining items, remove the action plan, confirm the
  technical details are evergreen (current-state contract only, no delivery history), and
  return the document to `Status: Developed`.
- Defer it: move the document to `Status: Updated Requirement` with a new mandatory
  subsection describing what is changing, so later development picks it up deliberately
  instead of silently inheriting a stale plan.

`Updated Requirement` is a deliberate deferral, not a loophole: the document still
describes intended future work, and merging it in that state is only acceptable because
the new subsection makes the outstanding scope explicit.

Finishing is feature-branch work, not merge-time work: once the implementation, tests, and
validation for a Caravaggio change are complete, the author returns the document to
`Status: Developed` in the same branch — action plan removed, technical details harmonized
to the current-state contract with no delivery history or change markers. Completeness is
judged by done-ness of the work, never by whether the branch has merged; a finished branch
must already read evergreen. The merge gate above is a backstop against accidentally merging
`In Progress` documents, not the step where documents get finished.

### Public Site Browser Compatibility

The public site bundle (`nop/builtin/site.js`, built from `nop/ts/site`) must remain compatible with iOS 12 / Safari 12. It ships as one classic IIFE script loaded by the public layout, so one unsupported parse token disables every public-site interaction.

The compatibility pipeline must include all of these gates:

- A pinned browserslist source in `nop/ts/site`, containing:
  ```text
  iOS >= 12
  Safari >= 12
  ```
- Vite builds the public site as an IIFE with `build.target: 'esnext'` and `build.minify: 'terser'`; bundler lowering is not relied on for the floor.
- `npm run build` runs `vite build`, then `npm run build:legacy`, then the bundle compatibility check.
- `npm run build:legacy` runs Babel CLI over the generated `nop/builtin/site.js` with `nop/ts/site/babel.legacy.config.cjs`, then reruns terser with `ecma=2019`. This lowers Vite's generated wrapper and app code together.
- The Babel legacy config uses `@babel/preset-env` with explicit targets for iOS 12 / Safari 12.
- No runtime ECMAScript or Web API polyfill imports: `fetch`, `AbortController`, collections, and `async`/`await` are native at this floor. Do not reintroduce `core-js`, `regenerator-runtime`, `whatwg-fetch`, or `abortcontroller-polyfill`.
- `nop/ts/site/vite.config.ts` prepends the legacy browser prelude before the public IIFE. The
  prelude defines `globalThis` and a usable `EventTarget` right-hand side before bundle code can
  evaluate framework or helper output.
- `nop/ts/site/scripts/check-site-bundle.mjs` runs `es-check es2019`, scans for unsupported syntax,
  and executes the built `nop/builtin/site.js` in a jsdom smoke scenario with the `EventTarget`
  constructor removed. The smoke must prove core navigation initializes.
- Terser minification so minification does not reintroduce unsupported syntax.
- `eslint-plugin-compat` in `npm run check`, reading the same browserslist target and failing on unsupported runtime APIs.
- A post-build compatibility check against `nop/builtin/site.js` that fails if the shipped bundle contains syntax above the Safari 12 floor.
- The site package uses normal direct dependency upgrades to avoid vulnerable build tooling. It does not use npm overrides to force patched transitive versions.

The source code may use DOM convenience methods such as `replaceWith`, `append`, `prepend`, `before`, and `after` directly; they are native at this floor.

### Login SPA Browser Compatibility

The login SPA (`nop/ts/login`) must remain compatible with iOS 12 / Safari 12. This is a hard
compatibility floor because login is the gateway for public users and admins, and Safari 12 fails
the entire script at parse time when a shipped bundle contains unsupported syntax.

The login SPA is built as a classic browser script. The generated login shell must load it with a
normal `<script src="...">` tag and must not use `type="module"`, dynamic `import()`, or a
module/nomodule split. UX tests must continue to validate the user-visible login behavior and must
not assert implementation details such as whether the active password hasher is WebAssembly or the
asm.js fallback.

The login shell must not depend on an inline executable script to pass runtime config to the SPA.
Runtime config is rendered as an escaped `data-login-config` attribute on `#login-app`, and
`nop/ts/login/src/runtime.ts` parses that mount-node config before falling back to
`window.nopLoginConfig` for test/dev shells. This avoids nonce/CSP/user-agent differences from
making `getRuntimeConfig()` fail before the SPA can mount.

The compatibility pipeline must include all of these gates:

- A pinned browserslist source in `nop/ts/login/package.json`, containing:
  ```text
  iOS >= 12
  Safari >= 12
  ```
- Vite builds the login SPA with `build.target: 'esnext'` and `build.minify: 'terser'`; bundler
  lowering is not relied on for the floor.
- Vite prepends the repo-owned legacy browser prelude before the generated login script. The
  prelude defines `globalThis` and a usable `EventTarget` right-hand side before Svelte/runtime
  code can execute.
- `npm run build` runs `npm run build:vite`, then `npm run build:legacy`, then
  `npm run check:bundle`.
- `npm run build:vite` runs the existing Vite build and continues to honor
  `LOGIN_SPA_OUT_DIR` and `LOGIN_SPA_BASE` from `nop/crates/nop-rt-builtin/build.rs`.
- `npm run build:legacy` runs Babel CLI over the generated login JavaScript files in the active
  output directory using `nop/ts/login/babel.legacy.config.cjs`, then reruns terser with
  `ecma=2019`. The pass lowers Vite/Svelte wrapper code and app code together.
- The Babel legacy config uses `@babel/preset-env` with explicit targets for iOS 12 / Safari 12.
- `npm run check:types` runs `tsc -p tsconfig.json --noEmit`.
- `npm run lint:compat` runs `eslint-plugin-compat` over `src/**/*.ts`, reading the same
  browserslist target and failing on unsupported runtime APIs. Test files are excluded from this
  browser API gate.
- `npm run check:bundle` validates every generated `login*.js` file in the active output directory
  with `es-check es2019`, a banned syntax/API scan, and jsdom runtime smokes that execute the built
  script against a checked rendered-login-shell fixture. The fixture must contain escaped
  `data-login-config` HTML and must be guarded by a `nop-rt-templates` test that renders the real
  MiniJinja login template with the same runtime config. The runtime smoke removes legacy-missing
  browser APIs and asserts that the login shell mounts, that the unavailable-login fallback text is
  absent, and that the email login controls are present.
- `npm run check` runs type checking, compatibility linting, and bundle validation. When the
  active output directory is missing, the bundle validation must build to a temporary or default
  login output before checking.
- The build output remains a versioned builtin directory such as `nop/builtin/login-<hash>/` with
  stable files inside it (`login.js`, `login.css`, font files, and any explicitly copied fallback
  assets).

The final-bundle scan must fail on unsupported syntax or runtime dependencies, including:

- unguarded WebAssembly dependency patterns. Feature-detected WebAssembly use is allowed only in a
  password-hashing adapter that can fall back to asm.js.
- `BigInt`
- hard `EventTarget` constructor dependency
- dynamic `import(`
- ES module `import`/`export` declarations
- optional chaining (`?.`)
- nullish coalescing (`??`)

Runtime API compatibility is separate from syntax compatibility. `fetch`, `AbortController`,
collections, and `async`/`await` are native at this floor and need no polyfills. The login SPA
keeps feature-detected `queueMicrotask`, DOM convenience-method, and `String.prototype.replaceAll`
(compiled Svelte output needs it below Safari 13.1) shims in `src/legacy-polyfills.ts`.

Additional polyfills must be added only when the login SPA actually uses the missing API, and the
reason must be documented in the compatibility lint settings. Prefer baseline DOM APIs such as
`appendChild`, `insertBefore`, and `replaceChild` over adding convenience-method polyfills.

#### Login Password Hashing Fallback

The login SPA must prefer the current WebAssembly `hash-wasm` Argon2id path when WebAssembly is
available. When WebAssembly is unavailable, the password provider must use the standalone
`nop/ts/login/argon2-asm/dist/argon2id.asm.js` artifact as a classic-script fallback.

The fallback integration contract is:

- The asm.js file is generated and validated by the standalone `argon2-asm` enclosure before the
  login SPA imports or copies it.
- The login SPA build copies the final asm.js artifact into the versioned login builtin directory
  with a stable filename such as `argon2id.asm.js`.
- The login shell or login runtime loader loads the fallback only as a classic script, never as an
  ES module.
- The runtime detects WebAssembly support before loading the fallback. Unsupported browsers must
  never attempt to parse or instantiate the WebAssembly path as a hard requirement.
- The provider-facing hashing API must return identical lowercase hex output for WebAssembly and
  asm.js paths for the configured password-login Argon2id parameters.
- Empty-password rejection, salt validation, parameter validation, and error reporting must be
  consistent between the WebAssembly and asm.js paths.

The standalone asm.js artifact remains governed by `docs/iam/password-login.md`. This build
Caravaggio owns only how that validated artifact is incorporated into the login SPA build and
release pipeline.

#### Login Build Script Integration

`nop/crates/nop-rt-builtin/build.rs` is the release embedding authority for login assets. It must
continue to call `npm run build (login)` with `LOGIN_SPA_OUT_DIR` and `LOGIN_SPA_BASE` set to the
versioned builtin directory. That npm build must perform legacy lowering and bundle validation
before `build.rs` embeds assets in release mode.

The login source tracking in `build.rs` must include:

- `nop/ts/login/package.json` and `nop/ts/login/package-lock.json`.
- `nop/ts/login/vite.config.ts`, `svelte.config.js`, `tailwind.config.cjs`,
  `postcss.config.cjs`, `tsconfig.json`, and `index.html`.
- `nop/ts/login/babel.legacy.config.cjs`.
- `nop/ts/login/eslint.config.js`.
- `nop/ts/login/scripts/check-login-bundle.mjs`.
- all files under `nop/ts/login/src/`.
- the validated Argon2 fallback inputs required by the login build:
  `nop/ts/login/argon2-asm/dist/argon2id.asm.js` and
  `nop/ts/login/argon2-asm/argon2id.asm.manifest.json`.

When login dependencies are missing locally, `build.rs` must install them through `npm ci` when
`package-lock.json` exists. Release and CI paths must not fall back to a floating `npm install` for
the login package. A missing or stale login lockfile is a build failure, not an opportunity to
resolve a new graph during release.

### Test Pipeline

The full non-browser release scope is `scripts/run-full-tests.sh`.

It must run:

- Rust formatting, tests, and clippy for every local Rust path crate and the root `nop` package.
- Admin SPA dependency installation, `npm run check`, and `npm run test`.
- Login SPA dependency installation, `npm run argon2-asm:check`, `npm run check`, `npm run test`,
  and `npm run build`.
- Public site dependency installation, `npm run check`, `npm run test`, and `npm run build`.

The slow Argon2 asm.js equivalence suite (`npm run argon2-asm:test`) is not part of regular full
testing. It must run only when the Argon2 asm.js implementation changes: source bridge/wrapper
changes, generator changes, compatibility wrapper changes, vector corpus changes, or generated
artifact changes.

The browser release scope is `scripts/run-playwright.sh`. It installs Playwright dependencies and browser binaries, then runs the E2E project. Public-site and login-SPA compatibility are enforced by the build, lint, and bundle validation pipelines; Playwright and UX tests remain behavior-focused and should not depend on frontend implementation details.

Playwright is not the compatibility authority for Safari 12. Modern Playwright cannot drive legacy iOS Safari, so the release process still requires a physical iOS 12 smoke test for changes touching public-site JavaScript/CSS or login JavaScript/CSS.

### Supply-Chain Controls

Supply-chain risk is controlled by making dependency changes explicit, repeatable, audited, and easy to review.

- Keep lockfiles committed for all package managers that support them: `Cargo.lock` for the Rust release graph and `package-lock.json` for each Node package root.
- Prefer `npm ci` in automation so installs reproduce the lockfile exactly and do not silently upgrade transitive dependencies.
- Review every new dependency for maturity, maintenance status, license fit, platform compatibility, and whether the same outcome can be achieved with existing tooling.
- Keep package lifecycle script execution limited to what the toolchain requires. Where a package root does not need install scripts, prefer `npm ci --ignore-scripts`; where install scripts are required, document the reason.
- Do not use npm overrides, vendored patches, or local edits under `node_modules/` to force
  vulnerable or incompatible transitive dependency versions. Fixes must be normal direct
  dependency upgrades, lockfile refreshes, or dependency replacement/removal.
- The Argon2 asm.js fallback is generated from lockfile-resolved upstream source with a manifest;
  the login build consumes the generated artifact and must not patch upstream package files during
  build.
- Run `cargo audit` from `nop/`.
- Run `npm audit` from `nop/ts/site`, `nop/ts/login`, `nop/ts/admin`, and `tests/playwright`.
- Run `trivy fs .` before release candidates, and run `trivy image <image>` for container release candidates.
- For each finding, identify whether the affected dependency is development-only or present in runtime/release artifacts.
- For each finding, validate whether this repo exercises the vulnerable code path.
- Prefer upgrading to a fixed version. If no fix exists and the vulnerable code path is not used, record the rationale in the audit report and keep monitoring upstream. If no fix exists and the vulnerable code path is used, treat it as a release blocker unless a compensating control is documented and accepted.

### Security Audit Reporting

Each vulnerability report must include:

- Vulnerability identifier.
- Short vulnerability description.
- Impacted dependency and whether it is development-only or runtime.
- Validation of whether NoPressure uses the impacted code path.
- Fix availability.
- Mitigation and upgrade strategy.

Descriptions and proposed actions should be concise: one or two sentences each.

### Local Iteration

- `scripts/crg.sh nop run -- -C ../runtime -F` runs the server with a local runtime root and keeps it in the foreground.
- `scripts/crg.sh nop check` type-checks Rust without linking.
- `cd nop/ts/site && npm run check && npm run test && npm run build` is the focused public-site frontend validation scope.
- `cd nop/ts/login && npm run argon2-asm:check && npm run check && npm run test && npm run build` is the focused login frontend validation scope.
- `cd nop/ts/login && npm run argon2-asm:test` is required only when the Argon2 asm.js
  implementation, generator, compatibility wrapper, vector corpus, or generated artifact changes.
- `scripts/run-full-tests.sh` is the full non-browser release validation scope.
- `scripts/run-playwright.sh` is the browser E2E release validation scope.

### Validation Baseline

- `cd nop/ts/site && npm audit && npm run check && npm run test && npm run build` validates the public-site supply chain, compatibility lint, unit tests, production build, legacy lowering, and ES2019 bundle parse check.
- `cd nop/ts/login && npm audit && npm run argon2-asm:check && npm run check && npm run test && npm run build` validates the login SPA supply chain, Argon2 fallback artifact integrity/static compatibility, compatibility lint, unit tests, production build, legacy lowering, and ES2019 bundle parse check.
- `scripts/run-full-tests.sh` validates Rust formatting, tests, clippy, admin SPA checks/tests, login SPA Argon2 integrity/static checks/tests/build, and public-site checks/tests/build.
- `CARGO_INCREMENTAL=0 scripts/crg.sh nop build` validates the root debug build and all local Rust path dependencies.
- `CARGO_INCREMENTAL=0 scripts/crg.sh nop build --release` validates the optimized release binary with embedded builtin assets.

### Release Checklist

1. Ensure runtime configuration files exist, either by copying `examples/config.yaml.example` and `examples/users.yaml.example` into the runtime root or by relying on auto-bootstrap defaults.
2. Run focused checks for the touched area.
3. Run `scripts/run-full-tests.sh`.
4. Run supply-chain audits: `cargo audit`, `npm audit` in each Node package root, and `trivy fs .`.
5. Run `scripts/run-playwright.sh` when UI or browser-facing behavior is touched.
6. For public-site or login JavaScript/CSS changes, complete a physical iOS 12 smoke test.
7. Build the release binary with `scripts/crg.sh nop build --release`.
8. For container delivery, build through `examples/docker/` or package the prebuilt binary through `examples/docker-slim/`, then scan the resulting image with `trivy image <image>`.
9. Publish the resulting binary or image through the release pipeline only after audit findings and test failures are resolved or explicitly accepted.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
