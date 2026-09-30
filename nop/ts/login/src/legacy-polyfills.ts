// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

// ECMAScript and Web API polyfill imports were removed with the iOS 12 floor:
// fetch, AbortController, queueMicrotask (12.1+), and all core-js modules used
// here are native. The feature-detected queueMicrotask and DOM
// convenience-method shims below stay as belt-and-braces for older 12.x WebKit.

export {};

declare global {
  interface Window {
    queueMicrotask?: (callback: () => void) => void;
  }
}

if (typeof window.queueMicrotask !== 'function') {
  window.queueMicrotask = (callback: () => void) => {
    Promise.resolve()
      .then(callback)
      .catch((err) => {
        setTimeout(() => {
          throw err;
        }, 0);
      });
  };
}

// String.prototype.replaceAll is Safari 13.1+. Compiled Svelte output uses it,
// so a feature-detected fallback stays until the floor moves past Safari 13.
// (Accessed indirectly: the login TS lib predates the es2021 typings.)
const stringPrototype = String.prototype as unknown as Record<string, unknown>;
if (typeof stringPrototype['replaceAll'] !== 'function') {
  Object.defineProperty(String.prototype, 'replaceAll', {
    configurable: true,
    writable: true,
    value: function (this: string, search: string | RegExp, replacement: string): string {
      const subject = String(this);
      if (typeof search === 'string') {
        return subject.split(search).join(replacement);
      }
      const flags = search.global ? search.flags : `${search.flags}g`;
      return subject.replace(new RegExp(search.source, flags), replacement);
    }
  });
}

function toNode(value: Node | string): Node {
  return typeof value === 'string' ? document.createTextNode(value) : value;
}

function defineMethod<T extends object>(
  prototype: T | undefined,
  name: string,
  value: (...nodes: Array<Node | string>) => void
) {
  if (!prototype || typeof (prototype as Record<string, unknown>)[name] === 'function') {
    return;
  }
  Object.defineProperty(prototype, name, {
    configurable: true,
    writable: true,
    value
  });
}

function childBefore(this: ChildNode, ...nodes: Array<Node | string>) {
  const parent = this.parentNode;
  if (!parent) {
    return;
  }
  for (const node of nodes) {
    parent.insertBefore(toNode(node), this);
  }
}

function childAfter(this: ChildNode, ...nodes: Array<Node | string>) {
  const parent = this.parentNode;
  if (!parent) {
    return;
  }
  let reference = this.nextSibling;
  for (const node of nodes) {
    parent.insertBefore(toNode(node), reference);
  }
}

function childRemove(this: ChildNode) {
  const parent = this.parentNode;
  if (parent) {
    parent.removeChild(this);
  }
}

function parentAppend(this: ParentNode, ...nodes: Array<Node | string>) {
  for (const node of nodes) {
    this.appendChild(toNode(node));
  }
}

for (const prototype of [
  window.Element?.prototype,
  window.CharacterData?.prototype,
  window.DocumentType?.prototype
]) {
  defineMethod(prototype, 'before', childBefore);
  defineMethod(prototype, 'after', childAfter);
  defineMethod(prototype, 'remove', childRemove);
}

for (const prototype of [
  window.Document?.prototype,
  window.DocumentFragment?.prototype,
  window.Element?.prototype
]) {
  defineMethod(prototype, 'append', parentAppend);
}
