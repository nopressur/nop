// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { getAdminCspNonce } from "../config/runtime";
import { getDocument, getWindow } from "./browser";

type AceWindow = Window & {
  ace?: AceAjax.Ace & {
    config?: {
      set: (key: string, value: string) => void;
    };
  };
};

let acePromise: Promise<void> | null = null;
let styleNoncePatched = false;

function applyStyleNonce(): void {
  if (styleNoncePatched) {
    return;
  }
  const nonce = getAdminCspNonce();
  if (!nonce) {
    return;
  }

  const doc = getDocument();
  if (!doc) {
    return;
  }
  const originalCreateElement = doc.createElement.bind(doc);
  const originalCreateElementNS = doc.createElementNS.bind(doc);

  doc.createElement = ((tagName: string, options?: ElementCreationOptions) => {
    const element = originalCreateElement(tagName, options);
    if (tagName.toLowerCase() === "style") {
      element.setAttribute("nonce", nonce);
    }
    return element;
  }) as typeof doc.createElement;

  doc.createElementNS = ((
    namespaceURI: string,
    qualifiedName: string,
    options?: ElementCreationOptions
  ) => {
    const element = originalCreateElementNS(namespaceURI, qualifiedName, options);
    if (qualifiedName.toLowerCase() === "style") {
      element.setAttribute("nonce", nonce);
    }
    return element;
  }) as typeof doc.createElementNS;

  styleNoncePatched = true;
}

export async function loadAce(): Promise<void> {
  const win = getWindow() as AceWindow | null;
  if (!win) {
    return;
  }
  if (win.ace) {
    applyStyleNonce();
    return;
  }
  if (!acePromise) {
    acePromise = new Promise((resolve, reject) => {
      applyStyleNonce();
      const doc = getDocument();
      if (!doc) {
        reject(new Error("Document not available"));
        return;
      }
      const script = doc.createElement("script");
      script.src = "/builtin/ace.js";
      script.async = true;
      script.onload = () => {
        const aceWindow = getWindow() as AceWindow | null;
        if (!aceWindow) {
          reject(new Error("Window not available"));
          return;
        }
        if (aceWindow.ace?.config) {
          aceWindow.ace.config.set("basePath", "/builtin");
        }
        resolve();
      };
      script.onerror = () => reject(new Error("Failed to load Ace"));
      doc.head.appendChild(script);
    });
  }
  return acePromise;
}
