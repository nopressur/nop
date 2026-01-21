// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { writable } from "svelte/store";
import { getAdminRuntimeConfig } from "../config/runtime";
import {
  addWindowListener,
  getLocationPathname,
  getLocationSearch,
  getWindow,
  pushHistoryState,
  replaceHistoryState,
} from "../services/browser";

export type RouteState = {
  path: string;
  query: URLSearchParams;
  fullPath: string;
};

const config = getAdminRuntimeConfig();
const basePath = config.adminPath.replace(/\/$/, "");

function parseLocation(): RouteState {
  const pathname = getLocationPathname();
  const search = getLocationSearch();
  const fullPath = pathname + search;
  let path = pathname;
  if (path.startsWith(basePath)) {
    path = path.slice(basePath.length) || "/";
  }
  return {
    path,
    query: new URLSearchParams(search),
    fullPath
  };
}

export const route = writable<RouteState>(parseLocation());

export function navigate(path: string, replace = false): void {
  if (!getWindow()) {
    return;
  }
  const nextPath = toAdminPath(path);
  if (replace) {
    replaceHistoryState(nextPath);
  } else {
    pushHistoryState(nextPath);
  }
  route.set(parseLocation());
}

export function isActiveRoute(path: string, current: string): boolean {
  if (path === "/") {
    return current === "/";
  }
  return current.startsWith(path);
}

function toAdminPath(path: string): string {
  if (path.startsWith(basePath)) {
    return path;
  }
  if (path.startsWith("/")) {
    return `${basePath}${path}`;
  }
  return `${basePath}/${path}`;
}

addWindowListener("popstate", () => {
  route.set(parseLocation());
});
