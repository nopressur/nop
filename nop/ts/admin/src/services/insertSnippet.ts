// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import type { ContentListItem } from "./content";

export type InsertMode = "link" | "image" | "video" | "hero";

export type HeroOptions = {
  title: string;
  subtitle: string;
  lightify: boolean;
  darkify: boolean;
  lightShadow: boolean;
  darkShadow: boolean;
};

export type InsertEventDetail =
  | { item: ContentListItem; mode: "link" | "image" | "video" }
  | { item: ContentListItem; mode: "hero"; hero: HeroOptions };

export function defaultHeroOptions(): HeroOptions {
  return {
    title: "",
    subtitle: "",
    lightify: false,
    darkify: false,
    lightShadow: false,
    darkShadow: false,
  };
}

/// Build the markdown / shortcode snippet inserted at the editor cursor when
/// the user picks an item in the Insert content modal. Quoted shortcode
/// attribute values use `JSON.stringify` so `"` and `\` are escaped per the
/// shortcode parser's quoted-value grammar (`\"` for literal `"`, `\\` for
/// literal `\`).
export function buildModalInsertSnippet(
  item: ContentListItem,
  mode: InsertMode,
  hero?: HeroOptions,
): string {
  const displayText = item.title?.trim() || item.alias || item.id;
  const aliasPath = item.alias ? `/${item.alias}` : `/id/${item.id}`;

  if (mode === "image") {
    return `![${displayText}](${aliasPath})`;
  }
  if (mode === "video") {
    return `((video src=${JSON.stringify(aliasPath)}))`;
  }
  if (mode === "hero") {
    const opts = hero ?? defaultHeroOptions();
    const parts: string[] = [`src=${JSON.stringify(aliasPath)}`];
    if (opts.title) parts.push(`title=${JSON.stringify(opts.title)}`);
    if (opts.subtitle) parts.push(`subtitle=${JSON.stringify(opts.subtitle)}`);
    if (opts.lightify) parts.push("lightify");
    if (opts.darkify) parts.push("darkify");
    if (opts.lightShadow) parts.push("light-shadow");
    if (opts.darkShadow) parts.push("dark-shadow");
    return `((hero-img ${parts.join(" ")}))`;
  }
  return `[${displayText}](${aliasPath})`;
}
