// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { writable } from "svelte/store";
import { setBrowserTimeout } from "../services/browser";

export type NotificationTone = "info" | "success" | "error";

export type NotificationItem = {
  id: number;
  message: string;
  tone: NotificationTone;
};

export const notifications = writable<NotificationItem[]>([]);
let nextId = 1;

function logNotification(message: string, tone: NotificationTone): void {
  const label = `[admin toast:${tone}]`;
  if (tone === "error") {
    console.error(label, message);
    return;
  }
  if (tone === "success") {
    console.info(label, message);
    return;
  }
  console.info(label, message);
}

export function pushNotification(
  message: string,
  tone: NotificationTone = "info",
  durationMs = 5000,
): void {
  const id = nextId++;
  logNotification(message, tone);
  notifications.update((items) => [...items, { id, message, tone }]);
  if (durationMs > 0) {
    setBrowserTimeout(() => removeNotification(id), durationMs);
  }
}

export function removeNotification(id: number): void {
  notifications.update((items) => items.filter((item) => item.id !== id));
}
