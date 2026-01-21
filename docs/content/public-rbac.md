# Public Content RBAC

Status: Developed

## Objectives

- Enforce role-based access control for public content without a separate database.
- Define tag-driven access rules with predictable outcomes.
- Keep navigation and listings consistent with access rules.

## Technical Details

### Canonical Scope

This document defines the public RBAC model for flat, ID-based storage with optional aliases. Roles are assigned to
tags only. Content objects do not store roles directly. Role storage and lifecycle are defined in
`docs/content/role-management.md`.

### Tag Role Model

- Each tag can define `roles` and an optional `access_rule`.
- `access_rule` values:
  - `intersect` (default when unspecified)
  - `union`
- Tags without roles do not participate in role resolution when at least one tag contributes roles.
- If all tags on an object contribute zero roles, the object is public.

### Precedence Rules

When evaluating a content object with one or more tags:

1. If any tag explicitly sets `access_rule = intersect`, use intersect across the full tag set.
2. Else if at least one tag explicitly sets `access_rule = union`, use union across the full tag set.
3. Else default to intersect across the full tag set.

### Role Resolution

- **Union**: resolved roles are the union of all roles across the object's tags.
- **Intersect**: resolved roles are the intersection of all roles across the object's tags.

### Access Outcomes

- If an object has no tags, it is public.
- If at least one tag contributes roles and role resolution yields an empty role set, the object is inaccessible to all users.
- If role resolution yields roles, access is granted when the user has at least one of those roles.
- Anonymous users without access are redirected to `/login?return_path=...`.
- Authenticated users without access receive a 404.

### Cache Integration

- The in-memory cache stores tag membership and resolved access roles per object.
- `PageMetaCache::user_has_access` uses the resolved role set rather than file-level roles.
- Tag updates must trigger recomputation for all affected objects.

### Examples

**Union precedence**

Tags:
- `news` roles: `editor, author` access_rule: `union`
- `public` roles: (none) access_rule: (none)

Result: union applies; resolved roles are `editor, author`.

**Intersect precedence**

Tags:
- `finance` roles: `finance` access_rule: `intersect`
- `confidential` roles: `legal` access_rule: (none)

Result: intersect applies; resolved roles are the intersection of `finance` and `legal` (empty). The object is inaccessible.

**No tags**

- No tags assigned.
- Object is public.

**Tags without roles**

- `public` roles: (none) access_rule: (none)

Result: resolved roles are empty because no tags contribute roles. The object is public.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
