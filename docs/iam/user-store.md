# IAM User Store

Status: Developed

This document is the authoritative description of how user identities are stored, cached, and
persisted. It also defines scalability and performance requirements for user mutations.

## Objectives

- Document the users.yaml schema and how it maps to in-memory user records.
- Define persistence guarantees, atomic write behavior, and error handling.
- Describe the mutation pipeline, including ordering, batching, and backpressure.
- Ensure the design scales for frequent mutations without unbounded memory growth.

## Technical Details

### Current State (Developed Behavior)

#### Storage Format

- `users.yaml` is a YAML map keyed by user email (normalized internally to lowercase).
- Each entry maps to `YamlUser`:
  - `name` (string)
  - `password`:
    - provider block (`front_end_salt`, `back_end_salt`, `stored_hash`), or
    - legacy hash string
  - `roles` (array of strings)
  - `password_version` (u32; optional in YAML, defaulted to 1)
- In-memory records are stored as `User` with optional `PasswordProviderBlock` and
  `legacy_password_hash` fields.

#### Load and Migration

- `FileUserStore::load` reads `users.yaml`, parses it, and converts YAML into `UsersData`.
- If any users are missing `password_version`, the loader assigns version 1 for all users and
  persists the updated file (with a warning).
- Errors in reading or parsing bubble as `IamError::FileError` or `IamError::ParseError`.

#### Persistence

- `FileUserStore::save` serializes the in-memory map to YAML and writes via:
  - temp file creation next to `users.yaml`
  - permission copying from the existing file (unix)
  - `sync_all` on the temp file
  - atomic rename to replace `users.yaml`
  - directory sync on unix
- `FileUserStore::save` uses synchronous `std::fs` IO; `FileUserStore::save_async` uses `tokio::fs`
  and is the path used by the mutation worker.

#### In-Memory Model

- IAM stores users in `Arc<RwLock<UsersData>>`.
- Reads acquire a read lock and clone user records as needed.
- `IamService::get_user` returns users regardless of role membership; roles gate authorization
  elsewhere.
- `UserServices` calls `IamService` for lookup and validation.

#### Mutation Pipeline

- Mutations are sent to a background task over a bounded channel (depth 128).
- The worker drains queued requests into a batch (up to 64):
  1. Capture a snapshot under a read lock.
  2. Apply mutations to the snapshot in order, without holding a lock.
  3. Persist the snapshot via async IO.
  4. Swap the in-memory map to the snapshot on success.
- If persistence fails, the in-memory map is not mutated and the batch reports errors.

#### Performance Characteristics (Current)

- Reads are fast and in-memory.
- Writes amortize disk IO by batching and persisting once per batch.
- The bounded queue applies backpressure under load to avoid unbounded memory growth.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
