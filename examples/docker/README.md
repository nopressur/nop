# Docker Setup for NoPressure

This directory contains the Docker configuration for running the NoPressure Rust Actix web app.

## Directory Structure

- `/app` - Working directory inside the container where the app binary runs
- `/data` - Mounted runtime root with `config.yaml`, `users.yaml`, `content/`, `themes/`, and `state/`

## Files

- `Dockerfile` - Builds the Rust app and sets up the runtime environment
- `docker-compose.yaml` - Orchestrates the container, mounts volumes, and exposes the app port

## Usage

### 1. Build the Docker Image

From the `examples/docker` directory (the compose file builds using the repo root as context):

```sh
docker-compose build
```

### 2. Run the App

```sh
docker-compose up
```

The app will be available at [http://localhost:5466](http://localhost:5466).

### 3. Volume

- `../data` on the host is mounted to `/data` in the container

Create `../data` (relative to this directory) and place `config.yaml`, `users.yaml`, `content/`, `themes/`, and `state/` inside it so the app can run with `-C /data`.

## Notes

- The app always runs on port 5466.
- The build context is the repo root and uses `examples/docker/Dockerfile`.
- The container runs as an unprivileged `nop` user by default.
- Do **not** copy files from `/inspiration` into these directories.
- For development, you can rebuild and restart the container as needed.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
