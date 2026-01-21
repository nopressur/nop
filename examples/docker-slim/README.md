# Docker-Slim Setup for NoPressure

This directory provides a minimal Docker setup for running the NoPressure Rust Actix web app, assuming the `nop` executable is already present in this directory.

## Directory Structure

- `/app` - Working directory inside the container where the app binary runs
- `/data` - Mounted runtime root with `config.yaml`, `users.yaml`, `content/`, `themes/`, and `state/`

## Files

- `Dockerfile` - Sets up a minimal runtime environment and runs the pre-built `nop` executable
- `docker-compose.yaml` - Orchestrates the container, mounts volumes, and exposes the app port

## Usage

### 1. Prepare the Directory

Place the pre-built `nop` executable in this directory (`examples/docker-slim/`).

### 2. Build the Docker Image

From the `examples/docker-slim` directory:

```sh
docker-compose build
```

### 3. Run the App

```sh
docker-compose up
```

The app will be available at [http://localhost:5466](http://localhost:5466).

### 4. Volume

- `../data` on the host is mounted to `/data` in the container

Create `../data` (relative to this directory) and place `config.yaml`, `users.yaml`, `content/`, `themes/`, and `state/` inside it so the app can run with `-C /data`.

## Notes

- The app always runs on port 5466.
- This setup does **not** build the `nop` binary; it must be present in this directory before building the image.
- Do **not** copy files from `/inspiration` into these directories.
- For development, you can rebuild and restart the container as needed.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
