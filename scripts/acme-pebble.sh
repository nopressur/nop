#!/usr/bin/env bash
# This file is part of the product NoPressure.
# SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
# SPDX-License-Identifier: AGPL-3.0-or-later
# The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PEBBLE_DIR="$ROOT_DIR/scripts/acme-pebble"

usage() {
  cat <<'EOF'
Usage: scripts/acme-pebble.sh [start|stop|status]

Starts a local Pebble + challtestsrv stack for ACME tests.
EOF
}

ensure_layout() {
  mkdir -p "$PEBBLE_DIR"
  if [[ ! -f "$PEBBLE_DIR/docker-compose.yaml" ]]; then
    cat <<'YAML' > "$PEBBLE_DIR/docker-compose.yaml"
services:
  pebble:
    image: us-central1-docker.pkg.dev/krantz-dev-default/pebble/pebble:latest
    command: pebble -config /pebble-config.json -strict -dnsserver 10.30.50.3:8053
    ports:
      - "14000:14000"
      - "15000:15000"
    volumes:
      - ./pebble-config.json:/pebble-config.json
    networks:
      acme:
        ipv4_address: 10.30.50.2
  challtestsrv:
    image: us-central1-docker.pkg.dev/krantz-dev-default/pebble/pebble-challtestsrv:latest
    command: pebble-challtestsrv -defaultIPv6 "" -defaultIPv4 10.30.50.3
    ports:
      - "8055:8055"
    networks:
      acme:
        ipv4_address: 10.30.50.3
networks:
  acme:
    driver: bridge
    ipam:
      driver: default
      config:
        - subnet: 10.30.50.0/24
YAML
  fi

  if [[ ! -f "$PEBBLE_DIR/pebble-config.json" ]]; then
    cat <<'JSON' > "$PEBBLE_DIR/pebble-config.json"
{
  "pebble": {
    "listenAddress": "0.0.0.0:14000",
    "managementListenAddress": "0.0.0.0:15000",
    "certificate": "test/certs/localhost/cert.pem",
    "privateKey": "test/certs/localhost/key.pem",
    "httpPort": 5002,
    "tlsPort": 5003,
    "ocspResponderURL": "",
    "externalAccountBindingRequired": false,
    "externalAccountMACKeys": {
      "V6iRR0p3": "zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W"
    },
    "domainBlocklist": ["blocked-domain.example"]
  }
}
JSON
  fi
}

if [[ $# -ne 1 ]]; then
  usage
  exit 1
fi

command="$1"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker not available." >&2
  exit 1
fi

ensure_layout

case "$command" in
  start)
    docker compose -f "$PEBBLE_DIR/docker-compose.yaml" up -d
    ;;
  stop)
    docker compose -f "$PEBBLE_DIR/docker-compose.yaml" down
    ;;
  status)
    docker compose -f "$PEBBLE_DIR/docker-compose.yaml" ps
    ;;
  *)
    usage
    exit 1
    ;;
esac
