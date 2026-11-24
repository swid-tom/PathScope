#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "$0")"

if [[ -d config.yaml ]]; then
  printf '%s\n' "Error: config.yaml is a directory. Remove or rename it, then rerun this script." >&2
  exit 1
fi

if [[ ! -e config.yaml ]]; then
  cp config.example.yaml config.yaml
  printf '%s\n' "Created config.yaml from config.example.yaml."
fi

exec docker compose "$@"
