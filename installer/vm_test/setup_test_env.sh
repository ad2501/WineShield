#!/usr/bin/env bash
# Prepare a lightweight WineShield VM/test environment.
set -euo pipefail

if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update
  sudo apt-get install -y gcc make python3 python3-pip apparmor-utils wine xephyr
else
  echo "apt-get not found; install gcc, make, python3, apparmor-utils, wine, and xephyr manually" >&2
fi
