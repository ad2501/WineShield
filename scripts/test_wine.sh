#!/usr/bin/env bash
# Smoke-test Wine availability for WineShield.
set -euo pipefail
if ! command -v wine >/dev/null 2>&1; then
  echo "wine not installed; skipping Wine smoke test" >&2
  exit 77
fi
wine --version
