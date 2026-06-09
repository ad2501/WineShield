#!/usr/bin/env bash
# Validate or load WineShield AppArmor profiles.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE_DIR="${WINESHIELD_APPARMOR_DIR:-$ROOT/config/apparmor}"
MODE="${1:---check}"

if ! command -v apparmor_parser >/dev/null 2>&1; then
  echo "apparmor_parser not found" >&2
  exit 127
fi

profiles=(
  "$PROFILE_DIR/wineshield.wine"
  "$PROFILE_DIR/wineshield.wineserver"
  "$PROFILE_DIR/wineshield.framework"
  "$PROFILE_DIR/wine.profile"
  "$PROFILE_DIR/wineserver.profile"
  "$PROFILE_DIR/wineshield.profile"
)

case "$MODE" in
  --check)
    for profile in "${profiles[@]}"; do
      echo "checking $profile"
      apparmor_parser -Q -K "$profile"
    done
    ;;
  --load)
    for profile in "${profiles[@]}"; do
      echo "loading $profile"
      sudo apparmor_parser -r -W "$profile"
    done
    ;;
  *)
    echo "Usage: $0 [--check|--load]" >&2
    exit 2
    ;;
esac
