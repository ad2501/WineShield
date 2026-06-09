#!/usr/bin/env bash
# Install WineShield from a source checkout.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${PREFIX:-/usr/local}"
LIBDIR="${LIBDIR:-/usr/local/lib/wineshield}"

install -d "$LIBDIR" "$PREFIX/bin"
cp -a "$ROOT/core" "$ROOT/dashboard" "$ROOT/config" "$ROOT/scripts" "$LIBDIR/"

cat > "$PREFIX/bin/wineshield" <<LAUNCHER
#!/usr/bin/env bash
exec /usr/bin/python3 "$LIBDIR/core/launcher.py" "\$@"
LAUNCHER
chmod +x "$PREFIX/bin/wineshield"

echo "WineShield installed under $LIBDIR"
