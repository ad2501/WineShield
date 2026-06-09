#!/usr/bin/env bash
# ------------------------------------------------------------------
# build_deb.sh — Build WineShield .deb package
#
# Usage:
#   ./installer/build_deb.sh
#
# This script builds a Debian binary package from the current source
# tree.  It is designed to run on Ubuntu 22.04 LTS.
#
# The .deb is NOT stored in git — run this script to generate it.
# The generated .deb lands in installer/ by default.
# ------------------------------------------------------------------
set -euo pipefail

cd "$(dirname "$0")/.."
PROJECT_ROOT="$(pwd)"
PKG_NAME="wineshield"
VERSION="$(cat VERSION 2>/dev/null || echo '1.0.0-alpha')"
BUILD_DIR="/tmp/${PKG_NAME}-deb-build"
DEST_DIR="${PROJECT_ROOT}/installer"

# ---- Clean previous build ----
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}/DEBIAN"
mkdir -p "${BUILD_DIR}/usr/local/bin"
mkdir -p "${BUILD_DIR}/usr/lib/wineshield/core"
mkdir -p "${BUILD_DIR}/usr/lib/wineshield/dashboard"
mkdir -p "${BUILD_DIR}/usr/lib/wineshield/config"
mkdir -p "${BUILD_DIR}/usr/lib/wineshield/scripts"
mkdir -p "${BUILD_DIR}/etc/wineshield/apparmor"
mkdir -p "${BUILD_DIR}/etc/systemd/system"
mkdir -p "${BUILD_DIR}/usr/share/applications"

# ---- Copy core modules ----
cp -r core/*.py "${BUILD_DIR}/usr/lib/wineshield/core/"
cp -r core/*.c "${BUILD_DIR}/usr/lib/wineshield/core/"
cp core/Makefile "${BUILD_DIR}/usr/lib/wineshield/core/"

# ---- Copy dashboard ----
cp -r dashboard/*.py "${BUILD_DIR}/usr/lib/wineshield/dashboard/"
cp -r dashboard/templates "${BUILD_DIR}/usr/lib/wineshield/dashboard/"
cp -r dashboard/static "${BUILD_DIR}/usr/lib/wineshield/dashboard/"

# ---- Copy config ----
cp config/*.json "${BUILD_DIR}/etc/wineshield/"
cp config/wine_syscall_whitelist.conf "${BUILD_DIR}/etc/wineshield/"
cp config/apparmor/* "${BUILD_DIR}/etc/wineshield/apparmor/"

# ---- Copy scripts ----
cp scripts/*.sh scripts/*.py "${BUILD_DIR}/usr/lib/wineshield/scripts/" 2>/dev/null || true

# ---- Install launcher as /usr/local/bin/wineshield ----
cat > "${BUILD_DIR}/usr/local/bin/wineshield" << 'LAUNCHER'
#!/usr/bin/env bash
exec /usr/bin/python3 /usr/lib/wineshield/core/launcher.py "$@"
LAUNCHER
chmod +x "${BUILD_DIR}/usr/local/bin/wineshield"

# ---- Systemd service ----
cp installer/systemd/wineshield.service "${BUILD_DIR}/etc/systemd/system/"
cp installer/systemd/wineshield.socket "${BUILD_DIR}/etc/systemd/system/"

# ---- Build debian control file ----
cat > "${BUILD_DIR}/DEBIAN/control" << CONTROL
Package: ${PKG_NAME}
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: amd64
Depends: python3 (>= 3.10), python3-flask, python3-flask-socketio, python3-psutil, libseccomp-dev, xephyr, apparmor-utils
Maintainer: Ahmed <ahmad0782697665@gmail.com>
Description: Multi-layer security framework for Wine
 WineShield provides 5 layers of protection for running
 Windows applications via Wine on Linux, including syscall
 filtering, filesystem isolation, network control, behavior
 analysis, and X11 display isolation.
CONTROL

# ---- Post-installation script ----
cat > "${BUILD_DIR}/DEBIAN/postinst" << 'POSTINST'
#!/bin/sh
set -e
echo "[WineShield] Loading AppArmor profiles..."
for profile in /etc/wineshield/apparmor/*; do
    if [ -f "$profile" ]; then
        apparmor_parser -r "$profile" 2>/dev/null || true
    fi
done
echo "[WineShield] Building seccomp module..."
make -C /usr/lib/wineshield/core clean all 2>/dev/null || true
echo "[WineShield] Installation complete."
POSTINST
chmod +x "${BUILD_DIR}/DEBIAN/postinst"

# ---- Build the .deb ----
fakeroot dpkg-deb --build "${BUILD_DIR}" "${DEST_DIR}/${PKG_NAME}_${VERSION}_amd64.deb"
echo "✅ Package built: ${DEST_DIR}/${PKG_NAME}_${VERSION}_amd64.deb"
