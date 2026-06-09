#!/usr/bin/env bash
#
# WineShield — Ubuntu 22.04 Installer
# =====================================
# Installs all dependencies, builds the C module, sets up directories,
# configures AppArmor profiles, creates a system-wide command, and
# optionally installs a systemd user service for the dashboard.
#
# Usage:
#   sudo ./install.sh
#
# To skip optional steps (non-fatal warnings printed):
#   sudo ./install.sh   # everything attempted
#
# Exit codes:
#   0 — success
#   1 — missing apt or pip dependency installation failed
#   2 — C module build failure
#   3 — directory setup or symlink/copy failure
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Color helpers (ANSI)
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()      { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; }

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"

# Installation target (will be /opt/wineshield or a symlink)
INSTALL_DIR="/opt/wineshield"

# User data directory (under the calling user's home — uses SUDO_USER if available)
if [[ -n "${SUDO_USER:-}" ]]; then
    REAL_USER="$SUDO_USER"
    REAL_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
else
    REAL_USER="${USER:-$(whoami)}"
    REAL_HOME="$HOME"
fi
WINESHIELD_HOME="${REAL_HOME}/.wineshield"

# ---------------------------------------------------------------------------
# Stage 1 — Dependency Installation
# ---------------------------------------------------------------------------
section_apt_deps() {
    info "Updating apt package lists..."
    apt-get update -qq || {
        error "apt-get update failed. Check your network / package sources."
        return 1
    }
    ok "apt package lists updated."

    local APT_PKGS=(
        python3
        python3-pip
        python3-venv
        gcc
        make
        libseccomp-dev
        xserver-xephyr
        apparmor-utils
        xvfb
    )

    info "Installing APT packages: ${APT_PKGS[*]}..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${APT_PKGS[@]}" || {
        error "Failed to install one or more APT packages."
        return 1
    }
    ok "APT packages installed."
}

section_pip_deps() {
    local PIP_PKGS=(
        flask
        flask-socketio
        psutil
        python-socketio
        eventlet
    )

    info "Installing pip packages: ${PIP_PKGS[*]}..."
    pip3 install --quiet --break-system-packages "${PIP_PKGS[@]}" 2>/dev/null \
        || pip3 install --quiet "${PIP_PKGS[@]}" || {
        error "Failed to install pip packages."
        return 1
    }
    ok "pip packages installed."
}

# ---------------------------------------------------------------------------
# Stage 2 — Build the C Module
# ---------------------------------------------------------------------------
section_build_core() {
    info "Building C seccomp module in core/..."
    pushd "$PROJECT_ROOT/core" >/dev/null

    make -s clean all 2>&1 || {
        popd >/dev/null
        error "C module build failed. Check core/syscall_monitor.c and core/Makefile."
        return 2
    }

    popd >/dev/null

    if [[ -x "$PROJECT_ROOT/core/syscall_monitor" ]]; then
        ok "C module built successfully: core/syscall_monitor"
    else
        error "core/syscall_monitor binary is missing or not executable after build."
        return 2
    fi
}

# ---------------------------------------------------------------------------
# Stage 3 — Directory Structure Setup
# ---------------------------------------------------------------------------
section_directories() {
    info "Creating ~/.wineshield/ directory structure..."

    mkdir -p "$WINESHIELD_HOME/sandbox"
    mkdir -p "$WINESHIELD_HOME/logs"
    mkdir -p "$WINESHIELD_HOME/dashboard"

    # Remove stale symlink if it exists, then recreate
    if [[ -L "$WINESHIELD_HOME/profiles" ]]; then
        rm "$WINESHIELD_HOME/profiles"
    elif [[ -d "$WINESHIELD_HOME/profiles" ]]; then
        rm -rf "$WINESHIELD_HOME/profiles"
    fi

    if [[ -d "$PROJECT_ROOT/config/apparmor" ]]; then
        ln -sf "$PROJECT_ROOT/config/apparmor" "$WINESHIELD_HOME/profiles"
        ok "Symlinked profiles -> config/apparmor/"
    else
        mkdir -p "$WINESHIELD_HOME/profiles"
        warn "config/apparmor/ not found; created empty profiles/ directory."
    fi

    ok "Directory structure set up at $WINESHIELD_HOME"
}

# ---------------------------------------------------------------------------
# Stage 4 — Python Virtual Environment (optional)
# ---------------------------------------------------------------------------
section_venv() {
    # Only create a venv if not already inside one.
    if [[ -z "${VIRTUAL_ENV:-}" ]]; then
        local VENV_DIR="$WINESHIELD_HOME/venv"
        if [[ ! -d "$VENV_DIR" ]]; then
            info "Creating Python virtual environment at $VENV_DIR..."
            python3 -m venv "$VENV_DIR" || {
                warn "Failed to create virtual environment; skipping."
                return 0
            }
            # Install required packages into the venv as well
            "$VENV_DIR/bin/pip" install --quiet flask flask-socketio psutil python-socketio eventlet \
                || warn "pip install inside venv had issues (non-fatal)."
            ok "Virtual environment created at $VENV_DIR"
            info "Activate with: source $VENV_DIR/bin/activate"
        else
            ok "Virtual environment already exists at $VENV_DIR"
        fi
    else
        ok "Already inside a virtual environment ($VIRTUAL_ENV); skipping venv creation."
    fi
}

# ---------------------------------------------------------------------------
# Stage 5 — AppArmor Profile Installation
# ---------------------------------------------------------------------------
section_apparmor() {
    if ! command -v apparmor_parser &>/dev/null; then
        warn "apparmor_parser not found. AppArmor profiles NOT installed."
        warn "This is normal if the AppArmor kernel module is disabled (e.g. in a container, WSL, or VM without LSM)."
        return 0
    fi

    local AA_SRC="$PROJECT_ROOT/config/apparmor"
    if [[ ! -d "$AA_SRC" ]]; then
        warn "AppArmor profiles directory ($AA_SRC) not found; skipping."
        return 0
    fi

    local AA_DEST="/etc/apparmor.d"
    if [[ ! -d "$AA_DEST" ]]; then
        warn "$AA_DEST does not exist; skipping AppArmor installation."
        return 0
    fi

    info "Installing AppArmor profiles from $AA_SRC to $AA_DEST..."

    local profile
    local installed_count=0
    for profile in "$AA_SRC"/*; do
        [[ -f "$profile" ]] || continue
        local fname
        fname="$(basename "$profile")"
        cp "$profile" "$AA_DEST/$fname" || {
            warn "Failed to copy $fname to $AA_DEST; skipping."
            continue
        }
        if apparmor_parser -r -W "$AA_DEST/$fname" 2>/dev/null; then
            ok "  Loaded AppArmor profile: $fname"
            ((installed_count++))
        else
            warn "  Failed to parse/load $fname (may need kernel support)."
        fi
    done

    if [[ $installed_count -gt 0 ]]; then
        ok "$installed_count AppArmor profile(s) installed."
    else
        warn "No AppArmor profiles were loaded."
    fi
}

# ---------------------------------------------------------------------------
# Stage 6 — System-wide Command
# ---------------------------------------------------------------------------
section_system_command() {
    info "Installing system-wide command at /usr/local/bin/wineshield..."

    # First, ensure the project is available at /opt/wineshield/
    if [[ ! -e "$INSTALL_DIR" ]]; then
        info "Creating symlink: $INSTALL_DIR -> $PROJECT_ROOT"
        ln -sf "$PROJECT_ROOT" "$INSTALL_DIR" || {
            error "Failed to create symlink at $INSTALL_DIR"
            return 3
        }
        ok "Symlinked $INSTALL_DIR -> $PROJECT_ROOT"
    elif [[ -L "$INSTALL_DIR" ]]; then
        # Update existing symlink
        ln -sf "$PROJECT_ROOT" "$INSTALL_DIR"
        ok "Updated symlink at $INSTALL_DIR"
    else
        # Directory already exists (maybe from a previous install)
        info "$INSTALL_DIR already exists; using it."
    fi

    # Write the launcher wrapper
    cat > /usr/local/bin/wineshield <<'WRAPPER'
#!/bin/bash
# WineShield launcher wrapper
exec python3 /opt/wineshield/core/launcher.py "$@"
WRAPPER
    chmod 755 /usr/local/bin/wineshield

    ok "Command installed: /usr/local/bin/wineshield"
    info "Run 'wineshield --help' to get started."
}

# ---------------------------------------------------------------------------
# Stage 7 — Systemd Service (optional, user-level)
# ---------------------------------------------------------------------------
section_systemd_service() {
    # Check for systemctl
    if ! command -v systemctl &>/dev/null; then
        warn "systemctl not found; skipping dashboard systemd service."
        return 0
    fi

    local SERVICE_DIR="${REAL_HOME}/.config/systemd/user"
    mkdir -p "$SERVICE_DIR"

    local SERVICE_FILE="${SERVICE_DIR}/wineshield-dashboard.service"

    info "Creating systemd user service: $SERVICE_FILE"

    cat > "$SERVICE_FILE" <<SERVICE
[Unit]
Description=WineShield Security Dashboard
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/wineshield/dashboard/app.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
SERVICE

    # Set correct ownership if run via sudo
    if [[ -n "${SUDO_USER:-}" ]]; then
        chown "$SUDO_USER:$SUDO_USER" "$SERVICE_FILE"
    fi

    # Reload systemd user daemon (as the real user)
    if [[ -n "${SUDO_USER:-}" ]]; then
        runuser -u "$SUDO_USER" -- systemctl --user daemon-reload 2>/dev/null || true
    else
        systemctl --user daemon-reload 2>/dev/null || true
    fi

    ok "Systemd user service created: wineshield-dashboard.service"
    info "Start with: systemctl --user start wineshield-dashboard"
    info "Enable on login with: systemctl --user enable wineshield-dashboard"
    info "View logs with: journalctl --user -u wineshield-dashboard -f"
}

# ---------------------------------------------------------------------------
# Stage 8 — Post-installation Summary
# ---------------------------------------------------------------------------
print_summary() {
    echo ""
    echo "=========================================="
    echo "   WineShield Installation Complete"
    echo "=========================================="
    echo "  Version:     1.0.0-alpha"
    echo "  Location:    ${INSTALL_DIR}/"
    echo "  Config:      ${WINESHIELD_HOME}/"
    echo "  Command:     wineshield --help"
    echo "  Dashboard:   python3 ${INSTALL_DIR}/dashboard/app.py"
    echo "  Logs:        ${WINESHIELD_HOME}/logs/"
    echo "  Test:        cd ${INSTALL_DIR} && pytest tests/ -v"
    echo "=========================================="
    echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    # Ensure we are running as root (required for apt, /opt, /etc/apparmor.d, etc.)
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR]${NC} This script must be run as root (sudo)."
        echo "  Usage: sudo $0"
        exit 1
    fi

    echo ""
    echo "=========================================="
    echo "   WineShield Installer — Ubuntu 22.04"
    echo "=========================================="
    echo ""

    # --- Stage 1: Dependencies ---
    echo "--- Step 1/7: Installing system dependencies ---"
    section_apt_deps || exit 1
    section_pip_deps || exit 1
    echo ""

    # --- Stage 2: Build ---
    echo "--- Step 2/7: Building C seccomp module ---"
    section_build_core || exit 2
    echo ""

    # --- Stage 3: Directories ---
    echo "--- Step 3/7: Setting up ~/.wineshield/ directories ---"
    section_directories || exit 3
    echo ""

    # --- Stage 4: Virtual Environment ---
    echo "--- Step 4/7: Python virtual environment (optional) ---"
    section_venv
    echo ""

    # --- Stage 5: AppArmor ---
    echo "--- Step 5/7: AppArmor profile installation ---"
    section_apparmor
    echo ""

    # --- Stage 6: System command ---
    echo "--- Step 6/7: Installing system-wide command ---"
    section_system_command || exit 3
    echo ""

    # --- Stage 7: Systemd service ---
    echo "--- Step 7/7: Systemd service (optional) ---"
    section_systemd_service
    echo ""

    # --- Summary ---
    print_summary

    # Ownership: ensure ~/.wineshield belongs to the real user
    if [[ -n "${SUDO_USER:-}" ]]; then
        chown -R "$SUDO_USER:$SUDO_USER" "$WINESHIELD_HOME" 2>/dev/null || true
    fi

    ok "WineShield installation completed successfully."
    exit 0
}

main "$@"
