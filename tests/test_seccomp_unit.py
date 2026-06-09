#!/usr/bin/env python3
"""WineShield — Seccomp Unit Tests (Layer 1: syscall_filter)

Tests for the C binary (syscall_monitor) that implements the seccomp-BPF
syscall filter.  These tests run the compiled binary directly via
``subprocess`` and verify its behaviour at the process level.

Each test builds a command line, invokes ``sudo ./syscall_monitor …``,
and checks the return code and/or stdout for expected output.

Run with::

    cd /path/to/WineShield
    pytest tests/test_seccomp_unit.py -v                    # all tests

Markers:
    (none — tests call sudo internally via subprocess)
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

# ── Path to the compiled syscall_monitor binary ──────────────

_BINARY_CANDIDATES = [
    # Python-relative (when running from project root)
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "core", "syscall_monitor"),
    # CWD-relative (when running from tests/ or project root)
    os.path.join("core", "syscall_monitor"),
    "syscall_monitor",
]


def _binary_path() -> str:
    """Return the first existing path to the compiled syscall_monitor binary."""
    for p in _BINARY_CANDIDATES:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    # Last resort — let subprocess fail with a clear error
    return _BINARY_CANDIDATES[0]


def _skip_if_no_binary() -> None:
    """Skip the current test if the syscall_monitor binary is missing."""
    if not os.path.isfile(_binary_path()):
        pytest.skip(f"syscall_monitor binary not found at {_binary_path()}")


def _skip_if_no_sudo() -> None:
    """Skip the current test if sudo is not available."""
    try:
        subprocess.run(
            ["sudo", "-n", "true"],
            capture_output=True,
            timeout=5,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        pytest.skip("sudo not available or requires password")


# ═══════════════════════════════════════════════════════════════
#  Help Test: Help & Invalid Input
# ═══════════════════════════════════════════════════════════════


def test_help_returns_zero() -> None:
    """--help should return exit code 0."""
    _skip_if_no_binary()
    result = subprocess.run(
        [_binary_path(), "--help"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0
    assert "Usage" in result.stdout or "Usage" in result.stderr


def test_short_help_returns_zero() -> None:
    """-h should return exit code 0 (short form of --help)."""
    _skip_if_no_binary()
    result = subprocess.run(
        [_binary_path(), "-h"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0
    assert "Usage" in result.stdout or "Usage" in result.stderr


def test_unknown_flag_returns_nonzero() -> None:
    """An unknown flag should produce a non-zero exit code."""
    _skip_if_no_binary()
    result = subprocess.run(
        [_binary_path(), "--unknown-flag"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode != 0, f"Expected failure, got rc={result.returncode}"
    assert "Usage" in result.stdout or "Unknown" in result.stderr


def test_unknown_mode_returns_nonzero() -> None:
    """An invalid mode string should produce a non-zero exit."""
    _skip_if_no_binary()
    result = subprocess.run(
        [_binary_path(), "--mode", "bogus", "--", "/bin/true"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode != 0


# ═══════════════════════════════════════════════════════════════
#  Mode Tests: Basic /bin/true Invocation
# ═══════════════════════════════════════════════════════════════


def test_monitor_mode_simple_command() -> None:
    """--mode monitor /bin/true should succeed and print 'seccomp active'."""
    _skip_if_no_binary()
    result = subprocess.run(
        ["sudo", _binary_path(), "--mode", "monitor", "--", "/bin/true"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, (
        f"Expected 0, got {result.returncode}. "
        f"stdout: {result.stdout}, stderr: {result.stderr}"
    )
    assert "seccomp active" in result.stdout, (
        f"Expected 'seccomp active' in stdout. Got: {result.stdout}"
    )


def test_balanced_mode_simple_command() -> None:
    """--mode balanced /bin/true should succeed under BPF filter."""
    _skip_if_no_binary()
    binary = _binary_path()
    result = subprocess.run(
        ["sudo", binary, "--mode", "balanced", "--", "/bin/true"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, (
        f"Expected 0, got {result.returncode}. "
        f"stdout: {result.stdout}, stderr: {result.stderr}"
    )
    assert "seccomp active" in result.stdout


def test_strict_mode_simple_command() -> None:
    """--mode strict /bin/true should succeed (true only needs exit_group)."""
    _skip_if_no_binary()
    binary = _binary_path()
    result = subprocess.run(
        ["sudo", binary, "--mode", "strict", "--", "/bin/true"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, (
        f"Expected 0, got {result.returncode}. "
        f"stdout: {result.stdout}, stderr: {result.stderr}"
    )


def test_monitor_mode_echo() -> None:
    """--mode monitor echo hello should print 'hello' and 'seccomp active'."""
    _skip_if_no_binary()
    binary = _binary_path()
    result = subprocess.run(
        ["sudo", binary, "--mode", "monitor", "--", "/bin/echo", "hello"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, (
        f"Expected 0, got {result.returncode}. "
        f"stdout: {result.stdout}, stderr: {result.stderr}"
    )
    assert "seccomp active" in result.stdout
    assert "hello" in result.stdout, (
        f"Expected 'hello' in stdout. Got: {result.stdout}"
    )


def test_strict_mode_echo() -> None:
    """--mode strict echo hello should succeed (write syscall allowed)."""
    _skip_if_no_binary()
    binary = _binary_path()
    result = subprocess.run(
        ["sudo", binary, "--mode", "strict", "--", "/bin/echo", "hello"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, (
        f"Expected 0, got {result.returncode}. "
        f"stdout: {result.stdout}, stderr: {result.stderr}"
    )


def test_strict_mode_ls_works() -> None:
    """--mode strict ls / should work (stat/getdents allowed in whitelist)."""
    _skip_if_no_binary()
    binary = _binary_path()
    result = subprocess.run(
        ["sudo", binary, "--mode", "strict", "--", "/bin/ls", "/"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, (
        f"Expected 0, got {result.returncode}. "
        f"stdout: {result.stdout}, stderr: {result.stderr}"
    )


# ═══════════════════════════════════════════════════════════════
#  Block Tests: syscalls that should be rejected
# ═══════════════════════════════════════════════════════════════


def test_balanced_blocks_ptrace() -> None:
    """--mode balanced should block ptrace (exit 159 = SIGSYS)."""
    _skip_if_no_binary()
    binary = _binary_path()
    # Build a small test program that calls ptrace()
    result = subprocess.run(
        ["sudo", binary, "--mode", "balanced", "--", "/bin/sh", "-c",
         'python3 -c "import ctypes; ctypes.CDLL(None).ptrace(0, 0, 0, 0)"'],
        capture_output=True,
        text=True,
        timeout=15,
    )
    # The process should be killed with SIGSYS (signal 31) -> exit 159 (128+31)
    # or return non-zero from the seccomp denial
    assert result.returncode != 0, (
        f"Expected ptrace to be blocked, but got rc=0. "
        f"stdout: {result.stdout[:200]}"
    )


def test_default_command_is_ls() -> None:
    """Running without a target command should default to 'ls' (or fail gracefully)."""
    _skip_if_no_binary()
    binary = _binary_path()
    result = subprocess.run(
        ["sudo", binary, "--mode", "monitor"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    # Should either succeed (defaults to 'ls') or return a specific error
    assert "seccomp active" in result.stdout or result.returncode != 0


# ═══════════════════════════════════════════════════════════════
#  Output Verification Tests (mode / message printing)
# ═══════════════════════════════════════════════════════════════


def test_monitor_prints_mode_monitor() -> None:
    """Verify 'mode=MONITOR' appears in output."""
    _skip_if_no_binary()
    binary = _binary_path()
    result = subprocess.run(
        ["sudo", binary, "--mode", "monitor", "--", "/bin/true"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0
    assert "MONITOR" in result.stdout.upper() or "mode=MONITOR" in result.stdout


def test_balanced_prints_mode_balanced() -> None:
    """Verify 'mode=BALANCED' appears in output."""
    _skip_if_no_binary()
    binary = _binary_path()
    result = subprocess.run(
        ["sudo", binary, "--mode", "balanced", "--", "/bin/true"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0
    assert "BALANCED" in result.stdout.upper() or "mode=BALANCED" in result.stdout


def test_strict_prints_mode_strict() -> None:
    """Verify 'mode=STRICT' appears in output."""
    _skip_if_no_binary()
    binary = _binary_path()
    result = subprocess.run(
        ["sudo", binary, "--mode", "strict", "--", "/bin/true"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0
    assert "STRICT" in result.stdout.upper() or "mode=STRICT" in result.stdout
