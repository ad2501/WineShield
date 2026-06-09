#!/usr/bin/env python3
"""Regression tests for importable package surfaces.

These tests codify the public Python modules that should be importable even
when native/root-only layers are exercised through binaries or mocked wrappers.
"""
from __future__ import annotations

import importlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_core_package_exports_syscall_monitor_wrapper() -> None:
    from core import syscall_monitor

    assert syscall_monitor.MODE_MONITOR == 0
    assert syscall_monitor.MODE_BALANCED == 1
    assert syscall_monitor.MODE_STRICT == 2
    assert callable(syscall_monitor.wineshield_init_seccomp)


def test_core_package_exports_sandbox_engine_facade() -> None:
    from core.sandbox_engine import SandboxEngine, WineSandbox

    assert issubclass(SandboxEngine, WineSandbox)
    assert hasattr(SandboxEngine(), "create_namespaces")


def test_dashboard_support_modules_are_importable() -> None:
    for module_name in (
        "dashboard.database",
        "dashboard.routes",
        "dashboard.websocket_server",
    ):
        module = importlib.import_module(module_name)
        assert module is not None


def test_placeholder_files_removed_from_python_and_shell_sources() -> None:
    checked = [
        ROOT / "dashboard" / "database.py",
        ROOT / "dashboard" / "routes.py",
        ROOT / "dashboard" / "websocket_server.py",
        ROOT / "scripts" / "generate_whitelist.py",
        ROOT / "scripts" / "setup_apparmor.sh",
        ROOT / "tests" / "fixtures" / "malware_samples.py",
    ]
    for path in checked:
        assert path.exists(), path
        assert path.read_text(encoding="utf-8").strip() != "testing files"
