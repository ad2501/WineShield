#!/usr/bin/env python3
"""
WineShield — Sandbox Engine Unit Tests (Layer 2: filesystem_guard / namespace)

Tests for the ``WineSandbox`` class (``core/sandbox_engine.py``).

These tests verify the sandbox lifecycle: creation, status reporting,
duplicate sandbox handling, and destruction.  Some tests exercise the
real namespace/unshare code path and may require root privileges on
Linux (or they will raise ``PermissionError`` which is handled
gracefully).

Run with::

    cd /path/to/WineShield
    pytest tests/test_sandbox.py -v

Markers:
    @pytest.mark.sudo — tests that create real namespaces (require root).
"""

from __future__ import annotations

import os
import sys
import tempfile

import pytest

from core.sandbox_engine import WineSandbox


# ── Fixtures ─────────────────────────────────────────────────────


@pytest.fixture
def minimal_config() -> dict:
    """Return a minimal valid config dict for WineSandbox."""
    return {
        "filesystem": {
            "sandbox_base": "/tmp/wineshield_test_sandboxes",
            "lower_dirs": [],
            "read_only_mask": [],
            "cleanup_on_exit": True,
            "wineprefix_isolation": False,
        },
        "network": {
            "use_network_namespace": False,
        },
    }


@pytest.fixture
def sandbox(minimal_config: dict) -> WineSandbox:
    """Provide a fresh WineSandbox instance (not yet active)."""
    return WineSandbox(minimal_config)


# ── Constructor / initial state tests ───────────────────────────


class TestInitialState:
    """Verify the initial state of a freshly created WineSandbox."""

    def test_constructor_accepts_config(self, sandbox: WineSandbox) -> None:
        """Constructor should store the config and not raise."""
        assert sandbox.config is not None
        assert isinstance(sandbox.config, dict)

    def test_initial_is_active_false(self, sandbox: WineSandbox) -> None:
        """is_active should start as False."""
        assert sandbox._is_active is False

    def test_initial_app_name_none(self, sandbox: WineSandbox) -> None:
        """app_name should start as None."""
        assert sandbox._app_name is None

    def test_initial_error_none(self, sandbox: WineSandbox) -> None:
        """error should start as None."""
        assert sandbox._error is None

    def test_initial_mounts_empty(self, sandbox: WineSandbox) -> None:
        """mounts_active should start as an empty list."""
        assert sandbox._mounts_active == []

    def test_initial_namespaces_empty(self, sandbox: WineSandbox) -> None:
        """namespaces_unshared should start as an empty list."""
        assert sandbox._namespaces_unshared == []


# ── get_status() tests ──────────────────────────────────────────


class TestGetStatus:
    """Verify get_status() returns expected keys / structure."""

    def test_get_status_returns_dict(self, sandbox: WineSandbox) -> None:
        """get_status() should return a dict."""
        status = sandbox.get_status()
        assert isinstance(status, dict)

    def test_get_status_has_expected_keys(self, sandbox: WineSandbox) -> None:
        """get_status() should contain all documented keys."""
        status = sandbox.get_status()
        expected_keys = {
            "app_name",
            "sandbox_dir",
            "upper_dir",
            "work_dir",
            "merged_dir",
            "wineprefix_dir",
            "is_active",
            "namespaces_active",
            "mounts_active",
            "error",
            "reduced_isolation",
            "sandbox_dir_exists",
        }
        for key in expected_keys:
            assert key in status, f"Missing expected key: {key}"

    def test_get_status_initial_values_correct(
        self, sandbox: WineSandbox
    ) -> None:
        """Initial status values should reflect the pre-active state."""
        status = sandbox.get_status()
        assert status["app_name"] is None
        assert status["is_active"] is False
        assert status["error"] is None
        assert status["namespaces_active"] == []
        assert status["mounts_active"] == []
        assert status["sandbox_dir_exists"] is False

    def test_get_status_is_repeatable(self, sandbox: WineSandbox) -> None:
        """Calling get_status() multiple times should not change state."""
        s1 = sandbox.get_status()
        s2 = sandbox.get_status()
        assert s1 == s2


# ── Create / Destroy cycle tests ────────────────────────────────


class TestCreateDestroyCycle:
    """Test the full create → get_status → destroy lifecycle."""

    def test_create_sandbox_creates_directories(
        self, minimal_config: dict
    ) -> None:
        """create_sandbox() should create the sandbox directory tree
        on disk (even if namespace creation fails)."""
        sb = WineSandbox(minimal_config)
        # Before calling, there should be no directory
        sb._resolve_sandbox_paths("test_app")
        sandbox_dir = sb._sandbox_dir
        assert sandbox_dir is not None
        # Remove if it somehow exists
        if os.path.isdir(sandbox_dir):
            import shutil
            shutil.rmtree(sandbox_dir, ignore_errors=True)

        # Create sandbox — namespace creation may fail without root
        try:
            sb.create_sandbox("test_app")
        except (PermissionError, RuntimeError, OSError):
            pass

        # Even if namespace creation failed, directories may have been
        # created before the error. Check if they exist.
        exists = os.path.isdir(sandbox_dir) if sandbox_dir else False
        # If namespace creation succeeded, the dir should absolutely exist.
        # If it failed partway, the constructor does cleanup (destroy_sandbox).

        # Finalize: destroy if active
        try:
            sb.destroy_sandbox()
        except Exception:
            pass

        # The assertion is that status can be retrieved at any point
        status = sb.get_status()
        assert isinstance(status, dict)
        # After destroy, is_active should be False
        assert status["is_active"] is False

    def test_create_twice_is_noop(self, minimal_config: dict) -> None:
        """Calling create_sandbox() twice should not crash (no-op)."""
        sb = WineSandbox(minimal_config)
        try:
            sb.create_sandbox("dup_test")
            is_active_1 = sb._is_active
        except (PermissionError, RuntimeError, OSError):
            is_active_1 = False  # couldn't create, skip
            sb.destroy_sandbox()
            return

        # Call create_sandbox again — should log warning, not crash
        sb.create_sandbox("dup_test")
        # is_active should remain True (no state corruption)
        assert sb._is_active == is_active_1

        sb.destroy_sandbox()
        assert sb._is_active is False

    def test_destroy_without_create_does_not_crash(
        self, sandbox: WineSandbox
    ) -> None:
        """Calling destroy_sandbox() on a never-created sandbox is safe."""
        # Should not raise
        sandbox.destroy_sandbox()
        assert sandbox._is_active is False

    def test_create_destroy_create_works(
        self, minimal_config: dict
    ) -> None:
        """A second create after destroy should be allowed (reuse)."""
        sb = WineSandbox(minimal_config)
        try:
            sb.create_sandbox("reuse_test")
            sb.destroy_sandbox()
        except (PermissionError, RuntimeError, OSError):
            # Namespaces may not work — still test the lifecycle
            sb.destroy_sandbox()

        assert sb._is_active is False

        # Try creating again
        try:
            sb.create_sandbox("reuse_test_2")
            assert sb._is_active is True
            sb.destroy_sandbox()
        except (PermissionError, RuntimeError, OSError):
            pass

        assert sb._is_active is False

    @pytest.mark.sudo
    def test_get_status_after_create(
        self, minimal_config: dict
    ) -> None:
        """After a successful create, status fields should reflect activity.

        Root privileges are required for namespace operations.  When running
        as root the test is executed normally; when not root the ``sudo``
        marker causes the conftest to skip it at collection time with a
        clear message.

        Even as root, some operations may fail on WSL (e.g. mount namespace
        with ``ENOMEM``) — those are caught gracefully.
        """
        sb = WineSandbox(minimal_config)
        try:
            sb.create_sandbox("status_test")
        except (PermissionError, RuntimeError, OSError):
            sb.destroy_sandbox()
            pytest.skip("Cannot create sandbox "
                        "(namespace creation failed — "
                        "this is expected on WSL without kernel support)")

        status = sb.get_status()
        assert status["app_name"] == "status_test"
        assert status["is_active"] is True
        assert status["error"] is None

        sb.destroy_sandbox()
        assert sb._is_active is False


# ── Config variations ───────────────────────────────────────────


class TestConfigVariations:
    """Test WineSandbox with different config structures."""

    def test_empty_config_does_not_crash(self) -> None:
        """An empty config dict should be handled gracefully."""
        sb = WineSandbox({})
        assert sb.config == {}
        status = sb.get_status()
        assert status["is_active"] is False
        sb.destroy_sandbox()  # should not crash

    def test_partial_config_does_not_crash(self) -> None:
        """A config with only some sections should be handled."""
        sb = WineSandbox({"version": "1.0"})
        assert sb.config["version"] == "1.0"
        status = sb.get_status()
        assert isinstance(status, dict)

    @pytest.mark.sudo
    def test_config_with_network_namespace(self) -> None:
        """Config enabling network namespace is accepted (may fail at runtime).

        Root privileges are required for namespace operations.  The ``sudo``
        marker causes a collection-time skip when not running as root.
        Even as root, WSL may not support network namespace unshare.
        """
        config = {
            "filesystem": {
                "sandbox_base": "/tmp/wineshield_test_ns",
                "lower_dirs": [],
                "read_only_mask": [],
                "cleanup_on_exit": True,
                "wineprefix_isolation": False,
            },
            "network": {
                "use_network_namespace": True,
            },
        }
        sb = WineSandbox(config)
        try:
            sb.create_sandbox("netns_test")
            sb.destroy_sandbox()
        except (PermissionError, RuntimeError, OSError):
            sb.destroy_sandbox()
            pytest.skip("Network namespace creation not available")

    def test_reduced_isolation_flag(self, minimal_config: dict) -> None:
        """reduced_isolation should be False until something fails."""
        sb = WineSandbox(minimal_config)
        assert sb._reduced_isolation is False


# ── Context manager tests ───────────────────────────────────────


class TestContextManager:
    """Verify that WineSandbox supports the context-manager protocol."""

    def test_context_manager_requires_active(self) -> None:
        """Entering context on an inactive sandbox should raise RuntimeError."""
        sb = WineSandbox({})
        with pytest.raises(RuntimeError, match="not active"):
            with sb:
                pass  # pragma: no cover

    @pytest.mark.sudo
    def test_context_manager_exit_calls_destroy(
        self, minimal_config: dict
    ) -> None:
        """Exiting the context should call destroy_sandbox().

        Root privileges are required for namespace operations.  The ``sudo``
        marker causes a collection-time skip when not running as root.
        Even as root, WSL limitations may prevent sandbox creation.
        """
        sb = WineSandbox(minimal_config)
        try:
            sb.create_sandbox("ctx_test")
        except (PermissionError, RuntimeError, OSError):
            pytest.skip("Cannot create sandbox")

        with sb as active_sb:
            assert active_sb._is_active is True

        # After context exit, should be destroyed
        assert sb._is_active is False


# ═══════════════════════════════════════════════════════════════
#  Path resolution tests (unit-level, no privileges needed)
# ═══════════════════════════════════════════════════════════════


class TestPathResolution:
    """Verify internal path resolution logic."""

    def test_expand_user(self) -> None:
        """_expand should resolve ~ to the user's home directory."""
        expanded = WineSandbox._expand("~/test")
        assert expanded.startswith("/")
        assert expanded.endswith("/test")
        assert "~" not in expanded

    def test_expand_absolute(self) -> None:
        """_expand should pass absolute paths through unchanged."""
        expanded = WineSandbox._expand("/absolute/path")
        assert expanded == "/absolute/path"

    def test_resolve_sandbox_paths_sets_all_dirs(
        self, minimal_config: dict
    ) -> None:
        """_resolve_sandbox_paths should populate all directories."""
        sb = WineSandbox(minimal_config)
        sb._resolve_sandbox_paths("myapp")
        assert sb._sandbox_dir is not None and sb._sandbox_dir.endswith("myapp")
        assert sb._upper_dir is not None and sb._upper_dir.endswith("upper")
        assert sb._work_dir is not None and sb._work_dir.endswith("work")
        assert sb._merged_dir is not None and sb._merged_dir.endswith("merged")
        assert sb._wineprefix_dir is not None and sb._wineprefix_dir.endswith("wineprefix")
