#!/usr/bin/env python3
"""
WineShield — Pytest shared fixtures and configuration.

This conftest provides:

* ``root_available`` fixture — True when running as root (uid==0), False otherwise.
* Automatic skip of ``@pytest.mark.sudo``-marked tests when not root.
* The ``sudo`` marker is registered in ``pyproject.toml`` but we ensure it's
  also registered here so standalone test-file runs work correctly.
"""
from __future__ import annotations

import os

import pytest


# ── Helpers ─────────────────────────────────────────────────────


def is_root() -> bool:
    """Return ``True`` if the current process is running as root (uid == 0)."""
    return os.geteuid() == 0


# ── Marker registration ─────────────────────────────────────────


def pytest_configure(config: pytest.Config) -> None:
    """Register the ``sudo`` marker (idempotent — pyproject.toml also registers it)."""
    config.addinivalue_line(
        "markers",
        "sudo: marks tests that require root privileges "
        "(deselect with '-m \"not sudo\"')",
    )


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Auto-skip tests marked with ``@pytest.mark.sudo`` when not running as root.

    When the process *is* root the marker is left alone so the test runs
    normally.  When not root the marker is converted to a ``skip`` marker
    with a clear explanation.
    """
    if is_root():
        return  # root available — let all tests run

    for item in items:
        if item.get_closest_marker("sudo") is not None:
            item.add_marker(
                pytest.mark.skip(
                    reason="requires root privileges — "
                    "run with 'sudo python3 -m pytest ...'"
                )
            )


# ── Fixtures ────────────────────────────────────────────────────


@pytest.fixture
def root_available() -> bool:
    """Fixture: ``True`` when the test process is running as root."""
    return is_root()
