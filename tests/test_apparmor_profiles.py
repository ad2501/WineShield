#!/usr/bin/env python3
"""Tests for WineShield AppArmor profile source files.

Runtime AppArmor loading requires kernel support and root; these tests keep the
project honest by verifying the profile files are not placeholders and, when the
parser is available, that canonical profiles parse in compile/check mode.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
APPARMOR_DIR = ROOT / "config" / "apparmor"
CANONICAL_PROFILES = [
    APPARMOR_DIR / "wineshield.wine",
    APPARMOR_DIR / "wineshield.wineserver",
    APPARMOR_DIR / "wineshield.framework",
    APPARMOR_DIR / "wine.profile",
    APPARMOR_DIR / "wineserver.profile",
    APPARMOR_DIR / "wineshield.profile",
]


def test_apparmor_profiles_are_real_files_not_placeholders() -> None:
    for profile in CANONICAL_PROFILES:
        text = profile.read_text(encoding="utf-8")
        assert text.strip() != "testing files"
        assert "profile " in text
        assert "{" in text and "}" in text


def test_apparmor_profiles_do_not_reference_undefined_pid_tunable() -> None:
    for profile in CANONICAL_PROFILES:
        text = profile.read_text(encoding="utf-8")
        assert "@{PID}" not in text


def test_apparmor_profiles_avoid_nonstandard_wine_abstraction() -> None:
    wine_profile = APPARMOR_DIR / "wineshield.wine"
    assert "#include <abstractions/wine>" not in wine_profile.read_text(encoding="utf-8")


@pytest.mark.skipif(shutil.which("apparmor_parser") is None, reason="apparmor_parser unavailable")
def test_canonical_apparmor_profiles_parse_when_parser_available() -> None:
    for profile in CANONICAL_PROFILES[:3]:
        result = subprocess.run(
            ["apparmor_parser", "-Q", "-K", str(profile)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=20,
        )
        assert result.returncode == 0, result.stdout + result.stderr
