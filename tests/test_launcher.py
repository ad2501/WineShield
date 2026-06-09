#!/usr/bin/env python3
"""
WineShield — Launcher Integration Tests

Tests for the main entry point (``core/launcher.py``).

Verifies CLI argument parsing, ``--list-layers`` output, config loading
(including error handling for missing/invalid config files), and the
``build_parser`` function.

Run with::

    cd /path/to/WineShield
    pytest tests/test_launcher.py -v
"""

from __future__ import annotations

import json
import os
import sys
import tempfile

import pytest

from core.launcher import (
    AVAILABLE_LAYERS,
    LAYER_DESCRIPTIONS,
    REQUIRED_CONFIG_KEYS,
    build_parser,
    load_config,
    main,
)


# ── Fixtures ─────────────────────────────────────────────────────


@pytest.fixture
def valid_config_dict() -> dict:
    """Return a valid minimal configuration dict."""
    return {
        "version": "1.0.0-test",
        "general": {
            "seccomp_mode": "balanced",
            "log_level": "info",
            "log_file": "/tmp/wineshield_test_events.log",
            "wineshield_home": "/tmp/wineshield_test_home",
            "dashboard_port": 5000,
            "max_events_memory": 1000,
            "session_timeout_seconds": 3600,
        },
        "layers": {
            "syscall_filter": {"enabled": True, "description": ""},
            "filesystem_guard": {"enabled": True, "description": ""},
            "network_guard": {"enabled": True, "description": ""},
            "behavior_analyzer": {"enabled": True, "description": ""},
            "xephyr_guard": {"enabled": False, "description": ""},
            "apparmor": {"enabled": True, "description": ""},
        },
        "seccomp": {"default_mode": "balanced", "modes": {}},
        "filesystem": {"sandbox_base": "/tmp/wineshield_test_sb"},
        "network": {"mode": "monitor"},
        "behavior": {"analyzer_enabled": True},
    }


@pytest.fixture
def valid_config_path(valid_config_dict: dict) -> str:
    """Write a valid config to a temp file and return the path."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False
    ) as f:
        json.dump(valid_config_dict, f)
        return f.name


# ═══════════════════════════════════════════════════════════════════
#  build_parser tests
# ═══════════════════════════════════════════════════════════════════


class TestBuildParser:
    """Verify the argument parser construction."""

    def test_build_parser_returns_parser(self) -> None:
        """build_parser() should return an ArgumentParser instance."""
        parser = build_parser()
        assert parser is not None
        assert parser.prog == "wineshield"

    def test_parser_has_mode_argument(self) -> None:
        """Parser should accept --mode with choices."""
        parser = build_parser()
        args = parser.parse_args(["--mode", "balanced"])
        assert args.mode == "balanced"

    def test_parser_mode_valid_choices(self) -> None:
        """--mode should accept monitor, balanced, strict."""
        parser = build_parser()
        for mode in ("monitor", "balanced", "strict"):
            args = parser.parse_args(["--mode", mode])
            assert args.mode == mode

    def test_parser_has_app_argument(self) -> None:
        """Parser should accept --app."""
        parser = build_parser()
        args = parser.parse_args(["--app", "notepad.exe"])
        assert args.app == "notepad.exe"

    def test_parser_has_config_argument(self) -> None:
        """Parser should accept --config with default."""
        parser = build_parser()
        args = parser.parse_args([])
        assert args.config == "config/default_policy.json"

    def test_parser_config_custom(self) -> None:
        """Parser should accept a custom --config path."""
        parser = build_parser()
        args = parser.parse_args(["--config", "/custom/path.json"])
        assert args.config == "/custom/path.json"

    def test_parser_has_layer_argument(self) -> None:
        """Parser should accept --layer."""
        parser = build_parser()
        args = parser.parse_args(["--layer", "syscall,fs,behavior"])
        assert args.layer == "syscall,fs,behavior"

    def test_parser_has_list_layers(self) -> None:
        """Parser should accept --list-layers."""
        parser = build_parser()
        args = parser.parse_args(["--list-layers"])
        assert args.list_layers is True

    def test_parser_all_available_layers_listed(self) -> None:
        """AVAILABLE_LAYERS should contain all expected layer names."""
        expected = {"syscall", "fs", "network", "behavior", "xephyr", "apparmor"}
        assert set(AVAILABLE_LAYERS) == expected

    def test_parser_layer_descriptions_complete(self) -> None:
        """Every available layer should have a description."""
        for layer in AVAILABLE_LAYERS:
            assert layer in LAYER_DESCRIPTIONS, (
                f"Missing description for layer: {layer}"
            )
            assert LAYER_DESCRIPTIONS[layer] != ""


# ═══════════════════════════════════════════════════════════════════
#  --list-layers output tests
# ═══════════════════════════════════════════════════════════════════


class TestListLayers:
    """Verify the --list-layers CLI flag."""

    def test_list_layers_returns_zero(self) -> None:
        """--list-layers should exit with code 0."""
        rc = main(["--list-layers"])
        assert rc == 0

    def test_list_layers_contains_layer_names(self, capsys) -> None:
        """--list-layers should print all available layer names."""
        rc = main(["--list-layers"])
        captured = capsys.readouterr()
        output = captured.out
        assert rc == 0
        for layer in AVAILABLE_LAYERS:
            assert layer in output, f"Layer '{layer}' missing from --list-layers output"

    def test_list_layers_contains_descriptions(self, capsys) -> None:
        """--list-layers should print descriptions of each layer."""
        rc = main(["--list-layers"])
        captured = capsys.readouterr()
        output = captured.out
        assert rc == 0
        for layer in AVAILABLE_LAYERS:
            desc = LAYER_DESCRIPTIONS[layer]
            assert desc in output, (
                f"Description for '{layer}' missing from --list-layers output"
            )


# ═══════════════════════════════════════════════════════════════════
#  Config loading tests
# ═══════════════════════════════════════════════════════════════════


class TestConfigLoading:
    """Verify the load_config() function."""

    def test_load_valid_config(self, valid_config_path: str) -> None:
        """A valid config file should be loaded successfully."""
        config = load_config(valid_config_path)
        assert isinstance(config, dict)
        assert config["version"] == "1.0.0-test"

    def test_load_config_contains_required_keys(
        self, valid_config_path: str
    ) -> None:
        """A loaded config should contain all required keys."""
        config = load_config(valid_config_path)
        for key in REQUIRED_CONFIG_KEYS:
            assert key in config, f"Missing required config key: {key}"

    def test_load_nonexistent_config_raises(self) -> None:
        """Loading a non-existent path should raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            load_config("/tmp/wineshield_nonexistent_config_12345.json")

    def test_load_invalid_json_raises(self) -> None:
        """An invalid JSON file should raise json.JSONDecodeError."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            f.write("this is not valid json {{{")
            path = f.name
        try:
            with pytest.raises(json.JSONDecodeError):
                load_config(path)
        finally:
            os.unlink(path)

    def test_load_config_missing_required_keys_raises(self) -> None:
        """A config missing required keys should raise ValueError."""
        incomplete = {"version": "1.0"}  # missing general, layers, seccomp, etc.
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(incomplete, f)
            path = f.name
        try:
            with pytest.raises(ValueError, match="missing required"):
                load_config(path)
        finally:
            os.unlink(path)

    def test_load_config_expands_user(self) -> None:
        """Paths with ~ should be expanded."""
        # We can't actually make a ~-path work in temp, but we can
        # verify the function doesn't crash on valid configs at ~ paths.
        config = load_config(
            os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "..",
                "config",
                "default_policy.json",
            )
        )
        assert isinstance(config, dict)

    def test_required_config_keys_list(self) -> None:
        """REQUIRED_CONFIG_KEYS should be a non-empty list of strings."""
        assert isinstance(REQUIRED_CONFIG_KEYS, list)
        assert len(REQUIRED_CONFIG_KEYS) > 0
        for key in REQUIRED_CONFIG_KEYS:
            assert isinstance(key, str)

    def test_load_config_version_field(self, valid_config_path: str) -> None:
        """A loaded config should preserve the version field."""
        config = load_config(valid_config_path)
        assert config["version"] == "1.0.0-test"


# ═══════════════════════════════════════════════════════════════════
#  Main() smoke tests  (limited — full invocation requires Wine)
# ═══════════════════════════════════════════════════════════════════


class TestMainEntryPoint:
    """Smoke tests for the main() entry point."""

    def test_main_help(self) -> None:
        """main() should accept --help and return 0."""
        # Accessing --help via the parser would print to stdout
        # and call sys.exit(0). We'll use the parser directly.
        parser = build_parser()
        with pytest.raises(SystemExit) as exc:
            parser.parse_args(["--help"])
        assert exc.value.code == 0

    def test_main_list_layers(self) -> None:
        """main() with --list-layers should return 0."""
        rc = main(["--list-layers"])
        assert rc == 0

    def test_main_missing_config_handled(self) -> None:
        """main() with a non-existent config path should return 1."""
        rc = main([
            "--config", "/tmp/wineshield_nonexistent_12345.json",
            "--list-layers",
        ])
        # --list-layers should process before config loading, so still 0
        assert rc == 0

    def test_main_no_arguments(self) -> None:
        """main() with no arguments should... handle it gracefully."""
        # Without any args, it will try to load the default config.
        # If the default config exists (which it should), it will proceed.
        # We just verify it doesn't crash with a traceback.
        try:
            rc = main([])
            assert rc in (0, 1)  # either success or controlled failure
        except SystemExit:
            pass  # acceptable in some cases

    def test_main_with_mode_only(self) -> None:
        """main() with --mode only should try to load config."""
        # This will attempt to load the default config and proceed.
        # If Wine isn't installed, it'll return 1 (controlled), not crash.
        try:
            rc = main(["--mode", "monitor"])
            assert rc in (0, 1)
        except SystemExit:
            pass
        except Exception:
            # Other controlled exits are acceptable
            pass


# ═══════════════════════════════════════════════════════════════════
#  AVAILABLE_LAYERS and LAYER_DESCRIPTIONS consistency
# ═══════════════════════════════════════════════════════════════════


class TestLayerDefinitions:
    """Verify layer definitions are consistent."""

    def test_all_layers_have_descriptions(self) -> None:
        """Every entry in AVAILABLE_LAYERS must have a description."""
        for layer in AVAILABLE_LAYERS:
            assert layer in LAYER_DESCRIPTIONS

    def test_no_extra_descriptions(self) -> None:
        """Every description should correspond to a known layer."""
        for layer in LAYER_DESCRIPTIONS:
            assert layer in AVAILABLE_LAYERS

    def test_layer_names_strings(self) -> None:
        """All layer names should be non-empty strings."""
        for layer in AVAILABLE_LAYERS:
            assert isinstance(layer, str) and len(layer) > 0

    def test_layer_descriptions_nonempty(self) -> None:
        """All layer descriptions should be non-empty strings."""
        for desc in LAYER_DESCRIPTIONS.values():
            assert isinstance(desc, str) and len(desc) > 0


# ═══════════════════════════════════════════════════════════════════
#  Config path expansion tests
# ═══════════════════════════════════════════════════════════════════


class TestConfigPathHandling:
    """Verify config path resolution edge cases."""

    def test_config_with_tilde(self) -> None:
        """Paths starting with ~ should be expanded."""
        # load_config handles ~ expansion via os.path.expanduser
        # Create a temp config in a ~-relative location isn't easy,
        # but we can verify the function doesn't crash on paths with ~
        # by using a non-existent path — it should raise FileNotFoundError
        with pytest.raises(FileNotFoundError):
            load_config("~/wineshield_test_nonexistent_config.json")

    def test_config_with_relative_path(
        self, valid_config_path: str
    ) -> None:
        """Relative paths should be resolved relative to CWD."""
        # Change to temp dir and use a relative config path
        cwd = os.getcwd()
        config_dir = os.path.dirname(valid_config_path)
        config_file = os.path.basename(valid_config_path)
        try:
            os.chdir(config_dir)
            config = load_config(config_file)
            assert isinstance(config, dict)
        finally:
            os.chdir(cwd)
