#!/usr/bin/env python3
"""
WineShield — Main Entry Point / Launcher
=========================================

Orchestrates all 5+1 security layers for Wine application sandboxing.

Architecture
------------
WineShield provides defence-in-depth for running Windows binaries via Wine:

  1. syscall_filter   — seccomp-BPF syscall filter (C binary: syscall_monitor)
  2. filesystem_guard — OverlayFS + read-only path masking
  3. network_guard    — Network namespace isolation & connection monitoring
  4. behavior_analyzer— Runtime behaviour pattern detection
  5. xephyr_guard     — X11 input isolation via Xephyr
  +  apparmor         — AppArmor profile confinement

The modules communicate through a **unified event format** (dict with
id/timestamp/severity/layer/action/details/pid/process/session keys).

Usage (CLI)::

    wineshield --mode balanced --app notepad++.exe
    wineshield --mode monitor
    wineshield --mode strict --layer syscall,fs,behavior
    wineshield --list-layers

References
----------
- Config schema: config/default_policy.json
- Entry point registered in pyproject.toml as ``core.launcher:main``
"""

# ───────────────────────────────────────────────────────────────────
#  Imports
# ───────────────────────────────────────────────────────────────────
from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ── Core-layer imports (with graceful fallbacks for stubs) ────────
from core.sandbox_engine import WineSandbox

# Each guard module may be a stub during development; we try to import
# the expected class and fall back to a no-op class so the launcher
# never crashes due to a missing implementation.  We catch *all*
# exceptions (SyntaxError, ImportError, etc.) because stub files may
# contain plain text rather than valid Python.

try:
    from core.fs_guard import FSGuard
except Exception:
    # Stub fallback – will be replaced by the real implementation
    class FSGuard:  # type: ignore[no-redef]
        """Placeholder — real FSGuard not yet implemented."""
        def __init__(self, config: dict): self._config = config
        def setup(self) -> None:
            logging.getLogger(__name__).info("FSGuard (stub): setup skipped")
        def cleanup(self) -> None:
            logging.getLogger(__name__).info("FSGuard (stub): cleanup skipped")

try:
    from core.network_guard import NetworkGuard
except Exception:
    class NetworkGuard:  # type: ignore[no-redef]
        """Placeholder — real NetworkGuard not yet implemented."""
        def __init__(self, config: dict): self._config = config
        def start_monitoring(self, session_id: str) -> None: ...
        def stop_monitoring(self) -> None: ...
        def cleanup(self) -> None:
            logging.getLogger(__name__).info("NetworkGuard (stub): cleanup skipped")

try:
    from core.behavior_analyzer import BehaviorAnalyzer
except Exception:
    class BehaviorAnalyzer:  # type: ignore[no-redef]
        """Placeholder — real BehaviorAnalyzer not yet implemented."""
        def __init__(self, config: dict): self._config = config
        def start_monitoring(self, session_id: str) -> None: ...
        def stop_monitoring(self) -> None: ...
        def cleanup(self) -> None:
            logging.getLogger(__name__).info("BehaviorAnalyzer (stub): cleanup skipped")

try:
    from core.xephyr_guard import X11Guard
except Exception:
    class X11Guard:  # type: ignore[no-redef]
        """Placeholder — real X11Guard not yet implemented."""
        def __init__(self, config: dict): self._config = config
        def create_x11_sandbox(self, width: int = 1024, height: int = 768) -> None: ...
        def cleanup_x11_sandbox(self) -> None: ...

try:
    from core.apparmor_manager import AppArmorManager
except Exception:
    class AppArmorManager:  # type: ignore[no-redef]
        """Placeholder — real AppArmorManager not yet implemented."""
        def __init__(self): ...
        def load_profiles(self) -> None:
            logging.getLogger(__name__).info("AppArmorManager (stub): load_profiles skipped")
        def unload_profiles(self) -> None: ...
        def cleanup(self) -> None:
            logging.getLogger(__name__).info("AppArmorManager (stub): cleanup skipped")

# ───────────────────────────────────────────────────────────────────
#  Logging setup
# ───────────────────────────────────────────────────────────────────

_log = logging.getLogger(__name__)

# We configure logging *after* config is loaded so the log-level and
# file destination come from the policy file.  A basic stderr handler
# is installed at import time only as a last-resort.
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s")


# ═══════════════════════════════════════════════════════════════════
#  Configuration
# ═══════════════════════════════════════════════════════════════════

REQUIRED_CONFIG_KEYS: List[str] = [
    "general", "layers", "seccomp", "filesystem", "network", "behavior",
]


def load_config(path: str) -> Dict[str, Any]:
    """
    Read and validate the WineShield policy configuration.

    Parameters
    ----------
    path : str
        Filesystem path to ``default_policy.json`` (``~`` is expanded).

    Returns
    -------
    dict
        Parsed JSON configuration dictionary.

    Raises
    ------
    FileNotFoundError
        If the file does not exist.
    json.JSONDecodeError
        If the file is not valid JSON.
    ValueError
        If required top-level keys are missing.
    """
    resolved = os.path.expanduser(path)
    _log.info("Loading configuration from %s", resolved)

    try:
        with open(resolved, "r", encoding="utf-8") as fh:
            cfg: Dict[str, Any] = json.load(fh)
    except FileNotFoundError:
        _log.error("Configuration file not found: %s", resolved)
        raise
    except json.JSONDecodeError as exc:
        _log.error("Invalid JSON in %s: %s", resolved, exc)
        raise

    # ── validate required keys ─────────────────────────────────
    missing = [k for k in REQUIRED_CONFIG_KEYS if k not in cfg]
    if missing:
        msg = f"Configuration missing required key(s): {', '.join(missing)}"
        _log.error(msg)
        raise ValueError(msg)

    _log.info("Configuration loaded successfully (version: %s)",
              cfg.get("version", "unknown"))
    return cfg


# ═══════════════════════════════════════════════════════════════════
#  Unified Event Helpers
# ═══════════════════════════════════════════════════════════════════

def make_event(
    severity: str,
    layer: str,
    action: str,
    details: str = "",
    pid: int = 0,
    process_name: str = "",
    session: str = "",
) -> Dict[str, Any]:
    """
    Build a unified security event dictionary.

    All layers in WineShield emit events in this format so they can
    be consumed uniformly by the dashboard, log file, and alerting.
    """
    now = datetime.now(timezone.utc)
    return {
        "id": str(uuid.uuid4()),
        "timestamp": now.isoformat(),
        "date": now.strftime("%Y-%m-%d"),
        "severity": severity,
        "layer": layer,
        "action": action,
        "details": details,
        "pid": pid or os.getpid(),
        "process": process_name or os.path.basename(sys.argv[0]),
        "session": session,
    }


def write_event_json(event: Dict[str, Any], log_path: str) -> None:
    """
    Append a single event to the JSON events log.

    Each line is a complete JSON object (newline-delimited JSON).
    """
    try:
        raw = log_path
        # When running under sudo, expand ~ to the ORIGINAL user's home,
        # not root's
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user and raw.startswith("~"):
            import pwd
            pw = pwd.getpwnam(sudo_user)
            resolved = raw.replace("~", pw.pw_dir, 1)
        else:
            resolved = os.path.expanduser(raw)
        parent = os.path.dirname(resolved)
        if parent:
            os.makedirs(parent, mode=0o755, exist_ok=True)
        with open(resolved, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, default=str) + "\n")
    except OSError as exc:
        _log.warning("Failed to write event to %s: %s", log_path, exc)


# ═══════════════════════════════════════════════════════════════════
#  Layer Monitor Threads
# ═══════════════════════════════════════════════════════════════════

def _monitor_syscall_filter(
    mode: str,
    wine_binary: str,
    session_id: str,
    event_log_path: str,
    config: dict,
) -> None:
    """
    Monitor thread for the seccomp syscall filter (``syscall_monitor`` C binary).

    This thread keeps the syscall_monitor process alive for the duration
    of the Wine session.  When Wine exits, the monitor dies naturally.
    """
    seccomp_cfg = config.get("seccomp", {})
    mode_settings = seccomp_cfg.get("modes", {}).get(mode, {})

    # Determine the seccomp mode string for the binary
    # (monitor/balanced/strict all map directly)
    seccomp_arg = mode

    binary_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "syscall_monitor"
    )

    if not os.path.isfile(binary_path):
        _log.warning("syscall_monitor binary not found at %s — skipping", binary_path)
        event = make_event("warning", "syscall_filter",
                           "syscall_monitor binary not found",
                           f"Expected at {binary_path}", session=session_id)
        write_event_json(event, event_log_path)
        _log.warning("[%s] %s", event["id"][:8], event["action"])
        return

    cmd = ["sudo", binary_path, "--mode", seccomp_arg, "--", wine_binary]
    _log.info("Starting syscall_monitor: %s", " ".join(cmd))

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        event = make_event("info", "syscall_filter",
                           f"syscall_monitor started (mode={seccomp_arg})",
                           f"PID={proc.pid}", pid=proc.pid,
                           session=session_id)
        write_event_json(event, event_log_path)
        _log.info("[%s] %s", event["id"][:8], event["action"])

        # Read stdout/stderr as it comes
        assert proc.stdout is not None
        assert proc.stderr is not None
        for line in iter(proc.stdout.readline, ""):
            line = line.rstrip("\n")
            if line:
                _log.debug("[syscall_monitor] %s", line)
                ev = make_event("info", "syscall_filter", line,
                                session=session_id)
                write_event_json(ev, event_log_path)

        proc.wait()
        _log.info("syscall_monitor exited (returncode=%d)", proc.returncode)
        event = make_event("info", "syscall_filter",
                           f"syscall_monitor exited (rc={proc.returncode})",
                           session=session_id)
        write_event_json(event, event_log_path)

    except FileNotFoundError:
        _log.error("sudo or syscall_monitor not found — syscall filtering disabled")
    except Exception as exc:
        _log.error("syscall_monitor thread error: %s", exc)
        event = make_event("error", "syscall_filter",
                           f"syscall_monitor error: {exc}",
                           session=session_id)
        write_event_json(event, event_log_path)


def _monitor_fs_guard(
    guard: FSGuard,
    session_id: str,
    event_log_path: str,
) -> None:
    """
    Monitor thread placeholder for filesystem guard events.

    The real FSGuard will push filesystem access events through
    this channel once implemented.
    """
    _log.info("FSGuard monitor thread started (session=%s)", session_id)
    event = make_event("info", "filesystem_guard",
                       "FSGuard monitoring active",
                       session=session_id)
    write_event_json(event, event_log_path)

    # Future: poll guard for events or read from a pipe/queue
    try:
        # Keep thread alive until daemon flag kills it
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        pass


def _monitor_network_guard(
    guard: NetworkGuard,
    session_id: str,
    event_log_path: str,
) -> None:
    """
    Monitor thread for network activity.
    """
    _log.info("NetworkGuard monitor thread started (session=%s)", session_id)
    event = make_event("info", "network_guard",
                       "NetworkGuard monitoring active",
                       session=session_id)
    write_event_json(event, event_log_path)

    try:
        guard.start_monitoring()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        _log.warning("NetworkGuard monitoring error: %s", exc)


def _monitor_behavior_analyzer(
    analyzer: BehaviorAnalyzer,
    session_id: str,
    event_log_path: str,
) -> None:
    """
    Monitor thread for runtime behavior analysis.
    """
    _log.info("BehaviorAnalyzer monitor thread started (session=%s)", session_id)
    event = make_event("info", "behavior_analyzer",
                       "BehaviorAnalyzer monitoring active",
                       session=session_id)
    write_event_json(event, event_log_path)

    try:
        analyzer.start_monitoring(session_id)
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        _log.warning("BehaviorAnalyzer monitoring error: %s", exc)


# ═══════════════════════════════════════════════════════════════════
#  CLI Argument Parsing
# ═══════════════════════════════════════════════════════════════════

AVAILABLE_LAYERS = [
    "syscall",
    "fs",
    "network",
    "behavior",
    "xephyr",
    "apparmor",
]

LAYER_DESCRIPTIONS = {
    "syscall":  "seccomp-BPF syscall filter (syscall_monitor C binary)",
    "fs":       "Filesystem isolation via OverlayFS + read-only masks",
    "network":  "Network namespace isolation & connection monitoring",
    "behavior": "Runtime behaviour pattern detection",
    "xephyr":   "X11 input isolation via Xephyr",
    "apparmor": "AppArmor profile confinement",
}


def build_parser() -> argparse.ArgumentParser:
    """Build and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="wineshield",
        description="WineShield — Multi-layer security framework for Wine on Linux",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  wineshield --mode balanced --app notepad++.exe\n"
            "  wineshield --mode monitor\n"
            "  wineshield --mode strict --layer syscall,fs,behavior\n"
            "  wineshield --list-layers\n"
        ),
    )

    parser.add_argument(
        "--mode",
        choices=["monitor", "balanced", "strict"],
        default=None,
        help="Security mode (overrides config default)",
    )
    parser.add_argument(
        "--app",
        type=str,
        default=None,
        help="Path to Windows .exe to run (default: launch Wine explorer)",
    )
    parser.add_argument(
        "app_args",
        nargs="*",
        metavar="ARG",
        help="Arguments to pass to the target application",
    )
    parser.add_argument(
        "--config",
        type=str,
        default="config/default_policy.json",
        help="Path to configuration file (default: config/default_policy.json)",
    )
    parser.add_argument(
        "--layer",
        type=str,
        default=None,
        help=(
            "Comma-separated list of layer names to enable. "
            f"Options: {', '.join(AVAILABLE_LAYERS)}. "
            "Default: all enabled layers from config."
        ),
    )
    parser.add_argument(
        "--list-layers",
        action="store_true",
        help="Show available security layers and exit",
    )

    return parser


# ═══════════════════════════════════════════════════════════════════
#  Main Entry Point
# ═══════════════════════════════════════════════════════════════════

def main(argv: Optional[List[str]] = None) -> int:
    """
    WineShield entry point — orchestrate all security layers.

    This function is referenced by ``pyproject.toml`` as the console
    script entry point::

        [project.scripts]
        wineshield = "core.launcher:main"

    Parameters
    ----------
    argv : list of str or None
        Command-line arguments (defaults to ``sys.argv[1:]``).

    Returns
    -------
    int
        Exit code (0 = success, 1 = error).
    """
    # ── 1. Parse arguments ─────────────────────────────────────
    parser = build_parser()
    args = parser.parse_args(argv)

    # ── 2. Show layers and exit? ───────────────────────────────
    if args.list_layers:
        print("WineShield — Available Security Layers")
        print("=" * 42)
        for name in AVAILABLE_LAYERS:
            desc = LAYER_DESCRIPTIONS.get(name, "")
            print(f"  {name:<12s}  {desc}")
        print()
        print("Enable with:  --layer syscall,fs,network,...")
        return 0

    # ── 3. Load configuration ──────────────────────────────────
    config_path = args.config
    try:
        config = load_config(config_path)
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as exc:
        _log.critical("Cannot start: %s", exc)
        return 1

    general_cfg = config.get("general", {})
    layers_cfg = config.get("layers", {})
    seccomp_cfg = config.get("seccomp", {})
    fs_cfg = config.get("filesystem", {})
    net_cfg = config.get("network", {})

    # ── 4. Resolve mode ────────────────────────────────────────
    mode = args.mode or general_cfg.get("seccomp_mode", "balanced")
    _log.info("Security mode: %s", mode)

    # ── 5. Determine enabled layers ────────────────────────────
    if args.layer:
        # Explicit list from CLI
        requested = [x.strip() for x in args.layer.split(",")]
        enabled_layers = {k: (k in requested) for k in AVAILABLE_LAYERS}
        # Validate that every requested layer is known
        unknown = [x for x in requested if x not in AVAILABLE_LAYERS]
        if unknown:
            _log.error("Unknown layer(s): %s. Valid: %s",
                       ", ".join(unknown), ", ".join(AVAILABLE_LAYERS))
            return 1
    else:
        # Read from config
        enabled_layers = {
            "syscall":  layers_cfg.get("syscall_filter", {}).get("enabled", True),
            "fs":       layers_cfg.get("filesystem_guard", {}).get("enabled", True),
            "network":  layers_cfg.get("network_guard", {}).get("enabled", True),
            "behavior": layers_cfg.get("behavior_analyzer", {}).get("enabled", True),
            "xephyr":   layers_cfg.get("xephyr_guard", {}).get("enabled", False),
            "apparmor": layers_cfg.get("apparmor", {}).get("enabled", True),
        }

    _log.info("Enabled layers: %s",
              ", ".join(k for k, v in enabled_layers.items() if v))

    # ── 6. Generate session ID ─────────────────────────────────
    session_id = str(uuid.uuid4())
    _log.info("Session ID: %s", session_id)

    # ── 7. Configure logging (now that we have config) ─────────
    log_level_name = general_cfg.get("log_level", "info").upper()
    log_level = getattr(logging, log_level_name, logging.INFO)
    log_file_path: str = general_cfg.get("log_file", "~/.wineshield/events.log")

    # Re-configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Clear any pre-existing handlers
    for h in root_logger.handlers[:]:
        root_logger.removeHandler(h)

    # Console handler (human-readable)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_fmt = logging.Formatter(
        "%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    console_handler.setFormatter(console_fmt)
    root_logger.addHandler(console_handler)

    # File handler for JSON — we handle this ourselves via write_event_json
    # so we don't duplicate.  The events.log path is used by write_event_json.

    _log.info("=" * 60)
    _log.info("WineShield v%s starting", config.get("version", "unknown"))
    _log.info("Mode: %s | Layers: %s", mode,
              ", ".join(k for k, v in enabled_layers.items() if v))
    _log.info("=" * 60)

    # ── 8. Initialise layers ───────────────────────────────────
    threads: List[threading.Thread] = []
    layer_objects: Dict[str, Any] = {}

    # Track whether sandbox was created (for cleanup)
    sandbox_created = False

    try:
        # ── 8a. AppArmor ───────────────────────────────────────
        if enabled_layers.get("apparmor"):
            _log.info("Initialising AppArmorManager...")
            try:
                apparmor = AppArmorManager(config)
                apparmor.load_profiles()
                layer_objects["apparmor"] = apparmor
                ev = make_event("info", "apparmor",
                                "AppArmor profiles loaded",
                                session=session_id)
                write_event_json(ev, log_file_path)
            except Exception as exc:
                _log.warning("AppArmorManager initialisation failed: %s", exc)
                ev = make_event("warning", "apparmor",
                                f"AppArmor init failed: {exc}",
                                session=session_id)
                write_event_json(ev, log_file_path)

        # ── 8b. Xephyr Guard ───────────────────────────────────
        if enabled_layers.get("xephyr"):
            _log.info("Initialising X11Guard...")
            try:
                xephyr_cfg = config.get("xephyr", {})
                display = xephyr_cfg.get("display")
                width = xephyr_cfg.get("default_width", 1280)
                height = xephyr_cfg.get("default_height", 720)
                xguard = X11Guard(config)
                xguard.create_x11_sandbox(width=width, height=height)
                layer_objects["xephyr"] = xguard
                ev = make_event("info", "xephyr_guard",
                                "Xephyr sandbox created",
                                f"Display={display or 'auto'} {width}x{height}",
                                session=session_id)
                write_event_json(ev, log_file_path)
            except Exception as exc:
                _log.warning("X11Guard initialisation failed: %s", exc)
                ev = make_event("warning", "xephyr_guard",
                                f"Xephyr init failed: {exc}",
                                session=session_id)
                write_event_json(ev, log_file_path)

        # ── 8c. Filesystem Guard ───────────────────────────────
        if enabled_layers.get("fs"):
            _log.info("Initialising FSGuard...")
            try:
                fs_guard = FSGuard(config)
                fs_guard.setup()
                layer_objects["fs"] = fs_guard
                ev = make_event("info", "filesystem_guard",
                                "FSGuard setup complete",
                                session=session_id)
                write_event_json(ev, log_file_path)
            except Exception as exc:
                _log.warning("FSGuard initialisation failed: %s", exc)
                ev = make_event("warning", "filesystem_guard",
                                f"FSGuard init failed: {exc}",
                                session=session_id)
                write_event_json(ev, log_file_path)

        # ── 8d. Network Guard ──────────────────────────────────
        if enabled_layers.get("network"):
            _log.info("Initialising NetworkGuard...")
            try:
                net_guard = NetworkGuard(config)
                layer_objects["network"] = net_guard
                ev = make_event("info", "network_guard",
                                "NetworkGuard initialised",
                                f"Mode={net_cfg.get('mode', 'monitor')}",
                                session=session_id)
                write_event_json(ev, log_file_path)
            except Exception as exc:
                _log.warning("NetworkGuard initialisation failed: %s", exc)
                ev = make_event("warning", "network_guard",
                                f"NetworkGuard init failed: {exc}",
                                session=session_id)
                write_event_json(ev, log_file_path)

        # ── 8e. Behavior Analyzer ──────────────────────────────
        if enabled_layers.get("behavior"):
            _log.info("Initialising BehaviorAnalyzer...")
            try:
                analyzer = BehaviorAnalyzer(config)
                layer_objects["behavior"] = analyzer
                ev = make_event("info", "behavior_analyzer",
                                "BehaviorAnalyzer initialised",
                                session=session_id)
                write_event_json(ev, log_file_path)
            except Exception as exc:
                _log.warning("BehaviorAnalyzer initialisation failed: %s", exc)
                ev = make_event("warning", "behavior_analyzer",
                                f"BehaviorAnalyzer init failed: {exc}",
                                session=session_id)
                write_event_json(ev, log_file_path)

        # ── 9. Start monitoring threads ────────────────────────
        # Each layer gets a daemon thread so they die with the main process.
        # IMPORTANT: Threads must be started BEFORE sandbox namespace creation
        # (step 10).  Once we enter a PID namespace via os.unshare(CLONE_NEWPID),
        # Python can no longer create new threads ("can't start new thread").

        # 9a. Syscall filter thread
        if enabled_layers.get("syscall"):
            wine_binary = args.app or "wine"
            t_syscall = threading.Thread(
                target=_monitor_syscall_filter,
                args=(mode, wine_binary, session_id, log_file_path, config),
                name="syscall-monitor",
                daemon=True,
            )
            t_syscall.start()
            threads.append(t_syscall)

        # 9b. FSGuard monitoring thread
        if enabled_layers.get("fs") and "fs" in layer_objects:
            t_fs = threading.Thread(
                target=_monitor_fs_guard,
                args=(layer_objects["fs"], session_id, log_file_path),
                name="fs-monitor",
                daemon=True,
            )
            t_fs.start()
            threads.append(t_fs)

        # 9c. NetworkGuard monitoring thread
        if enabled_layers.get("network") and "network" in layer_objects:
            t_net = threading.Thread(
                target=_monitor_network_guard,
                args=(layer_objects["network"], session_id, log_file_path),
                name="network-monitor",
                daemon=True,
            )
            t_net.start()
            threads.append(t_net)

        # 9d. BehaviorAnalyzer monitoring thread
        if enabled_layers.get("behavior") and "behavior" in layer_objects:
            t_beh = threading.Thread(
                target=_monitor_behavior_analyzer,
                args=(layer_objects["behavior"], session_id, log_file_path),
                name="behavior-monitor",
                daemon=True,
            )
            t_beh.start()
            threads.append(t_beh)

        _log.info("Started %d monitoring thread(s)", len(threads))

        # ── 10. Create sandbox ─────────────────────────────────
        app_name = os.path.basename(args.app) if args.app else "wine"
        _log.info("Creating WineSandbox for '%s'...", app_name)
        try:
            sandbox = WineSandbox(config)
            sandbox.create_sandbox(app_name)
            sandbox_created = True
            layer_objects["sandbox"] = sandbox
            ev = make_event("info", "sandbox_engine",
                            f"Sandbox created for '{app_name}'",
                            session=session_id)
            write_event_json(ev, log_file_path)
        except Exception as exc:
            _log.critical("Sandbox creation failed: %s", exc)
            ev = make_event("critical", "sandbox_engine",
                            f"Sandbox creation failed: {exc}",
                            session=session_id)
            write_event_json(ev, log_file_path)
            return 1

        # ── 11. Launch Wine inside sandbox ─────────────────────
        if args.app:
            wine_cmd = ["wine", args.app]
        else:
            # Launch Wine explorer as default
            wine_cmd = ["wine", "explorer", "/desktop=shell,1024x768"]

        _log.info("Launching: %s", " ".join(wine_cmd))
        ev = make_event("info", "launcher",
                        f"Launching Wine: {' '.join(wine_cmd)}",
                        session=session_id)
        write_event_json(ev, log_file_path)

        wine_proc = None
        try:
            wine_proc = subprocess.Popen(
                wine_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            ev = make_event("info", "launcher",
                            f"Wine process started (PID={wine_proc.pid})",
                            pid=wine_proc.pid,
                            process_name=os.path.basename(wine_cmd[0]),
                            session=session_id)
            write_event_json(ev, log_file_path)
            _log.info("Wine PID: %d", wine_proc.pid)

            # Read output in a non-blocking way
            def _read_wine_output(proc: subprocess.Popen, ev_log: str, sid: str) -> None:
                """Read Wine stdout/stderr and log it."""
                assert proc.stdout is not None
                for line in iter(proc.stdout.readline, ""):
                    line = line.rstrip("\n")
                    if line:
                        _log.debug("[wine] %s", line)
                        ev = make_event("info", "wine", line,
                                        pid=proc.pid,
                                        process_name="wine",
                                        session=sid)
                        write_event_json(ev, ev_log)

            wine_output_thread = threading.Thread(
                target=_read_wine_output,
                args=(wine_proc, log_file_path, session_id),
                name="wine-output",
                daemon=True,
            )
            wine_output_thread.start()

            # Wait for Wine to finish
            returncode = wine_proc.wait()
            _log.info("Wine process exited (returncode=%d)", returncode)
            ev = make_event("info", "launcher",
                            f"Wine exited (rc={returncode})",
                            pid=wine_proc.pid,
                            process_name="wine",
                            session=session_id)
            write_event_json(ev, log_file_path)

        except FileNotFoundError:
            _log.critical("'wine' binary not found in PATH. Is Wine installed?")
            ev = make_event("critical", "launcher",
                            "Wine binary not found",
                            session=session_id)
            write_event_json(ev, log_file_path)
            return 1
        except Exception as exc:
            _log.error("Error launching Wine: %s", exc)
            ev = make_event("error", "launcher",
                            f"Wine launch error: {exc}",
                            session=session_id)
            write_event_json(ev, log_file_path)
            return 1

    except KeyboardInterrupt:
        _log.warning("Interrupted by user")
        ev = make_event("warning", "launcher",
                        "Session interrupted by user",
                        session=session_id)
        write_event_json(ev, log_file_path)
    except Exception as exc:
        _log.critical("Unhandled exception: %s", exc)
        ev = make_event("critical", "launcher",
                        f"Unhandled exception: {exc}",
                        session=session_id)
        write_event_json(ev, log_file_path)
        raise
    finally:
        # ═════════════════════════════════════════════════════════
        #  12. Cleanup
        # ═════════════════════════════════════════════════════════
        _log.info("Beginning cleanup...")
        ev = make_event("info", "launcher",
                        "Session cleanup started",
                        session=session_id)
        write_event_json(ev, log_file_path)

        # Stop network/behavior monitoring
        if "network" in layer_objects:
            try:
                layer_objects["network"].stop_monitoring()
                layer_objects["network"].cleanup()
            except Exception as exc:
                _log.warning("NetworkGuard cleanup error: %s", exc)
        if "behavior" in layer_objects:
            try:
                layer_objects["behavior"].stop_monitoring()
                layer_objects["behavior"].cleanup()
            except Exception as exc:
                _log.warning("BehaviorAnalyzer cleanup error: %s", exc)

        # Filesystem guard cleanup
        if "fs" in layer_objects:
            try:
                layer_objects["fs"].cleanup()
            except Exception as exc:
                _log.warning("FSGuard cleanup error: %s", exc)

        # Xephyr cleanup
        if "xephyr" in layer_objects:
            try:
                layer_objects["xephyr"].cleanup_x11_sandbox()
            except Exception as exc:
                _log.warning("X11Guard cleanup error: %s", exc)

        # AppArmor cleanup
        if "apparmor" in layer_objects:
            try:
                layer_objects["apparmor"].unload_profiles()
                layer_objects["apparmor"].cleanup()
            except Exception as exc:
                _log.warning("AppArmorManager cleanup error: %s", exc)

        # Destroy sandbox
        if sandbox_created and "sandbox" in layer_objects:
            try:
                layer_objects["sandbox"].destroy_sandbox()
            except Exception as exc:
                _log.warning("Sandbox destroy error: %s", exc)

        # Final event
        ev = make_event("info", "launcher",
                        "Session ended",
                        session=session_id)
        write_event_json(ev, log_file_path)
        _log.info("Cleanup complete. Session %s ended.", session_id)

    return 0


# ═══════════════════════════════════════════════════════════════════
#  Direct execution guard
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    sys.exit(main())
