#!/usr/bin/env python3
"""
benchmark_base.py — Shared measurement infrastructure for WineShield benchmarks.

All three benchmark scripts (cpu_benchmark.py, latency_benchmark.py,
memory_benchmark.py) import common logic from this module so that
measurement protocols, configuration definitions, and reporting are
consistent across the suite.

Usage
-----
    from benchmarks.benchmark_base import (
        CONFIGURATIONS, WINE_NOTEPADPP, WINE_NOTEPAD,
        run_single, compute_stats, ReportWriter, is_wsl,
        verify_wine_prefix,
    )
"""

from __future__ import annotations

import json
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ═══════════════════════════════════════════════════════════════════
#  Constants & Paths
# ═══════════════════════════════════════════════════════════════════

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Wine executable paths
WINE = shutil.which("wine") or "/usr/bin/wine"

# Prefer Notepad++ if installed in the Wine prefix; fall back to Wine built-in notepad
_NOTEPADPP = (
    Path.home()
    / ".wine"
    / "drive_c"
    / "Program Files"
    / "Notepad++"
    / "notepad++.exe"
)
WINE_NOTEPADPP = str(_NOTEPADPP) if _NOTEPADPP.exists() else None
WINE_NOTEPAD = "notepad"  # built-in Wine notepad

# Determine the target application
if WINE_NOTEPADPP:
    TARGET_APP = WINE_NOTEPADPP
    TARGET_NAME = "Notepad++"
else:
    TARGET_APP = WINE_NOTEPAD
    TARGET_NAME = "Wine notepad (built-in)"

# Syscall monitor binary
SYSCALL_MONITOR = str(PROJECT_ROOT / "core" / "syscall_monitor")

# Launcher module
LAUNCHER_MODULE = "core.launcher"


# ═══════════════════════════════════════════════════════════════════
#  WSL Detection
# ═══════════════════════════════════════════════════════════════════

def is_wsl() -> bool:
    """Return True if running inside Windows Subsystem for Linux."""
    try:
        with open("/proc/version", "r") as f:
            return "microsoft" in f.read().lower() or "wsl" in f.read().lower()
    except OSError:
        return False


def verify_wine_prefix() -> Optional[str]:
    """Verify the Wine prefix is usable.  Returns None on success, or an
    error message string on failure."""
    try:
        result = subprocess.run(
            [WINE, "--version"],
            capture_output=True,
            text=True,
            timeout=15,
            env={**os.environ, "WINEDEBUG": "-all"},
        )
        if result.returncode != 0:
            return f"wine --version failed (rc={result.returncode}): {result.stderr.strip()}"
        return None
    except FileNotFoundError:
        return "wine binary not found"
    except subprocess.TimeoutExpired:
        return "wine --version timed out (possible WINEPREFIX issue)"
    except Exception as exc:
        return f"unexpected error: {exc}"


# ═══════════════════════════════════════════════════════════════════
#  Configuration Definitions
# ═══════════════════════════════════════════════════════════════════
#
# Each configuration is a dict with:
#   name        — short label (used in output tables)
#   description— human-readable explanation
#   command    — list-of-strings command to run under /usr/bin/time -v
#   layers     — which WineShield layers are active
#   skip_on_wsl— if True, this config will NOT be executed on WSL
#                (because sandbox features are known to fail there)

CONFIGURATIONS: List[Dict[str, Any]] = [
    {
        "name": "baseline",
        "description": "Wine without WineShield (no security layers)",
        "layers": [],
        "skip_on_wsl": False,
        "command": [
            WINE,
            TARGET_APP,
        ],
    },
    {
        "name": "seccomp_only",
        "description": "Syscall monitor (seccomp-BPF) only",
        "layers": ["seccomp"],
        "skip_on_wsl": False,
        # Must run as root (via sudo) for seccomp.  sudo resets HOME to
        # /root by default, so we explicitly pass WINEPREFIX to make sure
        # Wine uses the user's prefix directory.
        "command": [
            "sudo",
            f"WINEPREFIX={os.environ.get('WINEPREFIX', os.path.expanduser('~/.wine'))}",
            SYSCALL_MONITOR,
            "--mode",
            "monitor",
            "--user",
            os.environ.get("USER", "unknown"),
            "--",
            WINE,
            TARGET_APP,
        ],
    },
    {
        "name": "network_guard",
        "description": "Network Guard layer only",
        "layers": ["network"],
        "skip_on_wsl": True,  # namespace ops fail on WSL
        "command": [
            sys.executable,
            "-m",
            LAUNCHER_MODULE,
            "--mode",
            "monitor",
            "--layer",
            "network",
            "--app",
            WINE,
            TARGET_APP,
        ],
    },
    {
        "name": "behavior_analyzer",
        "description": "Behavior Analyzer layer only",
        "layers": ["behavior"],
        "skip_on_wsl": True,  # may need ptrace/perf which fail on WSL
        "command": [
            sys.executable,
            "-m",
            LAUNCHER_MODULE,
            "--mode",
            "monitor",
            "--layer",
            "behavior",
            "--app",
            WINE,
            TARGET_APP,
        ],
    },
    {
        "name": "all_layers",
        "description": "Full WineShield stack (all layers enabled)",
        "layers": ["seccomp", "network", "behavior"],
        "skip_on_wsl": True,
        "command": [
            sys.executable,
            "-m",
            LAUNCHER_MODULE,
            "--mode",
            "balanced",
            "--app",
            WINE,
            TARGET_APP,
        ],
    },
]


# ═══════════════════════════════════════════════════════════════════
#  Time parsing
# ═══════════════════════════════════════════════════════════════════

# Patterns for /usr/bin/time -v output
_RE_WALL_CLOCK = re.compile(
    r"Elapsed \(wall clock\) time \(h:mm:ss or m:ss\):\s*(\S+)"
)
_RE_USER_TIME = re.compile(r"User time \(seconds\):\s*([\d.]+)")
_RE_SYSTEM_TIME = re.compile(r"System time \(seconds\):\s*([\d.]+)")
_RE_CPU_PCT = re.compile(r"Percent of CPU this job got:\s*(\d+)%")
_RE_MAX_RSS = re.compile(r"Maximum resident set size \(kbytes\):\s*(\d+)")
_RE_MINOR_FLT = re.compile(r"Minor \(reclaiming a frame\) page faults:\s*(\d+)")
_RE_MAJOR_FLT = re.compile(r"Major \(requiring I/O\) page faults:\s*(\d+)")
_RE_VOL_CTX = re.compile(r"Voluntary context switches:\s*(\d+)")
_RE_INVOL_CTX = re.compile(r"Involuntary context switches:\s*(\d+)")
_RE_EXIT_STATUS = re.compile(r"Command exited with status:\s*(-?\d+)")


def _parse_hms(hms: str) -> float:
    """Convert h:mm:ss or m:ss to seconds float."""
    parts = hms.strip().split(":")
    if len(parts) == 3:
        # h:mm:ss
        return int(parts[0]) * 3600 + int(parts[1]) * 60 + float(parts[2])
    elif len(parts) == 2:
        # m:ss
        return int(parts[0]) * 60 + float(parts[1])
    else:
        return float(parts[0])


def parse_time_output(stderr_text: str) -> Dict[str, Any]:
    """Parse /usr/bin/time -v stderr output into a structured dict.

    Returns a dict with keys:
        wall_clock_sec, user_time_sec, system_time_sec,
        cpu_percent, max_rss_kb, minor_faults, major_faults,
        vol_context_switches, invol_context_switches,
        exit_status, raw (full stderr text)
    """
    result: Dict[str, Any] = {
        "wall_clock_sec": None,
        "user_time_sec": None,
        "system_time_sec": None,
        "cpu_percent": None,
        "max_rss_kb": None,
        "minor_faults": None,
        "major_faults": None,
        "vol_context_switches": None,
        "invol_context_switches": None,
        "exit_status": None,
        "error": None,
        "raw": stderr_text,
    }

    if not stderr_text:
        result["error"] = "No output from /usr/bin/time"
        return result

    m = _RE_WALL_CLOCK.search(stderr_text)
    if m:
        try:
            result["wall_clock_sec"] = _parse_hms(m.group(1))
        except (ValueError, IndexError):
            pass

    m = _RE_USER_TIME.search(stderr_text)
    if m:
        result["user_time_sec"] = float(m.group(1))

    m = _RE_SYSTEM_TIME.search(stderr_text)
    if m:
        result["system_time_sec"] = float(m.group(1))

    m = _RE_CPU_PCT.search(stderr_text)
    if m:
        result["cpu_percent"] = int(m.group(1))

    m = _RE_MAX_RSS.search(stderr_text)
    if m:
        result["max_rss_kb"] = int(m.group(1))

    m = _RE_MINOR_FLT.search(stderr_text)
    if m:
        result["minor_faults"] = int(m.group(1))

    m = _RE_MAJOR_FLT.search(stderr_text)
    if m:
        result["major_faults"] = int(m.group(1))

    m = _RE_VOL_CTX.search(stderr_text)
    if m:
        result["vol_context_switches"] = int(m.group(1))

    m = _RE_INVOL_CTX.search(stderr_text)
    if m:
        result["invol_context_switches"] = int(m.group(1))

    m = _RE_EXIT_STATUS.search(stderr_text)
    if m:
        result["exit_status"] = int(m.group(1))

    # Detect well-known failure modes in the raw output
    lower = stderr_text.lower()
    if "sandbox failed" in lower or "enomem" in lower or "einval" in lower:
        result["error"] = "Sandbox failure (expected on WSL — needs real Linux kernel)"
    elif "permission denied" in lower or "operation not permitted" in lower:
        if result["error"] is None:
            result["error"] = "Permission denied (may need sudo or kernel support)"

    return result


# ═══════════════════════════════════════════════════════════════════
#  Single Measurement Runner
# ═══════════════════════════════════════════════════════════════════

def run_single(
    config: Dict[str, Any],
    runtime_seconds: int = 12,
    xvfb_display: Optional[str] = None,
) -> Dict[str, Any]:
    """Run a single benchmark measurement for the given configuration.

    Parameters
    ----------
    config : dict
        One entry from CONFIGURATIONS.
    runtime_seconds : int
        How long (in seconds) to let the Wine app run before
        ``timeout`` terminates it.
    xvfb_display : str or None
        DISPLAY to use (e.g. ":99").  If None, inherits the current
        environment DISPLAY.

    Returns
    -------
    dict
        Merged result: the parsed ``/usr/bin/time -v`` stats plus
        metadata about the configuration and run.
    """
    inner_command = config["command"]
    name = config["name"]

    env = os.environ.copy()
    env["WINEDEBUG"] = "-all"  # suppress Wine debug spew
    if xvfb_display:
        env["DISPLAY"] = xvfb_display

    # Structure:
    #   /usr/bin/time -v timeout <runtime_seconds> <inner_command>
    #
    # ``timeout`` sends SIGTERM to the inner command after the specified
    # duration.  ``/usr/bin/time -v`` then sees the child exit normally
    # (with exit code 124 from ``timeout``) and writes its report to
    # stderr — no output is lost.
    timeout_bin = shutil.which("timeout")
    if timeout_bin:
        time_cmd = ["/usr/bin/time", "-v", timeout_bin, str(runtime_seconds)] + inner_command
    else:
        # If timeout(1) is not available (rare), fall back to the
        # subprocess-native approach with process-group kill
        time_cmd = ["/usr/bin/time", "-v"] + inner_command

    start_time = time.monotonic()

    try:
        proc = subprocess.Popen(
            time_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )

        try:
            stdout_data, stderr_data = proc.communicate(timeout=runtime_seconds + 10)
        except subprocess.TimeoutExpired:
            # Last-resort cleanup (should not normally trigger because
            # ``timeout`` handles the lifecycle)
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                pgid = os.getpgid(proc.pid)
                if pgid:
                    os.killpg(pgid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass
            try:
                stdout_data, stderr_data = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                stdout_data = ""
                stderr_data = ""
                try:
                    proc.kill()
                    proc.wait(timeout=3)
                except Exception:
                    pass

    except FileNotFoundError as exc:
        return {
            "config_name": name,
            "error": f"Command not found: {exc}",
            "wall_clock_sec": None,
            "cpu_percent": None,
            "max_rss_kb": None,
        }
    except Exception as exc:
        return {
            "config_name": name,
            "error": f"Unexpected execution error: {exc}",
            "wall_clock_sec": None,
            "cpu_percent": None,
            "max_rss_kb": None,
        }

    elapsed = time.monotonic() - start_time

    # Parse the time output (stderr contains the time -v report)
    parsed = parse_time_output(stderr_data)

    # Merge in metadata
    result: Dict[str, Any] = {
        "config_name": name,
        "config_description": config.get("description", ""),
        "layers": config.get("layers", []),
        "run_duration_sec": round(elapsed, 3),
        "target_app": TARGET_APP,
        "target_name": TARGET_NAME,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **parsed,
    }

    # If the parsed output has no wall_clock_sec but we got stdout,
    # /usr/bin/time probably failed silently.  Try to detect that.
    if (
        result.get("wall_clock_sec") is None
        and result.get("error") is None
        and stderr_data.strip()
    ):
        # Check if the entire stderr looks like time output (should contain
        # "Command being timed") or if it's a different error
        if "Command being timed" not in stderr_data and "Exit status" not in stderr_data:
            result["error"] = (
                "/usr/bin/time -v did not produce expected output. "
                "The command may have failed before /usr/bin/time could measure it."
            )
            # Still include the raw stderr for debugging
            result["stderr_hint"] = stderr_data[:500]

    return result


# ═══════════════════════════════════════════════════════════════════
#  Statistics Helpers
# ═══════════════════════════════════════════════════════════════════

def compute_stats(values: List[Optional[float]]) -> Dict[str, Any]:
    """Compute mean, stddev, min, max from a list of numbers (None entries
    are filtered out)."""
    filtered = [v for v in values if v is not None]
    n = len(filtered)
    if n == 0:
        return {"n": 0, "mean": None, "stddev": None, "min": None, "max": None}

    mean = sum(filtered) / n
    if n >= 2:
        variance = sum((x - mean) ** 2 for x in filtered) / (n - 1)
        stddev = math.sqrt(variance)
    else:
        stddev = 0.0

    return {
        "n": n,
        "mean": round(mean, 3),
        "stddev": round(stddev, 3),
        "min": round(min(filtered), 3),
        "max": round(max(filtered), 3),
    }


# ═══════════════════════════════════════════════════════════════════
#  Report Writer
# ═══════════════════════════════════════════════════════════════════

class ReportWriter:
    """Collects per-config measurements and produces summary output."""

    def __init__(
        self,
        metric_name: str,
        metric_unit: str,
        description: str,
    ):
        self.metric_name = metric_name
        self.metric_unit = metric_unit
        self.description = description
        self.results: Dict[str, List[Dict[str, Any]]] = {}
        self.errors: Dict[str, List[str]] = {}

    def add_result(self, config_name: str, measurement: Dict[str, Any]) -> None:
        """Record one measurement run."""
        self.results.setdefault(config_name, []).append(measurement)
        if measurement.get("error"):
            self.errors.setdefault(config_name, []).append(measurement["error"])

    def get_values(self, config_name: str) -> List[Optional[float]]:
        """Extract numeric values for the metric from all runs of a config."""
        runs = self.results.get(config_name, [])
        values = []
        for r in runs:
            val = r.get(self.metric_key())
            values.append(val)
        return values

    def metric_key(self) -> str:
        """Map user-facing metric name to the dict key in parsed output."""
        mapping = {
            "CPU Usage": "cpu_percent",
            "Wall Clock": "wall_clock_sec",
            "Memory (RSS)": "max_rss_kb",
        }
        return mapping.get(self.metric_name, self.metric_name.lower().replace(" ", "_"))

    def summary_table(self) -> List[Dict[str, Any]]:
        """Build a list of per-config summary dicts for printing."""
        rows = []
        for cfg in CONFIGURATIONS:
            name = cfg["name"]
            values = self.get_values(name)
            stats = compute_stats(values)
            error_list = self.errors.get(name, [])
            row = {
                "config": name,
                "description": cfg["description"],
                "layers": ", ".join(cfg["layers"]) or "none",
                "n": stats["n"],
                "mean": stats["mean"],
                "stddev": stats["stddev"],
                "min": stats["min"],
                "max": stats["max"],
                "errors": error_list,
            }
            rows.append(row)
        return rows

    def print_text(self, file=sys.stdout) -> None:
        """Print a human-readable summary table to *file*."""
        rows = self.summary_table()
        print("=" * 88, file=file)
        print(f"  WineShield Benchmark — {self.metric_name}", file=file)
        print(f"  {self.description}", file=file)
        print(f"  Target: {TARGET_NAME} ({TARGET_APP})", file=file)
        print(f"  Date:   {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", file=file)
        print("=" * 88, file=file)
        print("", file=file)

        if is_wsl():
            print("  ⚠  Running on WSL — sandbox features are expected to fail.", file=file)
            print("     Results for seccomp_only / network_guard / behavior_analyzer /", file=file)
            print("     all_layers will show errors.  This is normal.", file=file)
            print("", file=file)

        # Header
        print(
            f"  {'Config':<22} {'Runs':>4} {'Mean':>10} {'StdDev':>10} "
            f"{'Min':>10} {'Max':>10}  Errors",
            file=file,
        )
        print("  " + "-" * 80, file=file)

        for row in rows:
            mean_str = f"{row['mean']:.2f} {self.metric_unit}" if row["mean"] is not None else "  N/A"
            std_str = f"{row['stddev']:.2f}" if row["stddev"] is not None else " N/A"
            min_str = f"{row['min']:.2f}" if row["min"] is not None else " N/A"
            max_str = f"{row['max']:.2f}" if row["max"] is not None else " N/A"
            err_str = "; ".join(row["errors"][:2])
            if len(row["errors"]) > 2:
                err_str += f" ({len(row['errors'])} total)"
            print(
                f"  {row['config']:<22} {row['n']:>4} {mean_str:>10} {std_str:>10} "
                f"{min_str:>10} {max_str:>10}  {err_str}",
                file=file,
            )

        print("", file=file)
        print("  Note: 'N/A' means all runs for that configuration failed.", file=file)
        print("=" * 88, file=file)
        file.flush()

    def to_json(self) -> str:
        """Return JSON string of the full results."""
        rows = self.summary_table()
        package = {
            "benchmark": self.metric_name,
            "description": self.description,
            "metric_unit": self.metric_unit,
            "target_app": TARGET_NAME,
            "target_path": TARGET_APP,
            "wsl": is_wsl(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "configurations": [
                {
                    "name": cfg["name"],
                    "description": cfg["description"],
                    "layers": cfg["layers"],
                }
                for cfg in CONFIGURATIONS
            ],
            "results": rows,
            "raw_runs": {
                cn: [r for r in runs]
                for cn, runs in self.results.items()
            },
        }
        return json.dumps(package, indent=2, default=str)

    def save_json(self, path: str) -> str:
        """Write JSON report to *path* and return the path."""
        data = self.to_json()
        with open(path, "w") as f:
            f.write(data)
        print(f"  [report] JSON saved → {path}")
        return path


# ═══════════════════════════════════════════════════════════════════
#  Xvfb Helper
# ═══════════════════════════════════════════════════════════════════

_XVFB_PROC: Optional[subprocess.Popen] = None


def start_xvfb(display: str = ":99") -> Optional[str]:
    """Start a virtual X server (Xvfb) on *display*.

    Returns the display string on success, or None if Xvfb is not
    available or fails to start.
    """
    global _XVFB_PROC

    if _XVFB_PROC is not None:
        return display  # already running

    xvfb_bin = shutil.which("Xvfb")
    if not xvfb_bin:
        print("  [warn] Xvfb not found — using system DISPLAY", file=sys.stderr)
        return os.environ.get("DISPLAY")

    try:
        _XVFB_PROC = subprocess.Popen(
            [xvfb_bin, display, "-screen", "0", "1024x768x16"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Wait a moment for Xvfb to be ready
        time.sleep(0.8)
        # Quick health check
        if _XVFB_PROC.poll() is not None:
            print(
                f"  [warn] Xvfb exited immediately (rc={_XVFB_PROC.returncode})",
                file=sys.stderr,
            )
            _XVFB_PROC = None
            return os.environ.get("DISPLAY")
        return display
    except OSError as exc:
        print(f"  [warn] Could not start Xvfb: {exc}", file=sys.stderr)
        return os.environ.get("DISPLAY")


def stop_xvfb() -> None:
    """Stop the Xvfb server if we started one."""
    global _XVFB_PROC
    if _XVFB_PROC is not None:
        try:
            _XVFB_PROC.terminate()
            _XVFB_PROC.wait(timeout=3)
        except Exception:
            try:
                _XVFB_PROC.kill()
            except Exception:
                pass
        _XVFB_PROC = None
