#!/usr/bin/env python3
"""
WineShield — Malware Simulation Scripts

VALIDATION TOOLS — NOT MALWARE.

These scripts simulate the *behaviour* of real malware families to
test WineShield's detection capabilities.  They are **safety-designed**:

* Ransomware simulator: creates files ONLY in ``/tmp/wineshield_test/``
  and cleans up all created files at the end.
* Keylogger simulator: attempts read-only access to ``/dev/input/event*``
  with a hard 3-second timeout.  Handles permission errors gracefully.
* Network backdoor simulator: connects to PUBLIC websites only
  (google.com, example.com, etc.) with 2-second timeouts.

All three are intended to trigger specific WineShield detection layers
when run inside a sandbox.

Run a single simulation::

    python -c "from tests.test_simulations import simulate_ransomware; simulate_ransomware()"

Run all simulations sequentially::

    python tests/test_simulations.py
"""

from __future__ import annotations

import os
import select
import socket
import struct
import time
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════
#  Constants
# ═══════════════════════════════════════════════════════════════════

TEST_DIR = Path("/tmp/wineshield_test")
RANSOMWARE_FILE_COUNT = 120
RANSOMWARE_TIME_LIMIT = 2.0  # seconds
KEYLOGGER_DURATION = 3  # seconds
NETWORK_TIMEOUT = 2  # seconds per connection

NETWORK_TARGETS = [
    ("google.com", 80),
    ("example.com", 80),
    ("bing.com", 80),
    ("github.com", 80),
    ("stackoverflow.com", 80),
]


# ═══════════════════════════════════════════════════════════════════
#  Simulation helpers
# ═══════════════════════════════════════════════════════════════════

def _garbage_data(size: int = 4096) -> bytes:
    """Generate ``size`` bytes of pseudo-random garbage (fast)."""
    # Use a simple repeating pattern — faster than os.urandom for testing
    import hashlib
    seed = b"WineShield_test_garbage_2025"
    result = bytearray()
    while len(result) < size:
        result.extend(hashlib.sha256(seed + bytes([len(result) & 0xFF])).digest())
    return bytes(result[:size])


# ═══════════════════════════════════════════════════════════════════
#  a) Ransomware Simulator
# ═══════════════════════════════════════════════════════════════════

def simulate_ransomware(
    file_count: int = RANSOMWARE_FILE_COUNT,
    time_limit: float = RANSOMWARE_TIME_LIMIT,
    target_dir: str | Path | None = None,
) -> int:
    """
    Simulate ransomware behaviour by rapidly creating many files.

    Creates ``file_count`` ``.encrypted`` files in ``target_dir``
    (default: ``/tmp/wineshield_test/``) within ``time_limit`` seconds,
    writes garbage data to each, and cleans up afterwards.

    This is designed to trigger the ``ransomware_file_flood`` rate rule
    in WineShield's behavior analyzer (threshold: 50 files/second).

    Parameters
    ----------
    file_count : int
        Number of files to create (default: 120).
    time_limit : float
        Maximum time allowed for file creation in seconds (default: 2.0).
    target_dir : str or Path, optional
        Directory to create files in (default: ``/tmp/wineshield_test/``).

    Returns
    -------
    int
        The number of files successfully created.

    Raises
    ------
    RuntimeError
        If the target directory cannot be created.
    """
    target = Path(target_dir) if target_dir else TEST_DIR
    target = target.resolve()

    print("=" * 60)
    print("  WineShield — Ransomware Simulator")
    print("=" * 60)
    print(f"  Target:        {target}")
    print(f"  File count:    {file_count}")
    print(f"  Time limit:    {time_limit}s")
    print(f"  Extension:     .encrypted")
    print("-" * 60)

    # Create test directory
    try:
        target.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise RuntimeError(f"Cannot create test directory {target}: {exc}") from exc

    created: list[Path] = []
    start_time = time.time()
    deadline = start_time + time_limit

    try:
        for i in range(file_count):
            if time.time() >= deadline:
                print(f"  ⏰ Time limit reached after {i} files (limit={time_limit}s)")
                break

            file_path = target / f"document_{i:04d}.encrypted"
            try:
                file_path.write_bytes(_garbage_data(4096))
                created.append(file_path)
            except OSError as exc:
                print(f"  ⚠  Error writing {file_path.name}: {exc}")
                continue

            # Print progress every 10 files
            if (i + 1) % 10 == 0:
                elapsed = time.time() - start_time
                print(f"  ✓ Created {i + 1:>4d} files ... ({elapsed:.2f}s)")

    finally:
        elapsed = time.time() - start_time
        rate = len(created) / elapsed if elapsed > 0 else 0
        print(f"\n  Summary:")
        print(f"    Files created: {len(created)} / {file_count}")
        print(f"    Time elapsed:  {elapsed:.2f}s")
        print(f"    Creation rate: {rate:.1f} files/s")

        # Cleanup
        cleanup_count = 0
        for f in created:
            try:
                f.unlink(missing_ok=True)
                cleanup_count += 1
            except OSError:
                pass

        # Remove directory if empty
        try:
            target.rmdir()
        except OSError:
            pass

        print(f"    Files cleaned: {cleanup_count}")
        print()

    return len(created)


# ═══════════════════════════════════════════════════════════════════
#  b) Keylogger Simulator
# ═══════════════════════════════════════════════════════════════════

def simulate_keylogger(duration: float = KEYLOGGER_DURATION) -> int:
    """
    Simulate keylogger behaviour by attempting to read input events.

    Opens ``/dev/input/event*`` devices in read-only mode and polls for
    keyboard events for ``duration`` seconds.  All captured events are
    printed (anonymized — key codes only, no actual key content).

    This is designed to test detection mechanisms that monitor
    ``/dev/input`` access patterns.  The simulation handles permission
    errors gracefully (common when not running as root).

    Parameters
    ----------
    duration : float
        How long to listen for events, in seconds (default: 3).

    Returns
    -------
    int
        Number of input events captured (0 if no access).
    """
    import glob

    print("=" * 60)
    print("  WineShield — Keylogger Simulator")
    print("=" * 60)
    print(f"  Duration:      {duration}s")
    print(f"  Devices:       /dev/input/event*")
    print("-" * 60)

    # Find input event devices
    event_devices = sorted(glob.glob("/dev/input/event*"))

    if not event_devices:
        print("  ⚠  No /dev/input/event* devices found on this system.")
        print("  ℹ   This is normal in containers or WSL without input devices.")
        print()
        return 0

    print(f"  Found {len(event_devices)} event device(s)")

    open_fds: list[int] = []
    events_captured = 0

    try:
        # Attempt to open each device read-only
        for dev_path in event_devices:
            try:
                fd = os.open(dev_path, os.O_RDONLY | os.O_NONBLOCK)
                open_fds.append(fd)
                print(f"  ✓ Opened {dev_path} (fd={fd})")
            except PermissionError:
                print(f"  ⚠  Permission denied: {dev_path} (run as root to capture)")
            except OSError as exc:
                print(f"  ⚠  Cannot open {dev_path}: {exc}")

        if not open_fds:
            print("  ℹ   No input devices accessible. Nothing to capture.")
            print()
            return 0

        print(f"  Listening for {duration}s ...")

        # Poll for events
        INPUT_EVENT_SIZE = struct.calcsize("llHHI")
        deadline = time.time() + duration

        while time.time() < deadline:
            remaining = deadline - time.time()
            if remaining <= 0:
                break

            readable, _, _ = select.select(open_fds, [], [], min(remaining, 0.5))
            if not readable:
                continue

            for fd in readable:
                try:
                    raw = os.read(fd, INPUT_EVENT_SIZE)
                    if len(raw) != INPUT_EVENT_SIZE:
                        continue

                    # Unpack the input_event struct
                    tv_sec, tv_usec, etype, code, value = struct.unpack(
                        "llHHI", raw
                    )

                    # Only report keyboard events (type 1 = EV_KEY)
                    if etype == 1 and value in (1, 2):  # press or repeat
                        events_captured += 1
                        if events_captured <= 5:
                            print(
                                f"    [event] type=KEY code={code} "
                                f"value={'PRESS' if value == 1 else 'REPEAT'}"
                            )
                except (OSError, BlockingIOError):
                    continue

        print(f"\n  Summary:")
        print(f"    Events captured: {events_captured}")
        if events_captured == 0:
            print(f"    ℹ  No keyboard activity detected during the window.")
        print()

    finally:
        for fd in open_fds:
            try:
                os.close(fd)
            except OSError:
                pass

    return events_captured


# ═══════════════════════════════════════════════════════════════════
#  c) Network Backdoor Simulator
# ═══════════════════════════════════════════════════════════════════

def simulate_network_backdoor(
    targets: list[tuple[str, int]] | None = None,
    timeout: float = NETWORK_TIMEOUT,
) -> list[dict]:
    """
    Simulate network backdoor / C2 beaconing behaviour.

    Attempts TCP connections to several external hosts with a short
    timeout per attempt.  Each attempt is logged and the result
    recorded.  All sockets are properly closed.

    This is designed to test WineShield's network guard (connection
    monitoring) and behavior analyzer (beaconing pattern detection).

    Parameters
    ----------
    targets : list of (host, port) tuples, optional
        List of targets to connect to (default: google.com, example.com,
        bing.com, github.com, stackoverflow.com — all port 80).
    timeout : float
        Connection timeout per attempt, in seconds (default: 2).

    Returns
    -------
    list[dict]
        A list of dicts with keys ``target``, ``port``, ``success``,
        and ``error`` for each attempted connection.
    """
    targets = targets or NETWORK_TARGETS

    print("=" * 60)
    print("  WineShield — Network Backdoor Simulator")
    print("=" * 60)
    print(f"  Targets:       {len(targets)} hosts")
    print(f"  Timeout:       {timeout}s per connection")
    print("-" * 60)

    results: list[dict] = []

    for host, port in targets:
        result: dict = {
            "target": host,
            "port": port,
            "success": False,
            "error": None,
        }
        sock: socket.socket | None = None

        try:
            print(f"  → Connecting to {host}:{port} ...", end=" ")

            # Resolve hostname
            try:
                addr = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
                if not addr:
                    result["error"] = "DNS resolution failed"
                    print("DNS FAILED")
                    results.append(result)
                    continue
                ip = addr[0][4][0]
            except socket.gaierror as exc:
                result["error"] = f"DNS error: {exc}"
                print(f"DNS ERROR: {exc}")
                results.append(result)
                continue

            # Create socket and connect
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            connect_start = time.time()
            sock.connect((ip, port))
            elapsed = time.time() - connect_start

            result["success"] = True
            result["ip"] = ip
            result["elapsed"] = round(elapsed, 3)
            print(f"connected ({elapsed:.3f}s)")

            # Send a minimal HTTP request to look realistic
            try:
                sock.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                # Read a tiny bit of response
                response = sock.recv(256)
                result["response_size"] = len(response)
            except (socket.timeout, OSError):
                pass

        except socket.timeout:
            result["error"] = f"Connection timed out after {timeout}s"
            print("TIMEOUT")
        except socket.error as exc:
            result["error"] = str(exc)
            print(f"ERROR: {exc}")
        except Exception as exc:
            result["error"] = str(exc)
            print(f"UNEXPECTED: {exc}")
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

        results.append(result)

    # Summary
    successful = sum(1 for r in results if r["success"])
    failed = len(results) - successful
    print(f"\n  Summary:")
    print(f"    Connections attempted: {len(results)}")
    print(f"    Successful:            {successful}")
    print(f"    Failed:                {failed}")
    if failed:
        print(f"    Errors:               {[r['error'] for r in results if r['error']]}")
    print()

    return results


# ═══════════════════════════════════════════════════════════════════
#  d) Combined Runner
# ═══════════════════════════════════════════════════════════════════

def _layer_report(simulation_name: str, layers: list[dict]) -> None:
    """Print which WineShield detection layers should catch a simulation."""
    print(f"  Detection expectations for '{simulation_name}':")
    for layer in layers:
        print(f"    {layer['layer']:<20s} — {layer['reason']}")

    # Map severity to action the layer would take
    for layer in layers:
        if layer.get("action"):
            print(f"    {'':>20s}   Action: {layer['action']}")


def run_all_simulations() -> dict:
    """
    Run all three malware simulations sequentially.

    Returns a dict with results from each simulation for analysis.
    """
    print()
    print("╔" + "═" * 58 + "╗")
    print("║  WineShield — Malware Simulation Suite                     ║")
    print("╠" + "═" * 58 + "╣")
    print("║  Validates detection capabilities across all security       ║")
    print("║  layers.  These are SAFETY-DESIGNED test tools, not real    ║")
    print("║  malware.                                                   ║")
    print("╚" + "═" * 58 + "╝")
    print()

    results: dict = {}

    # ── 1. Ransomware ───────────────────────────────────────────
    print("\n" + "─" * 60)
    print("  1. RANSOMWARE SIMULATION")
    print("─" * 60)
    files_created = simulate_ransomware()
    results["ransomware"] = {
        "files_created": files_created,
        "detected_by": [
            {
                "layer": "behavior_analyzer",
                "rule": "ransomware_file_flood",
                "detection_type": "rate",
                "severity": "critical",
                "action": "suspend_process",
                "reason": "Creating 50+ files/second triggers the rate threshold",
            },
            {
                "layer": "filesystem_guard",
                "detection_type": "filesystem_monitoring",
                "severity": "info",
                "action": "log_warning",
                "reason": "Rapid file creation pattern visible in OverlayFS layer",
            },
        ],
    }
    _layer_report(
        "Ransomware Simulator",
        results["ransomware"]["detected_by"],
    )

    # ── 2. Keylogger ────────────────────────────────────────────
    print("\n" + "─" * 60)
    print("  2. KEYLOGGER SIMULATION")
    print("─" * 60)
    events_captured = simulate_keylogger()
    results["keylogger"] = {
        "events_captured": events_captured,
        "detected_by": [
            {
                "layer": "syscall_filter",
                "rule": "privilege_escalation_ptrace",  # ptrace is blocked
                "detection_type": "single",
                "severity": "critical",
                "action": "kill_process",
                "reason": "Opening /dev/input requires syscalls blocked in balanced/strict mode",
            },
            {
                "layer": "filesystem_guard",
                "detection_type": "filesystem_monitoring",
                "severity": "high",
                "action": "log_warning",
                "reason": "Access to /dev/input/event* devices is a suspicious file access pattern",
            },
        ],
    }
    _layer_report(
        "Keylogger Simulator",
        results["keylogger"]["detected_by"],
    )

    # ── 3. Network Backdoor ─────────────────────────────────────
    print("\n" + "─" * 60)
    print("  3. NETWORK BACKDOOR SIMULATION")
    print("─" * 60)
    connection_results = simulate_network_backdoor()
    results["network_backdoor"] = {
        "connections": connection_results,
        "detected_by": [
            {
                "layer": "network_guard",
                "detection_type": "connection_monitoring",
                "severity": "info",
                "action": "log_connection",
                "reason": "All outbound TCP connections to external hosts are logged",
            },
            {
                "layer": "behavior_analyzer",
                "rule": "worm_connection_spray",
                "detection_type": "rate",
                "severity": "critical",
                "action": "kill_process",
                "reason": "Multiple rapid connections to different hosts triggers rate alert (>15 connections/10s)",
            },
            {
                "layer": "behavior_analyzer",
                "rule": "beaconing",
                "detection_type": "pattern",
                "severity": "high",
                "action": "log_warning",
                "reason": "Connections to Google + example.com at consistent intervals = periodic beaconing",
            },
        ],
    }
    _layer_report(
        "Network Backdoor Simulator",
        results["network_backdoor"]["detected_by"],
    )

    # ── Final summary ───────────────────────────────────────────
    print("\n" + "═" * 60)
    print("  WINESHIELD — SIMULATION RESULTS SUMMARY")
    print("═" * 60)
    print(f"  Ransomware:     {results['ransomware']['files_created']:>5d} files created")
    print(f"  Keylogger:      {results['keylogger']['events_captured']:>5d} events captured")
    print(f"  Network backdoor: {sum(1 for c in connection_results if c['success']):>3d}/{len(connection_results)} connections succeeded")
    print()
    print("  Detection layers that SHOULD catch these:")
    print("    Layer               Simulation(s)           Mechanism")
    print("    " + "-" * 65)
    print("    syscall_filter      Keylogger               Blocks /dev/input access via BPF")
    print("    filesystem_guard    Ransomware              Monitors file-creation rate")
    print("    network_guard       Network backdoor        Logs all outbound connections")
    print("    behavior_analyzer   Ransomware              Rate alert (50+ files/s)")
    print("    behavior_analyzer   Network backdoor        Connection-spray rate alert")
    print("    behavior_analyzer   Network backdoor        Periodic beaconing detection")
    print("    xephyr_guard        Keylogger               X11 input isolation (if enabled)")
    print("=" * 60)
    print()

    return results


# ═══════════════════════════════════════════════════════════════════
#  Entry point
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)-7s] %(message)s",
    )
    run_all_simulations()
