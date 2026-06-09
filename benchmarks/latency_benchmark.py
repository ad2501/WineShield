#!/usr/bin/env python3
"""
latency_benchmark.py — WineShield Latency Overhead Benchmark

Measures the **wall-clock time (seconds)** that each security-layer
configuration adds to a standard Wine workload.  This captures both
startup overhead and any runtime slowdowns introduced by the monitoring
layers.

Protocol
--------
1. For each of the 5 configurations (baseline, seccomp_only,
   network_guard, behavior_analyzer, all_layers):
   a. Launch the Wine app under /usr/bin/time -v
   b. Let it run for a fixed duration (12 s by default)
   c. Kill the process group
   d. Parse the ``Elapsed (wall clock) time`` field from the time output
   e. Repeat 3 times
2. Compute mean, stddev, min, max per configuration.
3. Print a human-readable table and save a structured JSON report.

Usage
-----
    python3 benchmarks/latency_benchmark.py
    python3 benchmarks/latency_benchmark.py --runtime 15 --output report.json

Output
------
- Printed summary table to stdout
- Optional JSON file (default: latency_benchmark_<timestamp>.json)
"""

from __future__ import annotations

import argparse
import sys
import time as time_mod
from datetime import datetime, timezone

from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from benchmarks.benchmark_base import (
    CONFIGURATIONS,
    TARGET_APP,
    TARGET_NAME,
    compute_stats,
    is_wsl,
    run_single,
    start_xvfb,
    stop_xvfb,
    verify_wine_prefix,
    ReportWriter,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="WineShield Latency Overhead Benchmark",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--runtime",
        type=int,
        default=12,
        help="Number of seconds to let the Wine app run per iteration (default: 12)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Path to JSON output file (default: auto-name)",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=3,
        help="Number of measurement iterations per config (default: 3)",
    )
    args = parser.parse_args()

    # ── Pre-flight checks ──────────────────────────────────────────
    print("=" * 72)
    print("  WineShield — Latency Overhead Benchmark")
    print("=" * 72)
    print()

    err = verify_wine_prefix()
    if err:
        print(f"  ❌  Wine check failed: {err}")
        print("  Please ensure Wine is installed and the Wine prefix is initialized.")
        return 1

    print(f"  ✅  Wine: {TARGET_NAME} ({TARGET_APP})")
    if is_wsl():
        print("  ⚠   Running on WSL — sandbox features will fail (expected)")
    print()

    # ── Start Xvfb for headless GUI ─────────────────────────────────
    xvfb_display = start_xvfb()
    if xvfb_display:
        print(f"  🖥️  Display: {xvfb_display}")
    else:
        print("  🖥️  Display: inherited from environment")
    print()

    # ── Run measurements ────────────────────────────────────────────
    reporter = ReportWriter(
        metric_name="Wall Clock",
        metric_unit="s",
        description="Wall-clock elapsed time during Wine workload execution",
    )

    for cfg in CONFIGURATIONS:
        name = cfg["name"]
        desc = cfg["description"]
        skip = cfg.get("skip_on_wsl", False) and is_wsl()

        print(f"  ── [{name}] {desc} ──")

        if skip:
            print(f"     ⏭   Skipped: sandbox feature not available on WSL")
            for i in range(args.iterations):
                reporter.add_result(name, {
                    "config_name": name,
                    "error": "Skipped on WSL — needs real Linux kernel",
                    "wall_clock_sec": None,
                    "cpu_percent": None,
                    "max_rss_kb": None,
                })
            print()
            continue

        for i in range(1, args.iterations + 1):
            print(f"     Run {i}/{args.iterations} ... ", end="", flush=True)
            try:
                result = run_single(cfg, runtime_seconds=args.runtime,
                                    xvfb_display=xvfb_display)
                wall = result.get("wall_clock_sec")
                err_msg = result.get("error")

                if wall is not None:
                    print(f"wall = {wall:.2f}s", end="")
                else:
                    print(f"wall = N/A", end="")

                if err_msg:
                    print(f"  [{err_msg[:80]}]", end="")
                print()

                reporter.add_result(name, result)
            except KeyboardInterrupt:
                print("\n  Interrupted.")
                stop_xvfb()
                return 130
            except Exception as exc:
                print(f"ERROR: {exc}")
                reporter.add_result(name, {
                    "config_name": name,
                    "error": str(exc),
                    "wall_clock_sec": None,
                    "cpu_percent": None,
                    "max_rss_kb": None,
                })

        values = reporter.get_values(name)
        stats = compute_stats(values)
        if stats["mean"] is not None:
            print(f"     ─> Avg wall: {stats['mean']:.2f}s ± {stats['stddev']:.2f}s "
                  f"(range: {stats['min']:.2f}–{stats['max']:.2f}s)")
        else:
            print(f"     ─> Avg wall: N/A (all runs failed)")
        print()

    # ── Final report ────────────────────────────────────────────────
    print()
    reporter.print_text()

    # ── Save JSON ───────────────────────────────────────────────────
    if args.output:
        out_path = args.output
    else:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        out_path = f"latency_benchmark_{ts}.json"

    reporter.save_json(out_path)

    # ── Cleanup ─────────────────────────────────────────────────────
    stop_xvfb()
    print("  ✅  Benchmark complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
