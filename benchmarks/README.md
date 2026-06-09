# WineShield Benchmark Suite — Empirical Performance Evaluation

This directory contains the measurement framework for **Contribution #4:
Empirical overhead evaluation** of each security layer's performance
impact on real Windows applications running under Wine.

## Files

| File | Purpose |
|------|---------|
| `benchmark_base.py` | Shared infrastructure — config definitions, measurement runner, `/usr/bin/time -v` parser, statistics, and report writer |
| `cpu_benchmark.py` | **CPU overhead** — measures `%CPU` from `/usr/bin/time -v` per configuration |
| `latency_benchmark.py` | **Latency overhead** — measures wall-clock elapsed time per configuration |
| `memory_benchmark.py` | **Memory overhead** — measures max RSS (resident set size) per configuration |
| `README.md` | This file — methodology explanation |

## Methodology

### Test Workload

The benchmark uses **Notepad++** running under Wine as the reference
test application.  If Notepad++ is not installed in the Wine prefix,
the suite falls back to Wine's built-in **notepad.exe**.

For each measurement run:

1. A **virtual framebuffer (Xvfb)** is started to provide a headless
   display (no physical screen needed).
2. The target application is launched under `/usr/bin/time -v` with the
   appropriate WineShield configuration.
3. The application runs for a fixed **dwell time** (default: 12 seconds)
   — long enough for startup, file operations, and UI rendering to
   stabilise.
4. The process group is terminated and the `time -v` output is parsed
   for the relevant metrics.

### Configurations Benchmarked

| # | Name | Description | Command |
|---|------|-------------|---------|
| 1 | **baseline** | Wine without WineShield (no security layers) | `wine notepad++.exe` |
| 2 | **seccomp_only** | Syscall monitor (seccomp-BPF) only | `sudo syscall_monitor --mode monitor -- wine …` |
| 3 | **network_guard** | Network Guard layer only | `python3 -m core.launcher --mode monitor --layer network --app wine` |
| 4 | **behavior_analyzer** | Behavior Analyzer layer only | `python3 -m core.launcher --mode monitor --layer behavior --app wine` |
| 5 | **all_layers** | Full WineShield stack | `python3 -m core.launcher --mode balanced --app wine` |

### Measurement Protocol

For **every** configuration:

1. Run the workload **3 times** (configurable via `--iterations`).
2. Record the relevant metric from `/usr/bin/time -v`:
   - **CPU benchmark:** `Percent of CPU this job got` (%)
   - **Latency benchmark:** `Elapsed (wall clock) time` (seconds)
   - **Memory benchmark:** `Maximum resident set size` (KB → MB)
3. Compute **mean, standard deviation, min, and max** across the runs.
4. Report structured output as both a human-readable table and a JSON
   report file.

### WSL Handling

The sandbox features (seccomp, namespaces, etc.) are known to **fail
on WSL** due to missing kernel support (`ENOMEM` / `EINVAL`).  The
benchmark suite detects WSL automatically and:

- **Skips** configurations that require kernel sandbox features
  (network_guard, behavior_analyzer, all_layers).
- **Records** the skip with the message "Skipped on WSL — needs real
  Linux kernel".
- **Still runs** the baseline and seccomp_only configurations (seccomp
  may or may not work on WSL 2).

On a native Linux system, all 5 configurations run fully.

## Usage

Run any benchmark script from the project root:

```bash
# CPU benchmark (default: 3 iterations × 12 s dwell)
python3 benchmarks/cpu_benchmark.py

# Latency benchmark
python3 benchmarks/latency_benchmark.py

# Memory benchmark
python3 benchmarks/memory_benchmark.py

# Custom options
python3 benchmarks/cpu_benchmark.py \
    --runtime 15 \
    --iterations 5 \
    --output ./results/cpu_report.json
```

Each script:
1. Prints a **live progress** table as measurements are taken.
2. Prints a **summary table** at the end.
3. Saves a **structured JSON report** to disk.

### JSON Report Format

```json
{
  "benchmark": "CPU Usage",
  "description": "CPU utilization percentage during Wine workload execution",
  "metric_unit": "%",
  "target_app": "Notepad++",
  "target_path": "/home/user/.wine/.../notepad++.exe",
  "wsl": false,
  "timestamp": "2026-06-10T12:00:00+00:00",
  "configurations": [
    { "name": "baseline", "description": "...", "layers": [] },
    ...
  ],
  "results": [
    {
      "config": "baseline",
      "description": "...",
      "layers": "none",
      "n": 3,
      "mean": 45.2,
      "stddev": 2.1,
      "min": 43.0,
      "max": 47.5,
      "errors": []
    },
    ...
  ],
  "raw_runs": { ... }
}
```

## Interpreting Results

- **Baseline** is the reference point — overhead is computed relative
  to this configuration.
- **Seccomp-only** overhead should be minimal (<5% CPU, <100 ms
  latency) since seccomp-BPF is a lightweight kernel filter.
- **Network guard** and **behavior analyzer** add Python process
  overhead — expect higher CPU and RSS.
- **All layers** shows the combined overhead of the full stack.

## Dependencies

- `python3 >= 3.10`
- `wine` (any recent version)
- `Xvfb` (for headless GUI execution)
- `/usr/bin/time` (GNU time, not the shell built-in)
- `sudo` (for seccomp monitor)
- A configured Wine prefix with Notepad++ installed (or fallback to
  built-in `wine notepad`)

Install missing dependencies on Ubuntu/Debian:

```bash
sudo apt-get install xvfb time wine
```

## Citing This Benchmark

When using these benchmarks in academic work, reference:

> WineShield: Multi-layer security framework for Wine on Linux.
> Contribution #4 — Empirical overhead evaluation.
> https://github.com/ad2501/WineShield
