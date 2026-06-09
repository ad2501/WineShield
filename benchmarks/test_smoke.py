#!/usr/bin/env python3
"""Quick smoke test for the benchmark suite."""
import sys
sys.path.insert(0, '.')

from benchmarks.benchmark_base import (
    CONFIGURATIONS, is_wsl, parse_time_output,
    compute_stats, ReportWriter
)

print('PASS: benchmark_base imports OK')
print('Configs:', len(CONFIGURATIONS))
print('WSL:', is_wsl())

# Test parse_time_output with sample data
sample = (
    '\tCommand being timed: "true"\n'
    '\tUser time (seconds): 0.01\n'
    '\tSystem time (seconds): 0.00\n'
    '\tPercent of CPU this job got: 15%\n'
    '\tElapsed (wall clock) time (h:mm:ss or m:ss): 0:00.04\n'
    '\tMaximum resident set size (kbytes): 2048\n'
    '\tMinor (reclaiming a frame) page faults: 15\n'
    '\tVoluntary context switches: 1\n'
    '\tInvoluntary context switches: 0\n'
    '\tCommand exited with status: 0\n'
)
parsed = parse_time_output(sample)
assert parsed['cpu_percent'] == 15, f"Expected 15, got {parsed['cpu_percent']}"
assert abs(parsed['wall_clock_sec'] - 0.04) < 0.001, f"Expected 0.04, got {parsed['wall_clock_sec']}"
assert parsed['max_rss_kb'] == 2048, f"Expected 2048, got {parsed['max_rss_kb']}"
print('PASS: parse_time_output')

# Test compute_stats
stats = compute_stats([10.0, 12.0, 11.0])
assert abs(stats['mean'] - 11.0) < 0.01
assert abs(stats['stddev'] - 1.0) < 0.01
print('PASS: compute_stats')

# Test ReportWriter
rw = ReportWriter('CPU Usage', '%', 'test')
rw.add_result('baseline', {'config_name': 'baseline', 'cpu_percent': 45, 'error': None})
rw.add_result('baseline', {'config_name': 'baseline', 'cpu_percent': 47, 'error': None})
rw.add_result('baseline', {'config_name': 'baseline', 'cpu_percent': 43, 'error': None})
rows = rw.summary_table()
assert len(rows) == 5  # 5 configs defined
baseline_row = [r for r in rows if r['config'] == 'baseline'][0]
assert baseline_row['mean'] == 45.0
print('PASS: ReportWriter')

# Test JSON output
json_str = rw.to_json()
assert '"CPU Usage"' in json_str
print('PASS: JSON serialization')

# Test each script imports cleanly
for modname in ['cpu_benchmark', 'latency_benchmark', 'memory_benchmark']:
    __import__(f'benchmarks.{modname}')
    print(f'PASS: benchmarks.{modname} imports cleanly')

print()
print('ALL SMOKE TESTS PASSED')
