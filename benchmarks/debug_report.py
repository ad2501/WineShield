#!/usr/bin/env python3
import json, sys

with open(sys.argv[1]) as f:
    d = json.load(f)

baseline_runs = d.get('raw_runs', {}).get('baseline', [])
for i, run in enumerate(baseline_runs):
    print(f"--- Baseline run {i+1} ---")
    for k, v in run.items():
        if k == 'raw':
            print(f"  raw: <{len(v)} chars> first 200: {v[:200]!r}")
        else:
            print(f"  {k}: {v}")
    print()

seccomp_runs = d.get('raw_runs', {}).get('seccomp_only', [])
for i, run in enumerate(seccomp_runs):
    print(f"--- Seccomp run {i+1} ---")
    for k, v in run.items():
        if k == 'raw':
            print(f"  raw: <{len(v)} chars> first 200: {v[:200]!r}")
        else:
            print(f"  {k}: {v}")
    print()
