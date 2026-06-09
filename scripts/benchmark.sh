#!/usr/bin/env bash
# Run a small WineShield benchmark suite.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
python3 "$ROOT/benchmarks/benchmark_base.py" "$@"
