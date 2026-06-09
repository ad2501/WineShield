#!/usr/bin/env python3
"""Generate a syscall whitelist from the documented WineShield whitelist file.

By default this script reads ``config/wine_syscall_whitelist.conf`` and prints
one syscall name per line.  Use ``--json`` to emit a JSON array.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = ROOT / "config" / "wine_syscall_whitelist.conf"


def parse_whitelist(path: str | Path = DEFAULT_INPUT) -> list[str]:
    """Parse syscall names from ``name: justification`` lines."""
    names: list[str] = []
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        name = line.split(":", 1)[0].strip()
        if name and name.replace("_", "").isalnum():
            names.append(name)
    return names


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", default=str(DEFAULT_INPUT))
    parser.add_argument("--json", action="store_true", help="emit JSON instead of plain text")
    args = parser.parse_args(argv)

    names = parse_whitelist(args.input)
    if args.json:
        print(json.dumps(names, indent=2))
    else:
        print("\n".join(names))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
