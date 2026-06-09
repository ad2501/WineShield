#!/usr/bin/env python3
"""Repository hygiene tests for placeholder artifacts."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_PARTS = {".git", "__pycache__", ".pytest_cache"}


def test_no_text_file_is_left_as_testing_files_placeholder() -> None:
    offenders: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in SKIP_PARTS for part in path.parts):
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if b"\0" in data:
            continue
        text = data.decode("utf-8", errors="replace").strip()
        if text == "testing files":
            offenders.append(str(path.relative_to(ROOT)))
    assert offenders == []
