#!/usr/bin/env python3
"""Unit tests for the real behavior_analyzer module."""
from __future__ import annotations

import os
import sys

# Add the project root to the path so we can import core modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.behavior_analyzer import BehaviorAnalyzer


def _analyzer(patterns: list[dict], *, min_data_points: int = 1) -> BehaviorAnalyzer:
    analyzer = BehaviorAnalyzer({"behavior": {"rules_file": "/definitely/missing/behavior_rules.json"}})
    analyzer._parse_rules(
        {
            "global": {
                "analyzer_enabled": True,
                "suspension_enabled": False,
                "cooldown_seconds": 0,
                "min_data_points": min_data_points,
            },
            "patterns": patterns,
        }
    )
    return analyzer


def test_single_ptrace_event_generates_alert() -> None:
    analyzer = _analyzer(
        [
            {
                "id": "ptrace_attempt",
                "name": "ptrace attempt",
                "detection_type": "single",
                "metric": "ptrace_attempt",
                "severity": "critical",
                "action": "kill_process",
                "source_layer": "syscall_filter",
            }
        ]
    )
    analyzer.session_id = "test-session"

    analyzer.ingest_event(
        {
            "layer": "syscall_filter",
            "action": "ptrace_attempt",
            "details": "blocked ptrace attempt",
        }
    )

    alerts = analyzer.get_alerts()
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "ptrace_attempt"
    assert alerts[0]["severity"] == "critical"
    assert alerts[0]["session"] == "test-session"


def test_rate_rule_flags_ransomware_file_flood() -> None:
    analyzer = _analyzer(
        [
            {
                "id": "ransomware_file_flood",
                "name": "ransomware file flood",
                "detection_type": "rate",
                "metric": "files_written_per_second",
                "threshold": 1,
                "window_seconds": 10,
                "severity": "critical",
                "action": "suspend_process",
                "source_layer": "filesystem_guard",
            }
        ],
        min_data_points=1,
    )

    for _ in range(11):
        analyzer.ingest_event(
            {
                "layer": "filesystem_guard",
                "action": "file_written",
                "details": "file written in sandbox",
            }
        )
    analyzer._check_rules()

    alerts = analyzer.get_alerts()
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "ransomware_file_flood"


def test_sequence_rule_flags_read_then_network_send() -> None:
    analyzer = _analyzer(
        [
            {
                "id": "data_exfiltration",
                "name": "data exfiltration",
                "detection_type": "sequence",
                "sequence": [
                    {"event": "file_read", "within_seconds": 5},
                    {"event": "network_send", "bytes_threshold": 1000, "within_seconds": 5},
                ],
                "severity": "critical",
                "action": "kill_process",
                "source_layer": "behavior_analyzer",
            }
        ]
    )

    analyzer.ingest_event({"layer": "filesystem_guard", "action": "file_read", "details": "secret.dat"})
    analyzer.ingest_event({"layer": "network_guard", "action": "network_send", "details": "sent 4096 bytes"})

    alerts = analyzer.get_alerts()
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "data_exfiltration"


def test_non_matching_event_does_not_generate_alert() -> None:
    analyzer = _analyzer(
        [
            {
                "id": "ptrace_attempt",
                "name": "ptrace attempt",
                "detection_type": "single",
                "metric": "ptrace_attempt",
                "severity": "critical",
                "action": "kill_process",
                "source_layer": "syscall_filter",
            }
        ]
    )

    analyzer.ingest_event({"layer": "network_guard", "action": "connect", "details": "benign"})
    assert analyzer.get_alerts() == []
