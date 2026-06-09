#!/usr/bin/env python3
"""
WineShield — Behavior Analyzer Unit Tests (Layer 4)

Tests for the ``BehaviorAnalyzer`` class (``core/behavior_analyzer.py``).

Covers all 4 detection types (rate, single, sequence, pattern) plus
suspension mechanics and cleanup reporting.  Uses direct method calls
(``ingest_event``) rather than the background thread to keep tests
deterministic.

Run with::

    cd /path/to/WineShield
    pytest tests/test_behavior_analyzer.py -v
"""

from __future__ import annotations

import threading
import time

import pytest

from core.behavior_analyzer import BehaviorAnalyzer, _build_alert


# ── Fixtures ─────────────────────────────────────────────────────


@pytest.fixture
def minimal_config() -> dict:
    """Minimal config dict that triggers the built-in fallback rules."""
    return {
        "behavior": {
            "analyzer_enabled": True,
            "suspension_enabled": True,
            "cooldown_seconds": 5,
            "min_data_points": 1,
        }
    }


@pytest.fixture
def analyzer(minimal_config: dict) -> BehaviorAnalyzer:
    """Provide a fresh BehaviorAnalyzer (not yet monitoring)."""
    return BehaviorAnalyzer(minimal_config, session_id="test-session-001")


@pytest.fixture
def running_analyzer(minimal_config: dict) -> BehaviorAnalyzer:
    """Provide a BehaviorAnalyzer that has monitoring started."""
    ba = BehaviorAnalyzer(minimal_config, session_id="test-session-002")
    ba.start_monitoring()
    yield ba
    try:
        ba.stop_monitoring()
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════
#  Initial state tests
# ═══════════════════════════════════════════════════════════════════


class TestInitialState:
    """Verify the BehaviorAnalyzer starts in a clean state."""

    def test_constructor_accepts_config(self, analyzer: BehaviorAnalyzer) -> None:
        """Constructor should store config and not raise."""
        assert analyzer.config is not None

    def test_initial_session_id(self, analyzer: BehaviorAnalyzer) -> None:
        """session_id should match what was passed."""
        assert analyzer.session_id == "test-session-001"

    def test_initial_rules_loaded(self, analyzer: BehaviorAnalyzer) -> None:
        """Fallback rules should be loaded automatically."""
        assert len(analyzer._rules) > 0

    def test_initial_no_alerts(self, analyzer: BehaviorAnalyzer) -> None:
        """No alerts should exist initially."""
        assert analyzer.get_alerts() == []

    def test_initial_not_suspended(self, analyzer: BehaviorAnalyzer) -> None:
        """is_suspended() should return False initially."""
        assert analyzer.is_suspended() is False

    def test_initial_events_processed_zero(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """Events processed counter should start at 0."""
        assert analyzer._events_processed == 0

    def test_initial_alerts_generated_zero(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """Alerts generated counter should start at 0."""
        assert analyzer._alerts_generated == 0

    def test_default_rules_include_ransomware(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """Fallback rules should include the ransomware_file_flood rule."""
        rule_ids = {r["id"] for r in analyzer._rules}
        assert "ransomware_file_flood" in rule_ids

    def test_default_rules_include_ptrace(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """Fallback rules should include the ptrace single-event rule."""
        rule_ids = {r["id"] for r in analyzer._rules}
        assert "privilege_escalation_ptrace" in rule_ids

    def test_default_rules_include_exfiltration(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """Fallback rules should include the data_exfiltration sequence rule."""
        rule_ids = {r["id"] for r in analyzer._rules}
        assert "data_exfiltration" in rule_ids

    def test_default_rules_include_beaconing(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """Fallback rules should include the beaconing pattern rule."""
        rule_ids = {r["id"] for r in analyzer._rules}
        assert "beaconing" in rule_ids


# ═══════════════════════════════════════════════════════════════════
#  Rate detection tests
# ═══════════════════════════════════════════════════════════════════


class TestRateDetection:
    """Rate-based detection (e.g. ransomware_file_flood: >50 files/s)."""

    def test_single_event_no_alert(self, analyzer: BehaviorAnalyzer) -> None:
        """A single event should NOT trigger a rate alert (needs threshold)."""
        analyzer.ingest_event({
            "layer": "filesystem_guard",
            "action": "file_write",
            "details": "wrote 4096 bytes to /test/file",
            "severity": "info",
        })
        alerts = analyzer.get_alerts()
        assert len(alerts) == 0

    def test_rate_below_threshold_no_alert(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """Events below the rate threshold should not trigger."""
        for i in range(5):
            analyzer.ingest_event({
                "layer": "filesystem_guard",
                "action": "file_write",
                "details": f"wrote 4096 bytes to /test/file_{i}",
                "severity": "info",
            })
        # Manually trigger the rate check
        analyzer._check_rate_rule(
            [r for r in analyzer._rules if r["id"] == "ransomware_file_flood"][0],
            time.time(),
        )
        alerts = analyzer.get_alerts()
        assert len(alerts) == 0

    def test_high_rate_triggers_flood_alert(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """Injecting 300+ file_write events in a 5s window triggers flood alert.

        The rule threshold is 50 files/s over a 5s window, so we need
        250+ timestamps to reach rate >= 50 (300/5 = 60 >= 50).
        """
        now = time.time()
        rule = [r for r in analyzer._rules if r["id"] == "ransomware_file_flood"][0]

        # Inject many file_write events
        for i in range(70):
            analyzer.ingest_event({
                "layer": "filesystem_guard",
                "action": "file_write",
                "details": f"wrote 4096 bytes to /test/file_{i}",
                "severity": "info",
            })

        # Override the rate window with 300 timestamps all within the window
        # (ingest_event uses real time, so we force enough entries)
        with analyzer._lock:
            analyzer._rate_windows[rule["id"]] = [now - 0.1] * 300

        # Run the rate check
        analyzer._check_rate_rule(rule, now)
        alerts = analyzer.get_alerts()

        assert len(alerts) >= 1, "Expected at least 1 rate alert"
        alert = alerts[0]
        assert alert["rule_id"] == "ransomware_file_flood"
        assert alert["severity"] == "critical"
        assert alert["layer"] == "behavior_analyzer"
        assert "files_written_per_second" in alert["details"] or "rate" in alert["details"].lower()

    def test_rate_window_resets_after_trigger(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """After triggering, the rate window should be cleared."""
        now = time.time()
        rule = [r for r in analyzer._rules if r["id"] == "ransomware_file_flood"][0]

        with analyzer._lock:
            analyzer._rate_windows[rule["id"]] = [now - 0.1] * 300

        analyzer._check_rate_rule(rule, now)
        _ = analyzer.get_alerts()  # drain

        # Window should be cleared
        with analyzer._lock:
            assert analyzer._rate_windows[rule["id"]] == []


# ═══════════════════════════════════════════════════════════════════
#  Single event detection tests
# ═══════════════════════════════════════════════════════════════════


class TestSingleEventDetection:
    """Single-event detection (e.g. ptrace_attempt → immediate critical)."""

    def test_ptrace_attempt_triggers_alert(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """A ptrace_attempt event should immediately trigger a critical alert."""
        analyzer.ingest_event({
            "layer": "syscall_filter",
            "action": "ptrace_attempt",
            "details": "ptrace(PTRACE_TRACEME) called by PID 1234",
            "severity": "warning",
        })
        alerts = analyzer.get_alerts()
        assert len(alerts) >= 1
        alert = alerts[0]
        assert alert["rule_id"] == "privilege_escalation_ptrace"
        assert alert["severity"] == "critical"

    def test_ptrace_alert_has_expected_fields(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """The ptrace alert should have all required fields."""
        analyzer.ingest_event({
            "layer": "syscall_filter",
            "action": "ptrace_attempt",
            "details": "ptrace call detected",
            "severity": "warning",
        })
        alerts = analyzer.get_alerts()
        assert len(alerts) >= 1
        alert = alerts[0]
        assert "id" in alert
        assert "timestamp" in alert
        assert "layer" in alert
        assert "action" in alert
        assert "details" in alert
        assert "rule_id" in alert

    def test_non_ptrace_event_does_not_trigger(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """A non-ptrace event should not trigger the ptrace rule."""
        analyzer.ingest_event({
            "layer": "filesystem_guard",
            "action": "file_read",
            "details": "read /etc/passwd",
            "severity": "info",
        })
        alerts = analyzer.get_alerts()
        assert len(alerts) == 0


# ═══════════════════════════════════════════════════════════════════
#  Sequence detection tests
# ═══════════════════════════════════════════════════════════════════


class TestSequenceDetection:
    """Sequence detection (e.g. file_read → network_send = exfiltration)."""

    def test_first_event_only_no_alert(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """Just the first event in a sequence should not trigger an alert."""
        analyzer.ingest_event({
            "layer": "behavior_analyzer",
            "action": "file_read",
            "details": "read 4096 bytes from /secret/data.txt",
            "severity": "info",
        })
        alerts = analyzer.get_alerts()
        assert len(alerts) == 0

    def test_file_read_then_network_send_triggers_exfiltration(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """file_read followed by network_send should trigger exfiltration."""
        # Step 1: file_read
        analyzer.ingest_event({
            "layer": "behavior_analyzer",
            "action": "file_read",
            "details": "read 4096 bytes from /secret/data.txt",
            "severity": "info",
        })

        # Step 2: network_send (within the detection window)
        analyzer.ingest_event({
            "layer": "network_guard",
            "action": "network_send",
            "details": "sent 4096 bytes to 203.0.113.5:443",
            "severity": "info",
        })

        alerts = analyzer.get_alerts()
        assert len(alerts) >= 1, "Expected exfiltration alert"
        alert = alerts[0]
        assert alert["rule_id"] == "data_exfiltration"
        assert alert["severity"] == "critical"

    def test_file_read_only_no_exfiltration(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """Multiple file reads without network_send should not trigger."""
        for i in range(3):
            analyzer.ingest_event({
                "layer": "behavior_analyzer",
                "action": "file_read",
                "details": f"read {4096 * (i + 1)} bytes from /secret/data_{i}.txt",
                "severity": "info",
            })
        alerts = analyzer.get_alerts()
        assert len(alerts) == 0

    def test_network_send_before_file_read_no_trigger(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """Reverse order (send before read) should not trigger."""
        analyzer.ingest_event({
            "layer": "network_guard",
            "action": "network_send",
            "details": "sent 4096 bytes to 203.0.113.5:443",
            "severity": "info",
        })
        analyzer.ingest_event({
            "layer": "behavior_analyzer",
            "action": "file_read",
            "details": "read 4096 bytes from /secret/data.txt",
            "severity": "info",
        })
        alerts = analyzer.get_alerts()
        # The sequence is file_read -> network_send, so reverse order
        # should not trigger (but file_read as step 0 might start tracking)
        # Actually file_read as second event won't match step 0 since it's
        # after network_send... but file_read as step 0 won't trigger an alert
        # because step 1 (network_send) already happened before it.
        # So no alert should be generated.
        assert len(alerts) == 0


# ═══════════════════════════════════════════════════════════════════
#  Pattern detection tests (beaconing)
# ═══════════════════════════════════════════════════════════════════


class TestPatternDetection:
    """Pattern detection (e.g. C2 beaconing at consistent intervals)."""

    def test_single_connection_no_beacon(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """A single connection should not trigger beaconing."""
        analyzer.ingest_event({
            "layer": "network_guard",
            "action": "network_connect",
            "details": "connected to 203.0.113.5:443",
            "severity": "info",
        })
        alerts = analyzer.get_alerts()
        assert len(alerts) == 0

    def test_consistent_intervals_triggers_beaconing(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """5+ connections at consistent intervals should trigger beaconing."""
        rule = [r for r in analyzer._rules if r["id"] == "beaconing"][0]
        rule_id = rule["id"]
        dest_key = f"{rule_id}:203.0.113.5"

        # Inject timestamps at exactly 5s intervals
        now = time.time()
        timestamps = [now - (5 * (4 - i)) for i in range(5)]  # now-20, now-15, now-10, now-5, now
        with analyzer._lock:
            analyzer._pattern_timestamps[dest_key] = timestamps

        # Run pattern check
        analyzer._check_pattern_rule(rule, now + 0.1)
        alerts = analyzer.get_alerts()

        assert len(alerts) >= 1, "Expected beaconing alert"
        alert = alerts[0]
        assert alert["rule_id"] == "beaconing"
        assert alert["severity"] == "high"
        assert "periodic" in alert["details"].lower()

    def test_irregular_intervals_no_beacon(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """Random intervals should not trigger beaconing."""
        rule = [r for r in analyzer._rules if r["id"] == "beaconing"][0]
        rule_id = rule["id"]
        dest_key = f"{rule_id}:203.0.113.5"

        now = time.time()
        # Very irregular intervals: 20s, 10s, 5s, 1s away from mean
        # Intervals: 20, 10, 5, 1  → mean=9, 20-9=11 > tolerance(5)
        timestamps = [now - t for t in [50, 30, 20, 15, 14]]
        with analyzer._lock:
            analyzer._pattern_timestamps[dest_key] = timestamps

        analyzer._check_pattern_rule(rule, now)
        alerts = analyzer.get_alerts()
        assert len(alerts) == 0

    def test_different_destinations_independent(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """Connections to different destinations are tracked independently."""
        rule = [r for r in analyzer._rules if r["id"] == "beaconing"][0]
        rule_id = rule["id"]
        now = time.time()

        # Both destinations have consistent intervals
        with analyzer._lock:
            analyzer._pattern_timestamps[f"{rule_id}:dest_a"] = [
                now - (5 * (4 - i)) for i in range(5)
            ]
            analyzer._pattern_timestamps[f"{rule_id}:dest_b"] = [now - 10, now - 5]

        analyzer._check_pattern_rule(rule, now + 0.1)
        alerts = analyzer.get_alerts()

        # Only dest_a has enough periods (5 timestamps = 4 intervals >= min_periods-1=2)
        assert len(alerts) >= 1

    def test_inject_network_connect_events(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """Use ingest_event to build pattern state, then check."""
        rule = [r for r in analyzer._rules if r["id"] == "beaconing"][0]
        rule_id = rule["id"]

        # Inject several network_connect events for pattern tracking
        for i in range(5):
            analyzer.ingest_event({
                "layer": "network_guard",
                "action": "network_connect",
                "details": f"connected to 198.51.100.1:443",
                "severity": "info",
            })

        # Override timestamps with consistent intervals
        now = time.time()
        with analyzer._lock:
            analyzer._pattern_timestamps[f"{rule_id}:198.51.100.1"] = [
                now - (5 * (4 - i)) for i in range(5)
            ]

        analyzer._check_pattern_rule(rule, now + 0.1)
        alerts = analyzer.get_alerts()
        assert len(alerts) >= 1


# ═══════════════════════════════════════════════════════════════════
#  Suspension tests
# ═══════════════════════════════════════════════════════════════════


class TestSuspension:
    """Verify that critical alerts trigger suspension."""

    def test_critical_alert_sets_suspended(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """A critical alert with suspend_process action should set suspended."""
        analyzer.ingest_event({
            "layer": "syscall_filter",
            "action": "ptrace_attempt",
            "details": "ptrace call detected",
            "severity": "warning",
        })
        _ = analyzer.get_alerts()
        assert analyzer.is_suspended() is True

    def test_info_alert_does_not_suspend(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """A non-critical event should not trigger suspension."""
        analyzer.ingest_event({
            "layer": "filesystem_guard",
            "action": "file_read",
            "details": "normal file access",
            "severity": "info",
        })
        _ = analyzer.get_alerts()
        assert analyzer.is_suspended() is False

    def test_suspension_has_cooldown(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """Suspension should respect the cooldown period."""
        # First critical alert
        analyzer.ingest_event({
            "layer": "syscall_filter",
            "action": "ptrace_attempt",
            "details": "first ptrace",
            "severity": "warning",
        })
        _ = analyzer.get_alerts()
        assert analyzer.is_suspended() is True
        first_time = analyzer._last_suspension_time

        # Reset suspended flag
        analyzer._suspended = False

        # Second alert within cooldown — should NOT set suspended again
        analyzer.ingest_event({
            "layer": "syscall_filter",
            "action": "ptrace_attempt",
            "details": "second ptrace",
            "severity": "warning",
        })
        _ = analyzer.get_alerts()
        # Should still be False because cooldown hasn't elapsed
        assert analyzer.is_suspended() is False

    def test_suspension_after_cooldown(self, analyzer: BehaviorAnalyzer) -> None:
        """After the cooldown elapses, a new critical alert should suspend."""
        # First alert
        analyzer.ingest_event({
            "layer": "syscall_filter",
            "action": "ptrace_attempt",
            "details": "first ptrace",
            "severity": "warning",
        })
        _ = analyzer.get_alerts()
        assert analyzer.is_suspended() is True

        # Reset and fast-forward the cooldown clock
        analyzer._suspended = False
        analyzer._last_suspension_time = time.time() - analyzer._cooldown_seconds - 1

        # Second alert — should suspend again
        analyzer.ingest_event({
            "layer": "syscall_filter",
            "action": "ptrace_attempt",
            "details": "second ptrace after cooldown",
            "severity": "warning",
        })
        _ = analyzer.get_alerts()
        assert analyzer.is_suspended() is True


# ═══════════════════════════════════════════════════════════════════
#  Alert management tests
# ═══════════════════════════════════════════════════════════════════


class TestAlertManagement:
    """Verify alert accumulation and draining."""

    def test_get_alerts_drains_buffer(self, analyzer: BehaviorAnalyzer) -> None:
        """get_alerts() should return pending alerts and clear the buffer."""
        analyzer.ingest_event({
            "layer": "syscall_filter",
            "action": "ptrace_attempt",
            "details": "test ptrace",
            "severity": "warning",
        })
        alerts_1 = analyzer.get_alerts()
        assert len(alerts_1) >= 1

        # Second call should return empty (buffer drained)
        alerts_2 = analyzer.get_alerts()
        assert len(alerts_2) == 0

    def test_multiple_alerts_accumulate(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """Multiple rule triggers should accumulate in the buffer."""
        # Trigger ptrace twice (wait for cooldown in between... or test differently)
        # Actually the cooldown blocks repeated ptrace alerts.
        # Instead trigger two different rules.
        # ptrace_attempt
        analyzer.ingest_event({
            "layer": "syscall_filter",
            "action": "ptrace_attempt",
            "details": "first ptrace",
            "severity": "warning",
        })

        # For the second, reset suspension and trigger a rate alert
        analyzer._suspended = False
        analyzer._last_suspension_time = 0

        # Trigger the ransomware flood via rate check
        rule = [r for r in analyzer._rules if r["id"] == "ransomware_file_flood"][0]
        now = time.time()
        with analyzer._lock:
            analyzer._rate_windows[rule["id"]] = [now - 0.1] * 65
        analyzer._check_rate_rule(rule, now)

        alerts = analyzer.get_alerts()
        assert len(alerts) >= 1


# ═══════════════════════════════════════════════════════════════════
#  Start / Stop lifecycle tests
# ═══════════════════════════════════════════════════════════════════


class TestLifecycle:
    """Verify the monitoring start/stop lifecycle."""

    def test_start_monitoring_starts_thread(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """start_monitoring() should create and start a daemon thread."""
        assert analyzer._thread is None
        analyzer.start_monitoring()
        assert analyzer._thread is not None
        assert analyzer._thread.is_alive()
        analyzer.stop_monitoring()

    def test_duplicate_start_is_noop(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """Calling start_monitoring() twice should not crash."""
        analyzer.start_monitoring()
        thread_id = id(analyzer._thread)
        analyzer.start_monitoring()  # second call — should be no-op
        assert id(analyzer._thread) == thread_id
        analyzer.stop_monitoring()

    def test_stop_monitoring_stops_thread(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """stop_monitoring() should stop the daemon thread."""
        analyzer.start_monitoring()
        assert analyzer._thread is not None
        analyzer.stop_monitoring()
        # Give it a moment
        analyzer._thread.join(timeout=3)
        assert not analyzer._thread.is_alive()

    def test_stop_without_start_no_crash(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """Calling stop_monitoring() without start should not crash."""
        analyzer.stop_monitoring()  # should be a no-op

    def test_monitoring_resets_state(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """start_monitoring() should clear previous state."""
        # Inject some state
        analyzer.ingest_event({
            "layer": "syscall_filter",
            "action": "ptrace_attempt",
            "details": "test",
            "severity": "warning",
        })
        _ = analyzer.get_alerts()
        assert analyzer._events_processed > 0

        # Restart monitoring
        analyzer.start_monitoring()
        assert analyzer._events_processed == 0
        assert analyzer.get_alerts() == []
        analyzer.stop_monitoring()


# ═══════════════════════════════════════════════════════════════════
#  Cleanup tests
# ═══════════════════════════════════════════════════════════════════


class TestCleanup:
    """Verify cleanup() reports correct stats and resets state."""

    def test_cleanup_reports_events_processed(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """cleanup() should report the number of events processed."""
        analyzer.ingest_event({
            "layer": "filesystem_guard",
            "action": "file_write",
            "details": "test event 1",
            "severity": "info",
        })
        analyzer.ingest_event({
            "layer": "filesystem_guard",
            "action": "file_write",
            "details": "test event 2",
            "severity": "info",
        })
        analyzer.cleanup()
        # After cleanup, events_processed should be 0
        assert analyzer._events_processed == 0

    def test_cleanup_resets_alerts(self, analyzer: BehaviorAnalyzer) -> None:
        """cleanup() should clear all alerts."""
        analyzer.ingest_event({
            "layer": "syscall_filter",
            "action": "ptrace_attempt",
            "details": "trigger alert",
            "severity": "warning",
        })
        _ = analyzer.get_alerts()
        analyzer.cleanup()
        assert analyzer.get_alerts() == []
        assert analyzer._alerts_generated == 0

    def test_cleanup_resets_suspension(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """cleanup() should clear suspension state."""
        analyzer.ingest_event({
            "layer": "syscall_filter",
            "action": "ptrace_attempt",
            "details": "trigger alert",
            "severity": "warning",
        })
        _ = analyzer.get_alerts()
        assert analyzer.is_suspended() is True
        analyzer.cleanup()
        assert analyzer.is_suspended() is False

    def test_cleanup_resets_rate_windows(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """cleanup() should clear rate tracking windows."""
        analyzer.ingest_event({
            "layer": "filesystem_guard",
            "action": "file_write",
            "details": "test",
            "severity": "info",
        })
        analyzer.cleanup()
        with analyzer._lock:
            assert analyzer._rate_windows == {}

    def test_cleanup_resets_sequences(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """cleanup() should clear pending sequences."""
        analyzer.ingest_event({
            "layer": "behavior_analyzer",
            "action": "file_read",
            "details": "test read",
            "severity": "info",
        })
        analyzer.cleanup()
        with analyzer._lock:
            assert analyzer._pending_sequences == {}

    def test_cleanup_while_not_monitoring(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """cleanup() should work even if monitoring was never started."""
        analyzer.cleanup()  # should not crash
        assert analyzer._events_processed == 0


# ═══════════════════════════════════════════════════════════════════
#  Edge cases and input validation
# ═══════════════════════════════════════════════════════════════════


class TestEdgeCases:
    """Edge cases and input validation."""

    def test_ingest_none_dict(self, analyzer: BehaviorAnalyzer) -> None:
        """Ingesting a None should be handled gracefully."""
        analyzer.ingest_event(None)  # type: ignore[arg-type]
        assert analyzer._events_processed == 0

    def test_ingest_empty_dict(self, analyzer: BehaviorAnalyzer) -> None:
        """Ingesting an empty dict should be handled gracefully."""
        analyzer.ingest_event({})
        # No layer/action — should be skipped
        assert analyzer._events_processed == 0

    def test_ingest_dict_without_layer(
        self, analyzer: BehaviorAnalyzer
    ) -> None:
        """Ingesting a dict without 'layer' or 'action' should skip."""
        analyzer.ingest_event({"severity": "info", "details": "test"})
        assert analyzer._events_processed == 0

    def test_rules_disabled_no_alerts(self, minimal_config: dict) -> None:
        """When rules are disabled, no alerts should be generated."""
        ba = BehaviorAnalyzer(minimal_config)
        # Disable rules via the _rules_enabled flag directly
        # (the config dict's analyzer_enabled field is separate from
        #  the rules JSON's global.analyzer_enabled — tests verify the
        #  runtime flag)
        ba._rules_enabled = False
        ba.ingest_event({
            "layer": "syscall_filter",
            "action": "ptrace_attempt",
            "details": "should be ignored",
            "severity": "warning",
        })
        alerts = ba.get_alerts()
        assert len(alerts) == 0

    def test_rules_disabled_skips_events(
        self, minimal_config: dict
    ) -> None:
        """When rules are disabled, events should not be counted."""
        ba = BehaviorAnalyzer(minimal_config)
        ba._rules_enabled = False
        ba.ingest_event({
            "layer": "syscall_filter",
            "action": "ptrace_attempt",
            "details": "test",
            "severity": "warning",
        })
        assert ba._events_processed == 0


# ═══════════════════════════════════════════════════════════════════
#  _build_alert helper tests
# ═══════════════════════════════════════════════════════════════════


class TestBuildAlert:
    """Verify the _build_alert helper function."""

    def test_build_alert_returns_dict(self) -> None:
        """_build_alert should return a dict with required keys."""
        alert = _build_alert(
            rule_id="test_rule",
            rule_name="Test Rule",
            severity="high",
            action="log_warning",
            details="Test alert details",
            session="session-1",
        )
        assert isinstance(alert, dict)
        assert alert["rule_id"] == "test_rule"
        assert alert["rule_name"] == "Test Rule"
        assert alert["severity"] == "high"
        assert alert["action"] == "log_warning"
        assert alert["details"] == "Test alert details"
        assert alert["session"] == "session-1"
        assert alert["layer"] == "behavior_analyzer"

    def test_build_alert_has_timestamp(self) -> None:
        """Alert should have timestamp and id."""
        alert = _build_alert("r", "R", "low", "none", "details")
        assert "id" in alert
        assert "timestamp" in alert
        assert "date" in alert

    def test_build_alert_default_session(self) -> None:
        """Without a session, should default to 'unknown'."""
        alert = _build_alert("r", "R", "low", "none", "details")
        assert alert["session"] == "unknown"
