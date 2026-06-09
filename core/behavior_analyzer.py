#!/usr/bin/env python3
"""
WineShield — Behavior Analyzer (Layer 4)

Runtime behavioural pattern detection for Wine processes.

Detects suspicious behavioural patterns using rules from
``config/behavior_rules.json``, including rate-based thresholds,
event sequences, single-event triggers, and periodic beaconing.

Detection types
---------------
* **rate** — Count events per second, trigger if above threshold.
* **sequence** — Detect event A followed by event B within a time window.
* **single** — One occurrence of a specific event triggers an alert.
* **pattern** — Periodic behaviour detection (e.g. C2 beaconing).

Usage::

    analyzer = BehaviorAnalyzer(config_dict)
    analyzer.start_monitoring(session_id)
    analyzer.ingest_event(some_event)
    ...
    alerts = analyzer.get_alerts()
    analyzer.stop_monitoring()
    analyzer.cleanup()
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from collections import defaultdict
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Built-in fallback rules ────────────────────────────────────
# Used when config/behavior_rules.json is missing or unreadable.
_FALLBACK_RULES: dict = {
    "version": "1.0.0-fallback",
    "description": "Built-in fallback rules (config file not found)",
    "global": {
        "analyzer_enabled": True,
        "suspension_enabled": True,
        "cooldown_seconds": 30,
        "min_data_points": 1,
    },
    "patterns": [
        {
            "id": "ransomware_file_flood",
            "name": "Ransomware — Rapid File Write",
            "detection_type": "rate",
            "metric": "files_written_per_second",
            "threshold": 50,
            "window_seconds": 5,
            "severity": "critical",
            "action": "suspend_process",
            "source_layer": "filesystem_guard",
        },
        {
            "id": "worm_connection_spray",
            "name": "Network Worm — Connection Spray",
            "detection_type": "rate",
            "metric": "unique_outbound_connections_per_second",
            "threshold": 15,
            "window_seconds": 10,
            "severity": "critical",
            "action": "kill_process",
            "source_layer": "network_guard",
        },
        {
            "id": "privilege_escalation_ptrace",
            "name": "Privilege Escalation — ptrace Attempt",
            "detection_type": "single",
            "metric": "ptrace_attempt",
            "severity": "critical",
            "action": "kill_process",
            "source_layer": "syscall_filter",
        },
        {
            "id": "data_exfiltration",
            "name": "Data Exfiltration — Read then Send",
            "detection_type": "sequence",
            "sequence": [
                {"event": "file_read", "within_seconds": 5},
                {"event": "network_send", "bytes_threshold": 1000, "within_seconds": 5},
            ],
            "severity": "critical",
            "action": "kill_process",
            "source_layer": "behavior_analyzer",
        },
        {
            "id": "beaconing",
            "name": "C2 Beaconing — Periodic Connection",
            "detection_type": "pattern",
            "metric": "periodic_connection",
            "min_periods": 3,
            "tolerance_seconds": 5,
            "severity": "high",
            "action": "log_warning",
            "source_layer": "network_guard",
        },
    ],
}


def _build_alert(
    rule_id: str,
    rule_name: str,
    severity: str,
    action: str,
    details: str,
    session: str | None = None,
) -> dict:
    """Build a structured alert in the unified WineShield format."""
    now = datetime.now()
    return {
        "id": str(uuid.uuid4()),
        "timestamp": now.isoformat(),
        "date": now.strftime("%Y-%m-%d"),
        "severity": severity,
        "layer": "behavior_analyzer",
        "action": action,
        "details": details,
        "rule_id": rule_id,
        "rule_name": rule_name,
        "session": session or "unknown",
    }


# ═══════════════════════════════════════════════════════════════
#  BehaviorAnalyzer
# ═══════════════════════════════════════════════════════════════


class BehaviorAnalyzer:
    """
    Behavioural pattern detection engine for WineShield.

    Processes security events from lower layers and applies detection
    rules (rate, sequence, single, pattern) to identify malicious or
    suspicious behaviour in Wine processes.

    Parameters
    ----------
    config_dict : dict
        The full WineShield configuration dictionary (from
        ``config/default_policy.json`` or equivalent).
    session_id : str, optional
        An optional session identifier for logging and event
        correlation.  A UUID is generated if not provided.
    """

    def __init__(
        self,
        config_dict: dict,
        session_id: str | None = None,
    ) -> None:
        self.config = config_dict
        self.session_id = session_id or str(uuid.uuid4())
        self._log = logging.getLogger(__name__)

        # ── Rule state (populated by _load_rules) ──────────────
        self._rules: list[dict] = []
        self._rules_enabled: bool = True
        self._suspension_enabled: bool = True
        self._cooldown_seconds: int = 30
        self._min_data_points: int = 3

        self._load_rules()

        # ── Monitoring thread ──────────────────────────────────
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

        # ── Thread-safe event tracking ─────────────────────────
        self._lock = threading.Lock()

        # Rate tracking:  rule_id -> list of timestamps (float)
        self._rate_windows: dict[str, list[float]] = defaultdict(list)

        # Sequence tracking:  rule_id -> list of pending states
        self._pending_sequences: dict[str, list[dict]] = defaultdict(list)

        # Pattern (beaconing) tracking:  "rule_id:dest" -> list of timestamps
        self._pattern_timestamps: dict[str, list[float]] = defaultdict(list)

        # Generated alerts (accumulated since last get_alerts())
        self._alerts: list[dict] = []

        # Suspension state
        self._suspended: bool = False
        self._last_suspension_time: float = 0.0

        # Statistics
        self._events_processed: int = 0
        self._alerts_generated: int = 0

        self._log.info(
            "BehaviorAnalyzer initialised (session=%s, rules=%d)",
            self.session_id,
            len(self._rules),
        )

    # ───────────────────────────────────────────────────────────
    #  Rules loading
    # ───────────────────────────────────────────────────────────

    def _load_rules(self) -> None:
        """Load rules from ``config/behavior_rules.json`` or fallback.

        Tries the path from the config dict first, then a set of
        default locations.  If all fail, built-in fallback rules
        are used so the analyzer never starts with an empty rule set.
        """
        rules_path = self._resolve_rules_path()
        if rules_path is not None and rules_path.is_file():
            try:
                raw = rules_path.read_text(encoding="utf-8")
                data = json.loads(raw)
                self._parse_rules(data)
                self._log.info(
                    "Loaded %d rules from %s", len(self._rules), rules_path,
                )
                return
            except (json.JSONDecodeError, OSError) as exc:
                self._log.warning(
                    "Failed to load rules from %s: %s.  Using fallback rules.",
                    rules_path,
                    exc,
                )
        else:
            self._log.info(
                "Rules file not found at %s.  Using fallback rules.", rules_path,
            )

        # Fallback: built-in rules ensure the analyzer always works
        self._parse_rules(_FALLBACK_RULES)
        self._log.info("Loaded %d fallback built-in rules", len(self._rules))

    def _resolve_rules_path(self) -> Path | None:
        """Resolve the filesystem path to ``behavior_rules.json``.

        Checks (in order):
        1. The path from ``config.behavior.rules_file`` (if set).
        2. ``config/behavior_rules.json`` relative to CWD.
        3. ``config/behavior_rules.json`` relative to this file's parent.
        4. ``~/.wineshield/config/behavior_rules.json``.

        Returns the first existing path, or the most likely path if
        none exist yet.
        """
        # 1. From config dict
        behavior_cfg = self.config.get("behavior", {})
        rules_file: str = behavior_cfg.get("rules_file", "")

        candidates: list[Path] = []

        if rules_file:
            p = Path(rules_file)
            if p.is_absolute():
                candidates.append(p)
            else:
                candidates.extend([
                    Path.cwd() / rules_file,
                    Path(__file__).resolve().parent.parent / rules_file,
                    Path.home() / ".wineshield" / rules_file,
                ])

        # 2. Default locations
        candidates.extend([
            Path.cwd() / "config" / "behavior_rules.json",
            Path(__file__).resolve().parent.parent / "config" / "behavior_rules.json",
            Path.home() / ".wineshield" / "config" / "behavior_rules.json",
        ])

        for c in candidates:
            if c.is_file():
                return c.resolve()

        # Return the first candidate even if it doesn't exist yet
        # (so the caller can report a meaningful path)
        return candidates[0] if candidates else None

    def _parse_rules(self, data: dict) -> None:
        """Parse and validate rules from a loaded JSON dict.

        Sets global configuration from ``data["global"]`` and
        populates ``self._rules`` with validated rule dicts.

        Parameters
        ----------
        data : dict
            Parsed JSON contents from ``behavior_rules.json``.
        """
        global_cfg = data.get("global", {})
        self._rules_enabled = bool(global_cfg.get("analyzer_enabled", True))
        self._suspension_enabled = bool(global_cfg.get("suspension_enabled", True))
        self._cooldown_seconds = int(global_cfg.get("cooldown_seconds", 30))
        self._min_data_points = int(global_cfg.get("min_data_points", 3))

        raw_patterns = data.get("patterns", [])
        self._rules = []
        for rule in raw_patterns:
            if self._validate_rule(rule):
                self._rules.append(rule)
            else:
                self._log.warning(
                    "Skipping malformed rule: %s",
                    rule.get("id", rule.get("name", "unknown")),
                )

    @staticmethod
    def _validate_rule(rule: dict) -> bool:
        """Validate that a rule dict has the required fields for its type.

        Returns ``True`` if the rule is well-formed, ``False`` otherwise.
        """
        if not isinstance(rule, dict):
            return False

        rule_id = rule.get("id")
        if not rule_id or not isinstance(rule_id, str):
            return False

        det_type = rule.get("detection_type")
        if det_type not in ("rate", "sequence", "single", "pattern"):
            return False

        if det_type == "rate":
            required = ("metric", "threshold", "window_seconds", "severity", "action")
        elif det_type == "sequence":
            required = ("sequence", "severity", "action")
        elif det_type == "single":
            required = ("metric", "severity", "action")
        elif det_type == "pattern":
            required = ("metric", "min_periods", "tolerance_seconds", "severity", "action")
        else:
            return False

        for key in required:
            if key not in rule:
                return False

        # Extra validation for sequences
        if det_type == "sequence":
            seq = rule.get("sequence", [])
            if not isinstance(seq, list) or len(seq) < 2:
                return False
            for step in seq:
                if not isinstance(step, dict) or "event" not in step:
                    return False

        return True

    # ───────────────────────────────────────────────────────────
    #  Lifecycle: start / stop
    # ───────────────────────────────────────────────────────────

    def start_monitoring(self, session_id: str | None = None) -> None:
        """Start the background analysis thread.

        Called by the launcher.  Accepts an optional *session_id*
        to override the default.  If the thread is already running
        this is a no-op (logged as a warning).

        Parameters
        ----------
        session_id : str, optional
            Session identifier to use for this monitoring session.
        """
        if session_id:
            self.session_id = session_id

        if self._thread is not None and self._thread.is_alive():
            self._log.warning(
                "BehaviorAnalyzer already running — ignoring duplicate start",
            )
            return

        # Reset state for a fresh session
        self._stop_event.clear()
        self._suspended = False
        self._last_suspension_time = 0.0
        self._alerts.clear()
        self._rate_windows.clear()
        self._pending_sequences.clear()
        self._pattern_timestamps.clear()
        self._events_processed = 0
        self._alerts_generated = 0

        self._thread = threading.Thread(
            target=self._analysis_loop,
            name=f"beh-analyzer-{self.session_id[:8]}",
            daemon=True,
        )
        self._thread.start()
        self._log.info(
            "BehaviorAnalyzer monitoring started (session=%s)", self.session_id,
        )

    def start_analysis(self) -> None:
        """Alias for :meth:`start_monitoring` (no session override)."""
        self.start_monitoring()

    def stop_monitoring(self) -> None:
        """Stop the background analysis thread.

        Sets the stop event and joins the thread with a 5-second
        timeout.  Logs a warning if the thread does not stop in time.
        """
        self._stop_event.set()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=5)
            if self._thread.is_alive():
                self._log.warning(
                    "BehaviorAnalyzer thread did not stop within 5s "
                    "(session=%s)",
                    self.session_id,
                )
        self._log.info(
            "BehaviorAnalyzer monitoring stopped (session=%s)", self.session_id,
        )

    def stop_analysis(self) -> None:
        """Alias for :meth:`stop_monitoring`."""
        self.stop_monitoring()

    def _analysis_loop(self) -> None:
        """Main analysis loop — runs in a background daemon thread.

        Periodically checks rate-based and pattern-based rules.
        Sleeps for 1 second between iterations.
        """
        self._log.debug("Analysis loop started (session=%s)", self.session_id)
        while not self._stop_event.is_set():
            try:
                self._check_rules()
            except Exception as exc:
                self._log.error(
                    "Error in analysis loop: %s", exc, exc_info=True,
                )
            self._stop_event.wait(1.0)
        self._log.debug("Analysis loop exited (session=%s)", self.session_id)

    # ───────────────────────────────────────────────────────────
    #  Event ingestion
    # ───────────────────────────────────────────────────────────

    def ingest_event(self, event_dict: dict) -> None:
        """Process a security event from any lower layer.

        Records the event for rate / sequence / pattern analysis and
        immediately checks single-event rules.

        Parameters
        ----------
        event_dict : dict
            A structured event dict in the unified WineShield format.
            Must contain at least a ``"layer"`` key and an ``"action"`` key.
        """
        # Validate input
        if not isinstance(event_dict, dict):
            self._log.warning(
                "Ingested non-dict event: %s", type(event_dict).__name__,
            )
            return
        if not self._rules_enabled:
            return

        # Extract common fields
        layer = event_dict.get("layer", "")
        action = event_dict.get("action", "")
        details = event_dict.get("details", "")
        severity = event_dict.get("severity", "info")

        if not layer and not action:
            self._log.debug("Ingested event with no layer/action — skipping")
            return

        with self._lock:
            self._events_processed += 1

        self._log.debug(
            "Ingesting event: layer=%s action=%s", layer, action,
        )

        # Process each rule
        for rule in self._rules:
            rule_id: str = rule.get("id", "unknown")

            try:
                det_type = rule.get("detection_type")

                # Most rules specify a source_layer that events must match
                source_layer = rule.get("source_layer", "")
                if source_layer and source_layer != "behavior_analyzer":
                    if source_layer != layer:
                        continue

                if det_type == "rate":
                    self._process_rate_event(rule, action, details)
                elif det_type == "single":
                    self._process_single_event(rule, action, details)
                elif det_type == "sequence":
                    # Sequence rules accept events from any layer
                    # (they span multiple layers by nature)
                    self._process_sequence_event(rule, action, details)
                elif det_type == "pattern":
                    self._process_pattern_event(rule, event_dict)

            except Exception as exc:
                self._log.warning(
                    "Error processing rule '%s': %s", rule_id, exc,
                )

    # ── Rate ───────────────────────────────────────────────────

    def _process_rate_event(
        self, rule: dict, action: str, details: str,
    ) -> None:
        """Record a timestamp for a rate-based rule if the event matches.

        Parameters
        ----------
        rule : dict
            The rate rule dictionary.
        action : str
            The event's action string.
        details : str
            The event's details string.
        """
        metric = rule.get("metric", "")
        if not metric:
            return

        if self._event_matches_metric(action, details, metric):
            rule_id = rule.get("id", "")
            with self._lock:
                self._rate_windows[rule_id].append(time.time())

    # ── Single ─────────────────────────────────────────────────

    def _process_single_event(
        self, rule: dict, action: str, details: str,
    ) -> None:
        """Check if a single-event rule is triggered.

        If the event matches the rule's metric an alert is generated
        immediately.

        Parameters
        ----------
        rule : dict
            The single-event rule dictionary.
        action : str
            The event's action string.
        details : str
            The event's details string.
        """
        metric = rule.get("metric", "")
        if not metric:
            return

        if self._event_matches_metric(action, details, metric):
            rule_id = rule.get("id", "unknown")
            rule_name = rule.get("name", rule_id)
            severity = rule.get("severity", "high")
            action_taken = rule.get("action", "log_warning")

            alert = _build_alert(
                rule_id=rule_id,
                rule_name=rule_name,
                severity=severity,
                action=action_taken,
                details=(
                    f"Rule '{rule_name}': {metric} detected "
                    f"(single-event trigger)"
                ),
                session=self.session_id,
            )
            self._add_alert(alert, rule)

    # ── Sequence ───────────────────────────────────────────────

    def _process_sequence_event(
        self, rule: dict, action: str, details: str,
    ) -> None:
        """Process a sequence-based rule (A → B detection).

        When the first event in the sequence arrives, a pending state
        is recorded.  If the second event arrives within the time
        window, an alert is generated.

        Parameters
        ----------
        rule : dict
            The sequence rule dictionary.
        action : str
            The event's action string.
        details : str
            The event's details string.
        """
        rule_id: str = rule.get("id", "unknown")
        sequence: list[dict] = rule.get("sequence", [])
        rule_name: str = rule.get("name", rule_id)

        if len(sequence) < 2:
            return

        # Clean expired pending entries for this rule
        now = time.time()
        max_window = self._max_sequence_window(sequence)
        with self._lock:
            self._pending_sequences[rule_id] = [
                p
                for p in self._pending_sequences[rule_id]
                if now - p["timestamp"] < max_window
            ]
            pending = list(self._pending_sequences[rule_id])

        for step_index, step in enumerate(sequence):
            expected_event = step.get("event", "")
            if action != expected_event:
                continue

            if step_index == 0:
                # First event in the sequence — start tracking
                state: dict = {
                    "step": 0,
                    "timestamp": now,
                    "data": {"action": action, "details": details},
                }
                with self._lock:
                    self._pending_sequences[rule_id].append(state)
                self._log.debug(
                    "Sequence '%s': step 0 matched (%s)", rule_id, action,
                )

            else:
                # Subsequent step — look for preceding match
                preceding = [p for p in pending if p["step"] == step_index - 1]
                if not preceding:
                    continue

                # Check time constraint
                within = step.get("within_seconds", 5)
                last_preceding = preceding[-1]
                elapsed = now - last_preceding["timestamp"]
                if elapsed > within:
                    continue

                # Check optional bytes_threshold on the *current* event
                bytes_threshold = step.get("bytes_threshold", 0)
                if bytes_threshold:
                    byte_count = self._extract_byte_count(details)
                    if byte_count is not None and byte_count < bytes_threshold:
                        continue

                # Sequence complete — trigger alert
                severity = rule.get("severity", "high")
                action_taken = rule.get("action", "log_warning")
                first_event = sequence[0].get("event", "?")

                alert = _build_alert(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    severity=severity,
                    action=action_taken,
                    details=(
                        f"Rule '{rule_name}': sequence detected — "
                        f"{first_event} → {action} within {within}s"
                    ),
                    session=self.session_id,
                )
                self._add_alert(alert, rule)

                # Clear pending entries for this completed sequence
                with self._lock:
                    self._pending_sequences[rule_id] = [
                        p
                        for p in self._pending_sequences[rule_id]
                        if p["step"] != step_index - 1
                    ]

    @staticmethod
    def _max_sequence_window(sequence: list[dict]) -> float:
        """Return the largest ``within_seconds`` across all sequence steps."""
        max_sec = 0.0
        for step in sequence:
            sec = step.get("within_seconds", 5)
            if isinstance(sec, (int, float)) and sec > max_sec:
                max_sec = float(sec)
        return max_sec if max_sec > 0 else 5.0

    @staticmethod
    def _extract_byte_count(text: str) -> int | None:
        """Try to extract a byte count from an event detail string.

        Looks for patterns like ``"1024 bytes"``, ``"size=4096"``,
        or a bare number near the word "byte".
        """
        lower = text.lower()
        # Pattern: "<number> bytes" or "<number> byte"
        for word in ("bytes", "byte"):
            idx = lower.find(word)
            if idx >= 0:
                # Walk backwards to find the number
                prefix = lower[:idx].strip()
                parts = prefix.rsplit(None, 1)
                if parts:
                    try:
                        return int(parts[-1])
                    except ValueError:
                        pass
        # Pattern: "size=<number>"
        if "size=" in lower:
            after = lower.split("size=", 1)[1]
            num_part = after.split()[0].rstrip(",")
            try:
                return int(num_part)
            except ValueError:
                pass
        return None

    # ── Pattern (beaconing) ───────────────────────────────────

    def _process_pattern_event(
        self, rule: dict, event_dict: dict,
    ) -> None:
        """Record a timestamp for pattern (beaconing) analysis.

        Parameters
        ----------
        rule : dict
            The pattern rule dictionary.
        event_dict : dict
            The full event dict from which a destination is extracted.
        """
        rule_id = rule.get("id", "")
        metric = rule.get("metric", "")
        if not metric or not rule_id:
            return

        dest = self._extract_destination(event_dict)
        if dest:
            key = f"{rule_id}:{dest}"
            with self._lock:
                self._pattern_timestamps[key].append(time.time())

    @staticmethod
    def _extract_destination(event_dict: dict) -> str | None:
        """Extract a destination identifier from an event.

        Tries to find:
        1. An IP address in the action or details.
        2. A hostname after ``to``, ``host=``, or ``dst=``.
        3. Falls back to the event's ``layer``.

        Returns a string label or ``None``.
        """
        action = event_dict.get("action", "")
        details = event_dict.get("details", "")
        text = f"{action} {details}"

        # 1. IP address pattern
        # Simple IPv4 check (sufficient for typical C2 detection)
        tokens = text.split()
        for token in tokens:
            token = token.strip(".,:;\"'()[]")
            parts = token.split(".")
            if len(parts) == 4:
                if all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                    return token

        # 2. Hostname after known keywords
        keywords = ("to ", "host=", "dst=", "destination=")
        lower_text = text.lower()
        for kw in keywords:
            idx = lower_text.find(kw)
            if idx >= 0:
                start = idx + len(kw)
                remainder = text[start:]
                # Take the first word/path
                remainder = remainder.strip().split()[0] if remainder.strip() else ""
                if remainder:
                    return remainder

        # 3. Fallback: use layer name
        return event_dict.get("layer", None)

    # ── Metric matching helper ────────────────────────────────

    @staticmethod
    def _event_matches_metric(
        action: str, details: str, metric: str,
    ) -> bool:
        """Heuristic check if an event matches a rate/single metric name.

        Strips common suffixes (``_per_second``, ``_per_minute``,
        ``_attempt``, etc.) from the metric, splits into keywords,
        and checks if each keyword appears as a **substring** in the
        event's action or details text (case-insensitive).  Singular
        and plural forms are both tried (e.g. ``file`` and ``files``).

        Parameters
        ----------
        action : str
            Event action string.
        details : str
            Event details string.
        metric : str
            Metric name from the rule (e.g. ``files_written_per_second``).

        Returns
        -------
        bool
            ``True`` if the event plausibly matches the metric.
        """
        # Normalise the metric name to extract keywords
        m = metric.lower()

        # Strip common suffixes
        for suffix in (
            "_per_second", "_per_minute", "_per_hour",
            "_attempt", "_access", "_query",
        ):
            if m.endswith(suffix):
                m = m[: -len(suffix)]
                break

        # Split into keywords
        keywords = [kw for kw in m.split("_") if kw]
        if not keywords:
            return False

        event_text = f"{action} {details}".lower()

        def _matches(kw: str) -> bool:
            """Check if *kw* (or its singular/plural variant) appears in event text."""
            if kw in event_text:
                return True
            # Try singular if plural
            if kw.endswith("s") and len(kw) > 3:
                if kw[:-1] in event_text:
                    return True
            # Try plural if singular
            if not kw.endswith("s") and len(kw) > 2:
                if kw + "s" in event_text:
                    return True
            return False

        # Single-keyword metric — require match
        if len(keywords) == 1:
            return _matches(keywords[0])

        # Multi-keyword metric — require at least 2/3 to match
        matches = sum(1 for kw in keywords if _matches(kw))
        threshold = max(1, len(keywords) * 2 // 3)
        return matches >= threshold

    # ───────────────────────────────────────────────────────────
    #  Periodic rule checking
    # ───────────────────────────────────────────────────────────

    def _check_rules(self) -> None:
        """Periodic check of rate-based and pattern-based rules.

        Called every ~1 second from the analysis loop.

        Single-event and sequence rules are checked at ingest time
        and do not need periodic evaluation.
        """
        if not self._rules_enabled:
            return

        now = time.time()
        for rule in self._rules:
            det_type = rule.get("detection_type")
            try:
                if det_type == "rate":
                    self._check_rate_rule(rule, now)
                elif det_type == "pattern":
                    self._check_pattern_rule(rule, now)
            except Exception as exc:
                self._log.warning(
                    "Error checking rule '%s': %s",
                    rule.get("id", "unknown"), exc,
                )

    def _check_rate_rule(self, rule: dict, now: float) -> None:
        """Check if a rate-based rule's threshold has been exceeded.

        Calculates the event rate over the rule's configured window
        and triggers an alert if the rate meets or exceeds the threshold.

        Parameters
        ----------
        rule : dict
            The rate rule dictionary.
        now : float
            Current time (``time.time()``) for window calculations.
        """
        rule_id: str = rule.get("id", "")
        window_seconds: float = float(rule.get("window_seconds", 5))
        threshold: float = float(rule.get("threshold", 0))
        min_data: int = self._min_data_points

        with self._lock:
            timestamps: list[float] = list(self._rate_windows.get(rule_id, []))

        if len(timestamps) < min_data:
            return

        # Prune timestamps outside the window
        cutoff = now - window_seconds
        active = [t for t in timestamps if t >= cutoff]

        with self._lock:
            self._rate_windows[rule_id] = list(active) if active else []

        if len(active) < min_data:
            return

        # Calculate rate (events per second)
        rate = len(active) / window_seconds

        self._log.debug(
            "Rate check: rule=%s count=%d window=%.1fs rate=%.2f threshold=%.1f",
            rule_id, len(active), window_seconds, rate, threshold,
        )

        if rate >= threshold:
            rule_name = rule.get("name", rule_id)
            severity = rule.get("severity", "high")
            action_taken = rule.get("action", "log_warning")
            metric = rule.get("metric", "events")

            alert = _build_alert(
                rule_id=rule_id,
                rule_name=rule_name,
                severity=severity,
                action=action_taken,
                details=(
                    f"Rule '{rule_name}': {metric}={rate:.1f}, "
                    f"threshold={threshold:.0f} "
                    f"(over {window_seconds:.0f}s window)"
                ),
                session=self.session_id,
            )
            self._add_alert(alert, rule)

            # Reset the window to prevent repeated alerts
            with self._lock:
                self._rate_windows[rule_id] = []

    def _check_pattern_rule(self, rule: dict, now: float) -> None:
        """Check if a periodic pattern (beaconing) is detected.

        Examines the intervals between consecutive events to the same
        destination.  If the intervals are consistent (within tolerance)
        and there are enough periods, an alert is generated.

        Parameters
        ----------
        rule : dict
            The pattern rule dictionary.
        now : float
            Current time (``time.time()``).
        """
        rule_id: str = rule.get("id", "")
        min_periods: int = rule.get("min_periods", 3)
        tolerance: float = float(rule.get("tolerance_seconds", 5))

        prefix = f"{rule_id}:"

        with self._lock:
            keys = list(self._pattern_timestamps.keys())

        for key in keys:
            if not key.startswith(prefix):
                continue

            with self._lock:
                timestamps = list(self._pattern_timestamps.get(key, []))

            if len(timestamps) < min_periods:
                continue

            # Prune entries older than 1 hour
            cutoff = now - 3600.0
            active = [t for t in timestamps if t >= cutoff]

            with self._lock:
                self._pattern_timestamps[key] = list(active) if active else []

            if len(active) < min_periods:
                continue

            # Sort timestamps chronologically, then calculate intervals
            active.sort()
            intervals = [
                active[i + 1] - active[i] for i in range(len(active) - 1)
            ]
            if not intervals:
                continue

            # Check for consistent intervals
            mean_interval = sum(intervals) / len(intervals)
            if mean_interval <= 0.0:
                continue

            all_consistent = all(
                abs(iv - mean_interval) <= tolerance for iv in intervals
            )

            if all_consistent and len(intervals) >= min_periods - 1:
                dest = key.split(":", 1)[1] if ":" in key else "unknown"
                rule_name = rule.get("name", rule_id)
                severity = rule.get("severity", "high")
                action_taken = rule.get("action", "log_warning")

                alert = _build_alert(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    severity=severity,
                    action=action_taken,
                    details=(
                        f"Rule '{rule_name}': periodic pattern detected "
                        f"to {dest} "
                        f"(interval={mean_interval:.1f}s, "
                        f"periods={len(active)})"
                    ),
                    session=self.session_id,
                )
                self._add_alert(alert, rule)

                # Reset to prevent repeated alerts
                with self._lock:
                    self._pattern_timestamps[key] = []

    # ───────────────────────────────────────────────────────────
    #  Alert management & suspension
    # ───────────────────────────────────────────────────────────

    def _add_alert(self, alert: dict, rule: dict) -> None:
        """Record a generated alert and apply suspension if needed.

        If the alert is *critical* and the suspension mechanism is
        enabled, the ``_suspended`` flag is set and the launcher can
        act on it (e.g. kill the Wine process).  A cooldown prevents
        repeated suspension in quick succession.

        Parameters
        ----------
        alert : dict
            The alert dict (see :func:`_build_alert`).
        rule : dict
            The rule dict that triggered this alert (used for
            suspension decisions).
        """
        with self._lock:
            self._alerts.append(dict(alert))
            self._alerts_generated += 1

        severity = alert.get("severity", "info")
        self._log.log(
            logging.CRITICAL if severity == "critical" else logging.WARNING,
            "BEHAVIOR ALERT [%s] %s",
            severity.upper(),
            alert["details"],
        )

        # ── Suspension mechanism ──────────────────────────────
        if (
            self._suspension_enabled
            and severity == "critical"
        ):
            rule_action: str = rule.get("action", "")
            if rule_action in ("suspend_process", "kill_process"):
                now = time.time()
                if now - self._last_suspension_time >= self._cooldown_seconds:
                    self._suspended = True
                    self._last_suspension_time = now
                    self._log.critical(
                        "SUSPENSION TRIGGERED by rule '%s' "
                        "(session=%s, cooldown=%ds)",
                        rule.get("name", rule.get("id", "unknown")),
                        self.session_id,
                        self._cooldown_seconds,
                    )

    def get_alerts(self) -> list[dict]:
        """Return the list of generated alerts and clear the internal buffer.

        Returns
        -------
        list[dict]
            A (possibly empty) list of alert dicts accumulated since
            the last call to this method.
        """
        with self._lock:
            alerts = list(self._alerts)
            self._alerts.clear()
        return alerts

    def is_suspended(self) -> bool:
        """Check whether the process has been suspended by a critical alert.

        Returns
        -------
        bool
            ``True`` if a critical alert triggered suspension.
        """
        return self._suspended

    # ───────────────────────────────────────────────────────────
    #  Cleanup
    # ───────────────────────────────────────────────────────────

    def cleanup(self) -> None:
        """Stop monitoring, log summary, and reset state.

        Should be called when the Wine session ends.  Prints a
        statistics summary to stdout and logs the same information.
        """
        self.stop_monitoring()

        alert_count = len(self._alerts) + self._alerts_generated

        # Log summary
        self._log.info(
            "BehaviorAnalyzer cleanup — session=%s, "
            "events_processed=%d, alerts_generated=%d, suspended=%s",
            self.session_id,
            self._events_processed,
            alert_count,
            self._suspended,
        )

        # Print summary to stdout (visible in terminal/cli)
        print()
        print("=" * 60)
        print("  BehaviorAnalyzer — Session Summary")
        print("=" * 60)
        print(f"  Session ID:       {self.session_id}")
        print(f"  Events processed:  {self._events_processed}")
        print(f"  Alerts generated:  {alert_count}")
        print(f"  Rules loaded:      {len(self._rules)}")
        print(f"  Suspension active: {self._suspended}")
        print(f"  Rules file:        {self._resolve_rules_path() or 'fallback'}")
        print("=" * 60)
        print()

        # Reset internal state
        with self._lock:
            self._rate_windows.clear()
            self._pending_sequences.clear()
            self._pattern_timestamps.clear()
            self._alerts.clear()
            self._alerts_generated = 0
            self._events_processed = 0
            self._suspended = False
            self._last_suspension_time = 0.0
