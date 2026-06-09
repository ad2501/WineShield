#!/usr/bin/env python3
"""
WineShield — Dashboard Backend
================================

Flask + WebSocket + SQLite server that watches the WineShield event log,
stores events in SQLite, and serves them via REST API and WebSocket for
the browser frontend.

Architecture
------------
  1. SQLite Database    — stores events and sessions at ~/.wineshield/dashboard.db
  2. Log Watcher Thread — polls ~/.wineshield/events.log every second,
                          parses new JSON lines, persists to DB, broadcasts
                          via WebSocket.
  3. Flask API          — REST endpoints for events, stats, sessions, layers.
  4. WebSocket (SocketIO) — real-time push of new events, stats, layer changes.

Usage
-----
    python3 dashboard/app.py

Server runs on port 5000 by default (configurable in config/default_policy.json
under "dashboard.port").
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import flask
from flask import Flask, jsonify, request, render_template, send_from_directory
from flask_socketio import SocketIO, emit

# ─────────────────────────────────────────────────────────────────────
#  Logging
# ─────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
    stream=sys.stderr,
)
_log = logging.getLogger("dashboard")

# ─────────────────────────────────────────────────────────────────────
#  Paths & Configuration
# ─────────────────────────────────────────────────────────────────────

WINESHIELD_HOME = os.path.expanduser("~/.wineshield")
EVENTS_LOG_PATH = os.path.join(WINESHIELD_HOME, "events.log")
DB_PATH = os.path.join(WINESHIELD_HOME, "dashboard.db")
CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "config",
    "default_policy.json",
)

# ── Flask & SocketIO ────────────────────────────────────────────

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "templates"),
    static_folder=os.path.join(os.path.dirname(__file__), "static"),
)
app.config["SECRET_KEY"] = os.urandom(24).hex()
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ─────────────────────────────────────────────────────────────────────
#  1. SQLite Database
# ─────────────────────────────────────────────────────────────────────

_DB_LOCAL = threading.local()


def _get_db() -> sqlite3.Connection:
    """Get a thread-local SQLite connection."""
    if not hasattr(_DB_LOCAL, "conn") or _DB_LOCAL.conn is None:
        os.makedirs(WINESHIELD_HOME, mode=0o755, exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        _DB_LOCAL.conn = conn
    return _DB_LOCAL.conn


def init_db() -> None:
    """Create tables if they do not exist."""
    conn = _get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id          TEXT PRIMARY KEY,
            timestamp   TEXT NOT NULL,
            date        TEXT NOT NULL,
            severity    TEXT NOT NULL,
            layer       TEXT NOT NULL,
            action      TEXT NOT NULL,
            details     TEXT DEFAULT '{}',
            pid         INTEGER DEFAULT 0,
            process     TEXT DEFAULT '',
            session     TEXT DEFAULT '',
            created_at  TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_severity  ON events(severity);
        CREATE INDEX IF NOT EXISTS idx_events_layer     ON events(layer);
        CREATE INDEX IF NOT EXISTS idx_events_session   ON events(session);

        CREATE TABLE IF NOT EXISTS sessions (
            session_id  TEXT PRIMARY KEY,
            start_time  TEXT,
            end_time    TEXT,
            mode        TEXT DEFAULT '',
            layers      TEXT DEFAULT '[]',
            event_count INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS server_meta (
            key   TEXT PRIMARY KEY,
            value TEXT
        );
    """)
    conn.commit()
    _log.info("Database initialised at %s", DB_PATH)


# ─────────────────────────────────────────────────────────────────────
#  2. Log Watcher Thread
# ─────────────────────────────────────────────────────────────────────

class LogWatcher:
    """
    Polling-based watcher for ~/.wineshield/events.log.

    Every second, checks for new lines appended to the log file, parses
    them as JSON, stores them in SQLite, and broadcasts via WebSocket.
    """

    def __init__(self) -> None:
        self._log_path: str = EVENTS_LOG_PATH
        self._last_position: int = 0
        self._running: bool = False
        self._thread: Optional[threading.Thread] = None
        self._lock: threading.Lock = threading.Lock()
        self._stats_interval: float = 5.0  # seconds between stats broadcasts
        self._total_events_watched: int = 0

    def start(self) -> None:
        """Start the watcher thread (daemon)."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True, name="log-watcher")
        self._thread.start()
        _log.info("Log watcher started (polling %s)", self._log_path)

    def stop(self) -> None:
        """Signal the watcher thread to stop."""
        self._running = False

    @property
    def total_events(self) -> int:
        return self._total_events_watched

    def _init_position(self) -> None:
        """Initialise file position to the end of the log (don't replay old events on restart)."""
        try:
            if os.path.isfile(self._log_path):
                self._last_position = os.path.getsize(self._log_path)
            else:
                self._last_position = 0
        except OSError:
            self._last_position = 0

    def _run(self) -> None:
        """Main watcher loop."""
        self._init_position()
        last_stats_broadcast = time.monotonic()

        while self._running:
            try:
                new_events = self._poll()
                for event_data in new_events:
                    self._store_event(event_data)
                    self._total_events_watched += 1
                    # Broadcast to WebSocket clients
                    socketio.emit("new_event", event_data, namespace="/ws/events")

                # Periodic stats broadcast
                now = time.monotonic()
                if now - last_stats_broadcast >= self._stats_interval:
                    stats = self._compute_stats()
                    socketio.emit("stats_update", stats, namespace="/ws/events")
                    last_stats_broadcast = now

            except Exception as exc:
                _log.warning("Log watcher error: %s", exc)

            time.sleep(1.0)

    def _poll(self) -> List[Dict[str, Any]]:
        """
        Read new lines from the events log since last poll.

        Returns a list of parsed event dicts.
        """
        if not os.path.isfile(self._log_path):
            return []

        try:
            with open(self._log_path, "r", encoding="utf-8") as fh:
                fh.seek(self._last_position)
                lines = fh.readlines()
                self._last_position = fh.tell()
        except OSError as exc:
            _log.warning("Cannot read events log: %s", exc)
            return []

        events: List[Dict[str, Any]] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
                # Handle double-encoded JSON: if parsed is a string, try parsing it again
                if isinstance(parsed, str):
                    try:
                        parsed = json.loads(parsed)
                    except (json.JSONDecodeError, TypeError):
                        _log.debug("Skipping invalid string line in events.log: %s", line[:80])
                        continue
                if not isinstance(parsed, dict):
                    _log.debug("Skipping non-dict line in events.log: %s", line[:80])
                    continue
                event: Dict[str, Any] = parsed
                # Ensure all expected keys exist
                event.setdefault("id", str(uuid.uuid4()))
                event.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
                event.setdefault("date", datetime.now(timezone.utc).strftime("%Y-%m-%d"))
                event.setdefault("severity", "info")
                event.setdefault("layer", "unknown")
                event.setdefault("action", "")
                event.setdefault("details", {})
                if isinstance(event.get("details"), dict):
                    event["details"] = json.dumps(event["details"])
                elif isinstance(event.get("details"), str):
                    # Validate it's JSON; if not, wrap it
                    try:
                        json.loads(event["details"])
                    except (json.JSONDecodeError, TypeError):
                        event["details"] = json.dumps({"message": event["details"]})
                else:
                    event["details"] = json.dumps({})
                event.setdefault("pid", 0)
                event.setdefault("process", "")
                event.setdefault("session", "")
                events.append(event)
            except json.JSONDecodeError:
                _log.debug("Skipping non-JSON line in events.log: %s", line[:80])
        return events

    def _store_event(self, event: Dict[str, Any]) -> None:
        """Insert a parsed event into SQLite."""
        try:
            conn = _get_db()
            conn.execute(
                """INSERT OR IGNORE INTO events
                   (id, timestamp, date, severity, layer, action, details,
                    pid, process, session)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.get("id", ""),
                    event.get("timestamp", ""),
                    event.get("date", ""),
                    event.get("severity", ""),
                    event.get("layer", ""),
                    event.get("action", ""),
                    event.get("details", "{}"),
                    event.get("pid", 0),
                    event.get("process", ""),
                    event.get("session", ""),
                ),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            pass  # Duplicate event ID — skip
        except sqlite3.Error as exc:
            _log.warning("DB insert error: %s", exc)

    def _compute_stats(self) -> Dict[str, Any]:
        """Compute aggregate statistics from the events table."""
        try:
            conn = _get_db()
            cursor = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM events GROUP BY severity"
            )
            by_severity = {row["severity"]: row["cnt"] for row in cursor.fetchall()}

            cursor = conn.execute(
                "SELECT layer, COUNT(*) as cnt FROM events GROUP BY layer"
            )
            by_layer = {row["layer"]: row["cnt"] for row in cursor.fetchall()}

            cursor = conn.execute("SELECT COUNT(*) as total FROM events")
            total = cursor.fetchone()["total"]

            return {
                "events_by_severity": by_severity,
                "events_by_layer": by_layer,
                "total_events": total,
            }
        except sqlite3.Error as exc:
            _log.warning("Stats computation error: %s", exc)
            return {"events_by_severity": {}, "events_by_layer": {}, "total_events": 0}


# ─────────────────────────────────────────────────────────────────────
#  Server lifecycle / Uptime tracking
# ─────────────────────────────────────────────────────────────────────

_START_TIME: float = time.time()


def uptime_seconds() -> float:
    return time.time() - _START_TIME


def load_config() -> Dict[str, Any]:
    """Load the WineShield configuration from default_policy.json."""
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        _log.warning("Cannot load config: %s — using defaults", exc)
        return {}


def get_active_layers(config: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """
    Return a dict mapping layer name → current mode string.

    For seccomp-based layers this is one of monitor/balanced/strict.
    For others it is enabled/disabled.
    """
    if config is None:
        config = load_config()

    layers_config = config.get("layers", {})
    seccomp_mode = config.get("seccomp", {}).get("default_mode", "balanced")

    result: Dict[str, str] = {}
    for layer_name, layer_cfg in layers_config.items():
        if isinstance(layer_cfg, dict):
            enabled = layer_cfg.get("enabled", False)
            # Special handling: the syscall_filter uses seccomp modes
            if layer_name == "syscall_filter":
                result[layer_name] = seccomp_mode if enabled else "disabled"
            else:
                result[layer_name] = "enabled" if enabled else "disabled"
    return result


# ─────────────────────────────────────────────────────────────────────
#  Layer Toggle Implementation
# ─────────────────────────────────────────────────────────────────────

def toggle_layer_mode(layer_name: str) -> Optional[Dict[str, str]]:
    """
    Toggle a layer's mode in the config file.

    For seccomp layers (syscall_filter): cycles monitor → balanced → strict → monitor.
    For other layers: toggles enabled ↔ disabled.

    Returns dict with old_mode and new_mode, or None on failure.
    """
    config = load_config()
    if not config:
        return None

    layers = config.get("layers", {})
    if layer_name not in layers:
        _log.warning("Attempted to toggle unknown layer: %s", layer_name)
        return None

    layer_cfg = layers[layer_name]
    old_state: str

    if layer_name == "syscall_filter":
        # Seccomp mode cycling: monitor → balanced → strict → monitor
        seccomp_cfg = config.setdefault("seccomp", {})
        current_mode = seccomp_cfg.get("default_mode", "balanced")
        cycle = ["monitor", "balanced", "strict"]
        try:
            idx = cycle.index(current_mode)
        except ValueError:
            idx = 0
        new_mode = cycle[(idx + 1) % len(cycle)]
        old_state = current_mode
        new_state = new_mode
        seccomp_cfg["default_mode"] = new_mode
        # Ensure the layer is enabled when a mode is set
        layer_cfg["enabled"] = True
    else:
        # Generic on/off toggle
        old_state = "enabled" if layer_cfg.get("enabled", False) else "disabled"
        new_enabled = not layer_cfg.get("enabled", False)
        layer_cfg["enabled"] = new_enabled
        new_state = "enabled" if new_enabled else "disabled"

    # Write updated config
    try:
        os.makedirs(os.path.dirname(CONFIG_PATH), mode=0o755, exist_ok=True)
        with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
            json.dump(config, fh, indent=2)
            fh.write("\n")
    except OSError as exc:
        _log.error("Failed to write config: %s", exc)
        return None

    # Log the change as a security event (write to the events log)
    log_change_event(layer_name, old_state, new_state)

    # Broadcast via WebSocket
    socketio.emit(
        "layer_change",
        {"layer": layer_name, "old_mode": old_state, "new_mode": new_state},
        namespace="/ws/events",
    )

    return {"old_mode": old_state, "new_mode": new_state}


def log_change_event(layer: str, old_state: str, new_state: str) -> None:
    """Write a layer-toggle event to the events.log file."""
    event = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "severity": "info",
        "layer": "dashboard",
        "action": f"Layer '{layer}' toggled: {old_state} → {new_state}",
        "details": json.dumps({"layer": layer, "old_mode": old_state, "new_mode": new_state}),
        "pid": os.getpid(),
        "process": "dashboard",
        "session": "",
    }
    try:
        os.makedirs(os.path.dirname(EVENTS_LOG_PATH), mode=0o755, exist_ok=True)
        with open(EVENTS_LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, default=str) + "\n")
    except OSError as exc:
        _log.warning("Failed to log layer change event: %s", exc)


# ─────────────────────────────────────────────────────────────────────
#  Global watcher instance
# ─────────────────────────────────────────────────────────────────────

_watcher = LogWatcher()


# ─────────────────────────────────────────────────────────────────────
#  3. Flask API Routes
# ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the dashboard frontend."""
    return render_template("index.html")


@app.route("/static/<path:filename>")
def static_files(filename: str):
    """Serve static files from the dashboard/static directory."""
    return send_from_directory(app.static_folder or "static", filename)


# ── /api/status ─────────────────────────────────────────────────

@app.route("/api/status")
def api_status():
    """Return server status and summary metrics."""
    config = load_config()
    dash_cfg = config.get("dashboard", {})
    layers = get_active_layers(config)

    try:
        conn = _get_db()
        cursor = conn.execute("SELECT COUNT(*) as cnt FROM events")
        total_events = cursor.fetchone()["cnt"]
        cursor = conn.execute("SELECT COUNT(*) as cnt FROM sessions")
        total_sessions = cursor.fetchone()["cnt"]
        cursor = conn.execute("SELECT COUNT(DISTINCT session) as cnt FROM events WHERE session != ''")
        active_sessions = cursor.fetchone()["cnt"]
    except sqlite3.Error:
        total_events = 0
        total_sessions = 0
        active_sessions = 0

    return jsonify({
        "status": "running",
        "version": config.get("version", "unknown"),
        "uptime": round(uptime_seconds(), 2),
        "total_events": total_events,
        "total_sessions": total_sessions,
        "active_sessions": active_sessions,
        "layers": layers,
        "dashboard": {
            "host": dash_cfg.get("host", "127.0.0.1"),
            "port": dash_cfg.get("port", 5000),
            "debug": dash_cfg.get("debug", False),
            "refresh_interval_ms": dash_cfg.get("refresh_interval_ms", 2000),
            "max_events_display": dash_cfg.get("max_events_display", 200),
        },
    })


# ── /api/events ─────────────────────────────────────────────────

@app.route("/api/events")
def api_events():
    """Return paginated events with optional filters."""
    limit = request.args.get("limit", default=100, type=int)
    offset = request.args.get("offset", default=0, type=int)
    severity = request.args.get("severity", default=None, type=str)
    layer = request.args.get("layer", default=None, type=str)
    session = request.args.get("session", default=None, type=str)

    # Clamp limit
    limit = max(1, min(limit, 1000))

    query = "SELECT * FROM events WHERE 1=1"
    params: List[Any] = []

    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if layer:
        query += " AND layer = ?"
        params.append(layer)
    if session:
        query += " AND session = ?"
        params.append(session)

    # Count first
    count_query = query.replace("SELECT *", "SELECT COUNT(*) as cnt")
    try:
        conn = _get_db()
        total = conn.execute(count_query, params).fetchone()["cnt"]
    except sqlite3.Error:
        total = 0

    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    try:
        conn = _get_db()
        rows = conn.execute(query, params).fetchall()
    except sqlite3.Error as exc:
        _log.warning("Events query error: %s", exc)
        rows = []

    events = [_row_to_event(r) for r in rows]

    return jsonify({
        "total": total,
        "limit": limit,
        "offset": offset,
        "events": events,
    })


# ── /api/events/latest ──────────────────────────────────────────

@app.route("/api/events/latest")
def api_events_latest():
    """Return the last N events (default 100)."""
    n = request.args.get("n", default=100, type=int)
    n = max(1, min(n, 1000))
    try:
        conn = _get_db()
        rows = conn.execute(
            "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (n,)
        ).fetchall()
    except sqlite3.Error as exc:
        _log.warning("Latest events query error: %s", exc)
        rows = []
    return jsonify({
        "count": len(rows),
        "events": [_row_to_event(r) for r in rows],
    })


# ── /api/stats ──────────────────────────────────────────────────

@app.route("/api/stats")
def api_stats():
    """Return aggregated statistics."""
    try:
        conn = _get_db()

        # Events by severity
        cursor = conn.execute("SELECT severity, COUNT(*) as cnt FROM events GROUP BY severity")
        by_severity = {row["severity"]: row["cnt"] for row in cursor.fetchall()}

        # Events by layer
        cursor = conn.execute("SELECT layer, COUNT(*) as cnt FROM events GROUP BY layer")
        by_layer = {row["layer"]: row["cnt"] for row in cursor.fetchall()}

        # Total
        cursor = conn.execute("SELECT COUNT(*) as total FROM events")
        total_events = cursor.fetchone()["total"]

        # Events over time (last 24 hours, hourly buckets)
        cursor = conn.execute("""
            SELECT date(timestamp) as day,
                   CAST(strftime('%H', timestamp) AS INTEGER) as hour,
                   COUNT(*) as cnt
            FROM events
            WHERE timestamp >= datetime('now', '-1 day')
            GROUP BY day, hour
            ORDER BY day, hour
        """)
        over_time = [
            {"date": row["day"], "hour": row["hour"], "count": row["cnt"]}
            for row in cursor.fetchall()
        ]

        # Severity counts for quick reference
        cursor = conn.execute("""
            SELECT
                COALESCE(SUM(CASE WHEN severity = 'error' THEN 1 ELSE 0 END), 0) as errors,
                COALESCE(SUM(CASE WHEN severity = 'warning' THEN 1 ELSE 0 END), 0) as warnings,
                COALESCE(SUM(CASE WHEN severity = 'info' THEN 1 ELSE 0 END), 0) as infos,
                COALESCE(SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END), 0) as criticals
            FROM events
        """)
        severity_row = cursor.fetchone()

    except sqlite3.Error as exc:
        _log.warning("Stats query error: %s", exc)
        by_severity = {}
        by_layer = {}
        total_events = 0
        over_time = []
        severity_row = {"errors": 0, "warnings": 0, "infos": 0, "criticals": 0}

    return jsonify({
        "total_events": total_events,
        "events_by_severity": by_severity,
        "events_by_layer": by_layer,
        "severity_counts": {
            "error": severity_row["errors"],
            "warning": severity_row["warnings"],
            "info": severity_row["infos"],
            "critical": severity_row["criticals"],
        },
        "over_time": over_time,
    })


# ── /api/layers ─────────────────────────────────────────────────

@app.route("/api/layers")
def api_layers():
    """Return available layers and their current mode."""
    config = load_config()
    layers_config = config.get("layers", {})
    seccomp_mode = config.get("seccomp", {}).get("default_mode", "balanced")

    result: List[Dict[str, Any]] = []
    for name, cfg in layers_config.items():
        if not isinstance(cfg, dict):
            continue
        enabled = cfg.get("enabled", False)
        if name == "syscall_filter":
            status = seccomp_mode if enabled else "disabled"
        else:
            status = "enabled" if enabled else "disabled"

        result.append({
            "name": name,
            "status": status,
            "enabled": enabled,
            "description": cfg.get("description", ""),
        })

    return jsonify({"layers": result})


# ── /api/layers/{name}/toggle ───────────────────────────────────

@app.route("/api/layers/<name>/toggle", methods=["POST"])
def api_layer_toggle(name: str):
    """Toggle a layer's mode. Returns old and new state."""
    result = toggle_layer_mode(name)
    if result is None:
        return jsonify({"error": f"Unknown layer '{name}' or toggle failed"}), 404
    return jsonify({
        "layer": name,
        "old_mode": result["old_mode"],
        "new_mode": result["new_mode"],
        "message": f"Layer '{name}' toggled: {result['old_mode']} → {result['new_mode']}",
    })


# ── /api/sessions ───────────────────────────────────────────────

@app.route("/api/sessions")
def api_sessions():
    """Return all recorded sessions."""
    try:
        conn = _get_db()
        rows = conn.execute(
            "SELECT * FROM sessions ORDER BY start_time DESC"
        ).fetchall()
    except sqlite3.Error as exc:
        _log.warning("Sessions query error: %s", exc)
        rows = []

    sessions = []
    for row in rows:
        sessions.append({
            "session_id": row["session_id"],
            "start_time": row["start_time"],
            "end_time": row["end_time"],
            "mode": row["mode"],
            "layers": json.loads(row["layers"]) if row["layers"] else [],
            "event_count": row["event_count"],
        })

    return jsonify({"sessions": sessions})


# ─────────────────────────────────────────────────────────────────────
#  Helper: row → dict
# ─────────────────────────────────────────────────────────────────────

def _row_to_event(row: sqlite3.Row) -> Dict[str, Any]:
    """Convert a SQLite row to a clean event dict."""
    details_raw = row["details"]
    try:
        details = json.loads(details_raw) if isinstance(details_raw, str) else details_raw
    except (json.JSONDecodeError, TypeError):
        details = details_raw

    return {
        "id": row["id"],
        "timestamp": row["timestamp"],
        "date": row["date"],
        "severity": row["severity"],
        "layer": row["layer"],
        "action": row["action"],
        "details": details,
        "pid": row["pid"],
        "process": row["process"],
        "session": row["session"],
        "created_at": row["created_at"],
    }


# ─────────────────────────────────────────────────────────────────────
#  4. WebSocket Events (SocketIO, namespace /ws/events)
# ─────────────────────────────────────────────────────────────────────

@socketio.on("connect", namespace="/ws/events")
def ws_connect():
    """Handle WebSocket client connection."""
    _log.info("WebSocket client connected")
    emit("connected", {"status": "authenticated", "server_time": datetime.now(timezone.utc).isoformat()})


@socketio.on("disconnect", namespace="/ws/events")
def ws_disconnect():
    """Handle WebSocket client disconnection."""
    _log.info("WebSocket client disconnected")


# ─────────────────────────────────────────────────────────────────────
#  Startup
# ─────────────────────────────────────────────────────────────────────

def ensure_log_directory() -> None:
    """Create ~/.wineshield if it doesn't exist."""
    os.makedirs(WINESHIELD_HOME, mode=0o755, exist_ok=True)


# ═════════════════════════════════════════════════════════════════════
#  Main
# ═════════════════════════════════════════════════════════════════════

def main() -> None:
    """Initialise and run the dashboard server."""
    ensure_log_directory()
    init_db()

    # Start the log watcher
    _watcher.start()

    # Determine host/port from config
    config = load_config()
    dash_cfg = config.get("dashboard", {})
    host = dash_cfg.get("host", "127.0.0.1")
    port = dash_cfg.get("port", 5000)
    debug = dash_cfg.get("debug", False)

    _log.info(
        "WineShield Dashboard starting on %s:%s (debug=%s)",
        host, port, debug,
    )

    # Log a startup event
    startup_event = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "severity": "info",
        "layer": "dashboard",
        "action": "Dashboard server started",
        "details": json.dumps({"host": host, "port": port}),
        "pid": os.getpid(),
        "process": "dashboard",
        "session": "",
    }
    try:
        with open(EVENTS_LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(startup_event, default=str) + "\n")
    except OSError:
        pass  # Log directory may not exist yet — will be picked up by watcher

    try:
        socketio.run(
            app,
            host=host,
            port=port,
            debug=debug,
            allow_unsafe_werkzeug=True,
        )
    except KeyboardInterrupt:
        _log.info("Shutting down Dashboard")
    finally:
        _watcher.stop()
        _log.info("Dashboard stopped")


if __name__ == "__main__":
    main()
