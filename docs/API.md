# WineShield REST API

## Base URL

The dashboard server runs by default at `http://127.0.0.1:5000`.

## Endpoints

### `GET /api/status`

Returns the current system status, active layers, and event counters.

**Response:**
```json
{
  "status": "running",
  "active_sessions": 0,
  "total_events": 14,
  "total_sessions": 0,
  "uptime": 11.42,
  "layers": {
    "syscall_filter": "balanced",
    "filesystem_guard": "enabled",
    "network_guard": "enabled",
    "behavior_analyzer": "enabled",
    "xephyr_guard": "disabled",
    "apparmor": "enabled"
  },
  "dashboard": {
    "host": "127.0.0.1",
    "port": 5000,
    "refresh_interval_ms": 2000,
    "max_events_display": 200,
    "debug": false
  },
  "version": "1.0.0-alpha"
}
```

### `GET /api/events/latest`

Returns the most recent security events from the database.

**Query Parameters:**
- `limit` (int, default: 50) — max events to return

**Response:**
```json
{
  "total": 14,
  "events": [
    {
      "id": 1,
      "timestamp": "2026-06-09T23:55:05",
      "layer": "network_guard",
      "severity": "info",
      "action": "NetworkGuard initialised",
      "details": {}
    }
  ]
}
```

### `WebSocket — ws://127.0.0.1:5000/ws`

Real-time event stream. The server pushes new events as they arrive:

```json
{
  "type": "event",
  "data": {
    "timestamp": "2026-06-09T23:55:06",
    "layer": "behavior_analyzer",
    "severity": "warning",
    "action": "Suspicious file write pattern detected",
    "details": {"file_count": 120, "rate": 10178}
  }
}
```

### `POST /api/layer/<name>/toggle`

Enable or disable a security layer at runtime.

**Body:**
```json
{
  "enabled": false
}
```

**Response:**
```json
{
  "layer": "network_guard",
  "enabled": false,
  "status": "ok"
}
```
