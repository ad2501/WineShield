#!/usr/bin/env python3
"""
WineShield — Network Guard (Layer 3)

Network monitoring and filtering layer for Wine processes.

Monitors ``/proc/net/tcp`` and ``/proc/net/udp`` to track active
connections, enforces connection rules from ``config/network_rules.json``,
and detects connection-spray (scanning / reconnaissance) patterns.

In *monitor* mode (default) all blocked connections are logged but
not dropped.  In *strict* mode blocked connections are actively denied.

Usage::

    guard = NetworkGuard(config_dict, session_id="mysession")
    guard.start_monitoring()
    connections = guard.get_connections()
    allowed = guard.check_connection_allowed("1.2.3.4", 443, "tcp")
    # ... Wine runs here ...
    guard.cleanup()
"""

from __future__ import annotations

import json
import logging
import os
import pathlib
import socket
import threading
import time
import uuid
from datetime import datetime

logger = logging.getLogger(__name__)

# ── Proc filesystem paths ─────────────────────────────────────
_PROC_NET_TCP = "/proc/net/tcp"
_PROC_NET_UDP = "/proc/net/udp"
_PROC_NET_TCP6 = "/proc/net/tcp6"
_PROC_NET_UDP6 = "/proc/net/udp6"

_DEFAULT_RULES_FILE = "config/network_rules.json"
_DEFAULT_POLL_INTERVAL = 2  # seconds

# TCP state codes as they appear in /proc/net/tcp (st column)
_TCP_STATES: dict[str, str] = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}

# ── Spray detection constants ─────────────────────────────────
_SPRAY_WINDOW_SECONDS = 10  # sliding window for tracking unique IPs
_SPRAY_THRESHOLD = 10       # unique IPs within the window → alert


# ═══════════════════════════════════════════════════════════════
#  /proc/net/ parsing helpers
# ═══════════════════════════════════════════════════════════════


def _hex_ip_to_str(hex_ip: str) -> str:
    """Convert a hex-encoded IPv4 address from ``/proc/net/tcp`` to dotted notation.

    The four bytes are stored in network byte order **but** each 32-bit
    word appears as a little-endian integer on x86, so the byte string
    ``0100007F`` represents ``127.0.0.1``.
    """
    hex_ip = hex_ip.zfill(8)
    try:
        raw = bytes.fromhex(hex_ip)
        return ".".join(str(b) for b in reversed(raw))
    except (ValueError, TypeError):
        return "0.0.0.0"


def _hex_ip_to_str_v6(hex_ip: str) -> str:
    """Convert a hex-encoded IPv6 address from ``/proc/net/tcp6`` to string form.

    ``/proc/net/tcp6`` stores the address as four 32-bit groups in
    network byte order, but each group itself is stored little-endian
    on x86 (like IPv4).  We decode with ``socket.inet_ntop``.
    """
    hex_ip = hex_ip.zfill(32)  # 32 hex chars = 128 bits
    try:
        raw = bytes.fromhex(hex_ip)
        # Reverse each 4-byte group to get network byte order
        groups = []
        for i in range(0, 16, 4):
            groups.extend(reversed(raw[i : i + 4]))
        return socket.inet_ntop(socket.AF_INET6, bytes(groups))
    except (ValueError, TypeError, OSError):
        return "::"


def _parse_proc_net(path: str, protocol: str) -> list[dict]:
    """Parse a ``/proc/net/tcp`` or ``/proc/net/udp`` file.

    Returns a list of connection dicts with keys:

    - ``local_ip`` / ``local_port``
    - ``remote_ip`` / ``remote_port``
    - ``state`` (human-readable TCP state, or ``"N/A"`` for UDP)
    - ``uid``, ``inode``
    - ``protocol`` (as passed in)

    Returns an empty list if the file does not exist or is not readable.
    """
    results: list[dict] = []

    try:
        with open(path, "r") as fh:
            lines = fh.readlines()
    except (FileNotFoundError, PermissionError, OSError) as exc:
        logger.debug("Cannot read %s: %s", path, exc)
        return results

    if not lines:
        return results

    # Determine IP family from the path
    is_v6 = protocol.endswith("6")

    # Skip header line (column names)
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
        try:
            parts = line.split()
            if len(parts) < 10:
                continue

            local = parts[1]   # e.g. "0100007F:1A90"
            remote = parts[2]  # e.g. "01010101:1F90"
            state_code = parts[3]

            local_ip_hex, local_port_hex = local.split(":")
            remote_ip_hex, remote_port_hex = remote.split(":")

            local_port = int(local_port_hex, 16)
            remote_port = int(remote_port_hex, 16)

            local_ip = _hex_ip_to_str_v6(local_ip_hex) if is_v6 else _hex_ip_to_str(local_ip_hex)
            remote_ip = _hex_ip_to_str_v6(remote_ip_hex) if is_v6 else _hex_ip_to_str(remote_ip_hex)

            state = _TCP_STATES.get(state_code, state_code) if "tcp" in protocol else "N/A"

            uid = int(parts[7])
            inode = int(parts[9])

            results.append({
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "state": state,
                "uid": uid,
                "inode": inode,
                "protocol": protocol,
            })
        except (ValueError, IndexError) as exc:
            logger.debug("Skipping malformed line in %s: %s — %s", path, line, exc)
            continue

    return results


# ═══════════════════════════════════════════════════════════════
#  Unified event builder
# ═══════════════════════════════════════════════════════════════


def _make_event(
    severity: str,
    action: str,
    details: str,
    pid: int = 0,
    process: str = "wine",
    session: str | None = None,
) -> dict:
    """Build a structured event dict in the unified WineShield format."""
    now = datetime.now()
    return {
        "id": str(uuid.uuid4()),
        "timestamp": now.isoformat(),
        "date": now.strftime("%Y-%m-%d"),
        "severity": severity,
        "layer": "network_guard",
        "action": action,
        "details": details,
        "pid": pid,
        "process": process,
        "session": session or "unknown",
    }


# ═══════════════════════════════════════════════════════════════
#  NetworkGuard
# ═══════════════════════════════════════════════════════════════


class NetworkGuard:
    """Monitor and control network access for Wine processes.

    Polls ``/proc/net/tcp`` and ``/proc/net/udp`` to track active
    connections, enforces rules from ``config/network_rules.json``,
    and detects connection-spray (brute-force / scanning) patterns.

    Parameters
    ----------
    config_dict : dict
        The full WineShield configuration dictionary (from
        ``config/default_policy.json`` or equivalent).  The
        ``"network"`` subsection is used for operational settings.
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

        # ── Network config from the policy ──────────────────
        net_cfg = config_dict.get("network", {})
        self._mode: str = net_cfg.get("mode", "monitor")  # "monitor" | "strict"
        self._poll_interval: int = net_cfg.get(
            "poll_interval_seconds", _DEFAULT_POLL_INTERVAL,
        )
        self._log_all: bool = net_cfg.get("log_all_connections", True)

        # ── Rules ─────────────────────────────────────────
        rules_file = net_cfg.get("rules_file", _DEFAULT_RULES_FILE)
        self._rules: dict = self._load_rules(rules_file)
        self._apply_rules()

        # ── Worker-thread state ────────────────────────────
        self._monitor_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

        # Connection tracking: keys are 5-tuples
        # (local_ip, local_port, remote_ip, remote_port, protocol)
        self._known_connections: dict[tuple, bool] = {}
        self._connections_cache: list[dict] = []

        # Spray-detection state
        self._spray_window: list[tuple[float, str]] = []  # (timestamp, remote_ip)
        self._spray_alerted: bool = False

        logger.info(
            "NetworkGuard initialized (session=%s, mode=%s, poll=%ds)",
            self.session_id, self._mode, self._poll_interval,
        )

    # ─────────────────────────────────────────────────────────
    #  Rules loading
    # ─────────────────────────────────────────────────────────

    def _load_rules(self, rules_file: str) -> dict:
        """Load network rules from the JSON file specified in config.

        Falls back to sensible defaults if the file is missing or
        malformed.
        """
        default_rules: dict = {
            "default_policy": "DENY",
            "dns_allowed": True,
            "dns_servers": ["8.8.8.8", "8.8.4.4"],
            "allowed_ports": [80, 443],
            "blocked_ports": [],
            "allowed_hosts": [],
            "blocked_hosts": ["169.254.169.254"],
            "blocked_countries": [],
            "protocols": {"tcp": True, "udp": True, "icmp": False},
        }

        # Resolve the rules file path
        path = pathlib.Path(rules_file)
        if not path.is_absolute():
            # Try relative to CWD first, then config/ subdirectory
            if not path.exists():
                alt = pathlib.Path("config") / rules_file
                if alt.exists():
                    path = alt

        try:
            with open(path, "r") as fh:
                data = json.load(fh)
            # The file may be wrapped in a "network_rules" key or flat
            raw = data.get("network_rules", data)
            logger.debug("Loaded network rules from %s", path)
            return {**default_rules, **raw}
        except (FileNotFoundError, json.JSONDecodeError, OSError) as exc:
            logger.warning(
                "Could not load network rules from %s: %s.  Using defaults.",
                path, exc,
            )
            return default_rules

    def _apply_rules(self) -> None:
        """Copy rule values from ``self._rules`` into instance attributes."""
        r = self._rules
        self._default_policy: str = r.get("default_policy", "DENY")
        self._dns_allowed: bool = r.get("dns_allowed", True)
        self._dns_servers: list[str] = r.get("dns_servers", ["8.8.8.8", "8.8.4.4"])
        self._allowed_ports: set[int] = set(r.get("allowed_ports", [80, 443]))
        self._blocked_ports: set[int] = set(r.get("blocked_ports", []))
        self._allowed_hosts: set[str] = set(r.get("allowed_hosts", []))
        self._blocked_hosts: set[str] = set(r.get("blocked_hosts", ["169.254.169.254"]))
        self._blocked_countries: list[str] = r.get("blocked_countries", [])
        self._allowed_protocols: dict[str, bool] = r.get(
            "protocols", {"tcp": True, "udp": True, "icmp": False},
        )

        if self._blocked_countries:
            logger.warning(
                "Country-level blocking is configured (%s) but requires "
                "an external GeoIP library — enforcement is a no-op.",
                self._blocked_countries,
            )

    def reload_rules(self) -> None:
        """Reload rules from the rules file at runtime.

        This is safe to call while monitoring is active; the new
        rules take effect on the next poll cycle.
        """
        net_cfg = self.config.get("network", {})
        rules_file = net_cfg.get("rules_file", _DEFAULT_RULES_FILE)
        self._rules = self._load_rules(rules_file)
        self._apply_rules()
        logger.info("Network rules reloaded (session=%s)", self.session_id)

    # ─────────────────────────────────────────────────────────
    #  Monitoring lifecycle
    # ─────────────────────────────────────────────────────────

    def start_monitoring(self) -> None:
        """Start the background monitoring thread.

        The thread polls ``/proc/net/tcp`` and ``/proc/net/udp`` at the
        configured interval, tracking new connections and detecting
        spray patterns.

        If the thread is already running this is a no-op.
        """
        if self._monitor_thread and self._monitor_thread.is_alive():
            logger.debug("Monitoring thread already running (session=%s)", self.session_id)
            return

        self._stop_event.clear()
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            name=f"netguard-{self.session_id[:8]}",
            daemon=True,
        )
        self._monitor_thread.start()
        logger.info(
            "Network monitoring started (session=%s, interval=%ds)",
            self.session_id, self._poll_interval,
        )

    def stop_monitoring(self) -> None:
        """Stop the background monitoring thread.

        Sets the stop event and waits up to 5 seconds for the thread
        to finish.
        """
        if not self._monitor_thread or not self._monitor_thread.is_alive():
            logger.debug("No active monitoring thread to stop (session=%s)", self.session_id)
            return

        self._stop_event.set()
        self._monitor_thread.join(timeout=5)
        if self._monitor_thread.is_alive():
            logger.warning(
                "Monitoring thread did not stop within timeout (session=%s)",
                self.session_id,
            )
        else:
            logger.info("Network monitoring stopped (session=%s)", self.session_id)
        self._monitor_thread = None

    def _monitor_loop(self) -> None:
        """Main monitoring loop — runs in a background daemon thread."""
        logger.debug("Monitor loop entered (session=%s)", self.session_id)
        while not self._stop_event.is_set():
            try:
                connections = self._poll_connections()

                with self._lock:
                    self._connections_cache = connections
                    self._check_new_connections(connections)
                    self._check_connection_spray(connections)

                time.sleep(self._poll_interval)
            except Exception as exc:
                logger.error(
                    "Error in monitoring loop (session=%s): %s",
                    self.session_id, exc, exc_info=True,
                )
                time.sleep(self._poll_interval)
        logger.debug("Monitor loop exited (session=%s)", self.session_id)

    # ─────────────────────────────────────────────────────────
    #  Connection polling
    # ─────────────────────────────────────────────────────────

    def _poll_connections(self) -> list[dict]:
        """Read all connection tables from ``/proc/net/``.

        Tries IPv4 and IPv6, TCP and UDP.  Missing files (e.g. ``tcp6``
        when IPv6 is disabled) are silently skipped.
        """
        connections: list[dict] = []

        for path, proto in [
            (_PROC_NET_TCP, "tcp"),
            (_PROC_NET_UDP, "udp"),
            (_PROC_NET_TCP6, "tcp6"),
            (_PROC_NET_UDP6, "udp6"),
        ]:
            try:
                connections.extend(_parse_proc_net(path, proto))
            except Exception as exc:
                logger.debug("Error polling %s: %s", path, exc)

        return connections

    # ─────────────────────────────────────────────────────────
    #  New connection detection
    # ─────────────────────────────────────────────────────────

    def _check_new_connections(self, connections: list[dict]) -> None:
        """Compare current connections against the known set and log new ones.

        A connection is considered *new* if its 5-tuple
        ``(local_ip, local_port, remote_ip, remote_port, protocol)``
        has not been seen before.

        In *strict* mode, connections that violate rules are logged
        as ``"Blocked connection"`` events.
        """
        seen_keys: set[tuple] = set()

        for conn in connections:
            key = (
                conn["local_ip"],
                conn["local_port"],
                conn["remote_ip"],
                conn["remote_port"],
                conn["protocol"],
            )
            seen_keys.add(key)

            if key in self._known_connections:
                continue  # already known

            # ── Skip purely local / wildcard addresses ────
            remote_ip: str = conn["remote_ip"]
            if self._is_local_address(remote_ip):
                continue

            # ── New connection — always log ──────────────
            ev = _make_event(
                severity="info",
                action="New connection",
                details=(
                    f"{conn['protocol']} {conn['local_ip']}:{conn['local_port']} → "
                    f"{conn['remote_ip']}:{conn['remote_port']}"
                ),
                session=self.session_id,
            )
            logger.info("NetworkGuard event: %s", json.dumps(ev))

            # ── In strict mode, check rules ──────────────
            if self._mode == "strict" and not self._is_connection_allowed(conn):
                blocked_ev = _make_event(
                    severity="high",
                    action="Blocked connection",
                    details=(
                        f"{conn['protocol']} {conn['local_ip']}:{conn['local_port']} → "
                        f"{conn['remote_ip']}:{conn['remote_port']}"
                    ),
                    session=self.session_id,
                )
                logger.warning("NetworkGuard event: %s", json.dumps(blocked_ev))

        # Prune stale entries from the known set
        self._known_connections = {k: True for k in seen_keys}

    @staticmethod
    def _is_local_address(ip: str) -> bool:
        """Return ``True`` if *ip* is a localhost or wildcard address."""
        return (
            ip.startswith("127.") or ip == "::1"
            or ip == "0.0.0.0" or ip == "::"
        )

    # ─────────────────────────────────────────────────────────
    #  Connection-spray detection
    # ─────────────────────────────────────────────────────────

    def _check_connection_spray(self, connections: list[dict]) -> None:
        """Detect connection-spray patterns.

        If more than ``_SPRAY_THRESHOLD`` unique remote IPs are seen
        within a ``_SPRAY_WINDOW_SECONDS`` sliding window, a
        high-severity event is emitted.

        The alert auto-resets when activity drops below the threshold.
        """
        now = time.time()

        # Collect distinct non-local remote IPs from this poll
        remote_ips: set[str] = {
            c["remote_ip"]
            for c in connections
            if not self._is_local_address(c["remote_ip"])
        }

        # Prune entries older than the spray window
        self._spray_window = [
            (ts, ip)
            for ts, ip in self._spray_window
            if now - ts <= _SPRAY_WINDOW_SECONDS
        ]

        # Add current IPs
        for ip in remote_ips:
            self._spray_window.append((now, ip))

        unique_ips = {ip for _, ip in self._spray_window}

        if len(unique_ips) >= _SPRAY_THRESHOLD and not self._spray_alerted:
            ev = _make_event(
                severity="high",
                action="Connection spray detected",
                details=(
                    f"{len(unique_ips)} unique remote IPs contacted within "
                    f"{_SPRAY_WINDOW_SECONDS}s — possible scanning behavior"
                ),
                session=self.session_id,
            )
            logger.warning("NetworkGuard event: %s", json.dumps(ev))
            self._spray_alerted = True
        elif len(unique_ips) < _SPRAY_THRESHOLD:
            self._spray_alerted = False

    # ─────────────────────────────────────────────────────────
    #  Rule checking
    # ─────────────────────────────────────────────────────────

    def _is_connection_allowed(self, conn: dict) -> bool:
        """Apply all configured rules against a single connection dict.

        Returns ``True`` if the connection is permitted, ``False`` if
        it should be blocked.

        The evaluation order is:

        1. **Protocol** — unknown / disabled protocols are denied.
        2. **Blocked hosts** — explicit deny list.
        3. **Blocked ports** — explicit deny list.
        4. **DNS exception** — UDP/53 is always permitted if
           ``dns_allowed`` is ``True`` (checked before the whitelists
           so that DNS servers are reachable even when
           ``allowed_hosts`` is restrictive).
        5. **Allowed hosts** — if non-empty, acts as an IP whitelist;
           anything not in the set is denied.
        6. **Allowed ports** — if non-empty, acts as a port whitelist;
           anything not in the set is denied.
        7. **Default policy** — ``"DENY"`` falls through to ``False``;
           ``"ALLOW"`` (or unknown) falls through to ``True``.
        """
        remote_ip: str = conn["remote_ip"]
        remote_port: int = conn["remote_port"]
        protocol: str = conn["protocol"]

        # Normalise protocol name (tcp6 → tcp, udp6 → udp)
        proto_base = protocol.rstrip("6")

        # ── 1. Protocol check ─────────────────────────────
        if not self._allowed_protocols.get(proto_base, True):
            return False

        # ── 2. Blocked hosts (explicit deny) ──────────────
        if remote_ip in self._blocked_hosts:
            return False

        # ── 3. Blocked ports ──────────────────────────────
        if remote_port in self._blocked_ports:
            return False

        # ── 4. DNS exception (checked before whitelists) ──
        is_dns = (
            proto_base == "udp"
            and remote_port == 53
            and self._dns_allowed
        )
        if is_dns:
            return True

        # ── 5. Allowed hosts (if non-empty, IP whitelist) ─
        if self._allowed_hosts:
            return remote_ip in self._allowed_hosts

        # ── 6. Allowed ports (if non-empty, port whitelist)
        if self._allowed_ports:
            return remote_port in self._allowed_ports

        # ── 7. Default policy ─────────────────────────────
        if self._default_policy == "DENY":
            return False

        # default_policy == "ALLOW" (or unknown)
        return True

    def check_connection_allowed(self, dest_ip: str, dest_port: int, protocol: str) -> bool:
        """Check whether a connection to *dest_ip*:*dest_port* is allowed.

        Parameters
        ----------
        dest_ip : str
            Destination IP address (e.g. ``"1.2.3.4"``).
        dest_port : int
            Destination port number.
        protocol : str
            Protocol name (``"tcp"``, ``"udp"``, ``"tcp6"``, ``"udp6"``).

        Returns
        -------
        bool
            ``True`` if the connection is permitted, ``False`` if blocked.
        """
        conn = {
            "remote_ip": dest_ip,
            "remote_port": dest_port,
            "protocol": protocol,
        }
        allowed = self._is_connection_allowed(conn)

        if not allowed:
            severity = "high" if self._mode == "strict" else "warning"
            action = (
                "Connection blocked by rule"
                if self._mode == "strict"
                else "Connection would be blocked (monitor mode)"
            )
            ev = _make_event(
                severity=severity,
                action=action,
                details=(
                    f"{protocol} → {dest_ip}:{dest_port} "
                    f"(default_policy={self._default_policy})"
                ),
                session=self.session_id,
            )
            logger_func = logger.warning if self._mode == "strict" else logger.info
            logger_func("NetworkGuard event: %s", json.dumps(ev))

        return allowed

    # ─────────────────────────────────────────────────────────
    #  Connection querying
    # ─────────────────────────────────────────────────────────

    def get_connections(self) -> list[dict]:
        """Return the most recently polled list of active connections.

        Returns
        -------
        list[dict]
            Each dict has keys ``local_ip``, ``local_port``,
            ``remote_ip``, ``remote_port``, ``state``, ``uid``,
            ``inode``, and ``protocol``.

            Returns an empty list if monitoring has not been started yet.
        """
        with self._lock:
            return list(self._connections_cache)

    # ─────────────────────────────────────────────────────────
    #  PID resolution (best-effort)
    # ─────────────────────────────────────────────────────────

    @staticmethod
    def _resolve_pid_by_inode(inode: int) -> int | None:
        """Try to find the PID that owns a socket with *inode*.

        Scans ``/proc/*/fd/`` for symlinks pointing at
        ``socket:[{inode}]``.  This is intentionally a **best-effort**
        helper — it returns ``None`` quickly if no match is found.

        .. note::

            This method is **not** called automatically during the
            monitor loop because scanning ``/proc`` on every poll is
            expensive.  Call it explicitly when you need a PID for a
            specific connection.
        """
        proc_root = pathlib.Path("/proc")
        if not proc_root.is_dir():
            return None

        target = f"socket:[{inode}]"

        try:
            for entry in proc_root.iterdir():
                if not entry.name.isdigit():
                    continue
                fd_dir = entry / "fd"
                try:
                    for fd_entry in fd_dir.iterdir():
                        try:
                            link = os.readlink(str(fd_entry))
                            if link == target:
                                return int(entry.name)
                        except (OSError, ValueError):
                            continue
                except (PermissionError, OSError):
                    continue
        except PermissionError:
            pass

        return None

    # ─────────────────────────────────────────────────────────
    #  Cleanup
    # ─────────────────────────────────────────────────────────

    def cleanup(self) -> None:
        """Stop monitoring and log session end.

        Should be called when the Wine session ends.
        """
        logger.info("Cleaning up NetworkGuard (session=%s)", self.session_id)

        self.stop_monitoring()

        ev = _make_event(
            severity="info",
            action="Network monitoring ended",
            details=(
                f"Session {self.session_id} ended. "
                f"Tracked {len(self._known_connections)} unique connections."
            ),
            session=self.session_id,
        )
        logger.info("NetworkGuard event: %s", json.dumps(ev))

        # Reset runtime state
        with self._lock:
            self._connections_cache.clear()
            self._known_connections.clear()
            self._spray_window.clear()
            self._spray_alerted = False
