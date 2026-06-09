#!/usr/bin/env python3
"""
WineShield — Xephyr X11 Guard (Layer 5)

X11 input isolation layer using a nested Xephyr display server.  Runs Wine
inside the nested X server so that keyboard and mouse input is isolated from
the host X11 session — keyloggers inside the sandbox cannot steal keystrokes
destined for real host windows.

Usage::

    guard = X11Guard(config_dict, session_id="abc-123")
    guard.create_x11_sandbox()
    # … DISPLAY is now set to the nested Xephyr display …
    guard.destroy_x11_sandbox()
    # … DISPLAY is restored to the original value …

Requires the ``xserver-xephyr`` package (``/usr/bin/Xephyr``).
"""

from __future__ import annotations

import json
import logging
import os
import pathlib
import signal
import subprocess
import time
import uuid
from datetime import datetime

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────
_XEPHYR_BINARY = "/usr/bin/Xephyr"
_X11_SOCKET_DIR = pathlib.Path("/tmp/.X11-unix")
_SOCKET_TIMEOUT_SEC = 5

# ═════════════════════════════════════════════════════════════════════════════
#  Unified event builder (mirrors other core modules)
# ═════════════════════════════════════════════════════════════════════════════


def _make_event(
    severity: str,
    action: str,
    details: str,
    session: str | None = None,
) -> dict:
    """Build a structured event dict in the unified WineShield format."""
    now = datetime.now()
    return {
        "id": str(uuid.uuid4()),
        "timestamp": now.isoformat(),
        "source": "xephyr_guard",
        "severity": severity,
        "action": action,
        "details": details,
        "session": session or "",
    }


# ═════════════════════════════════════════════════════════════════════════════
#  Helpers
# ═════════════════════════════════════════════════════════════════════════════


def _find_free_display() -> int:
    """
    Return the first free display number >= 1 by inspecting
    /tmp/.X11-unix/ for existing sockets.

    Display 0 is skipped because it is typically the host X server.
    """
    if not _X11_SOCKET_DIR.is_dir():
        return 1

    existing: set[int] = set()
    for entry in _X11_SOCKET_DIR.iterdir():
        if entry.name.startswith("X") and entry.name[1:].isdigit():
            existing.add(int(entry.name[1:]))

    candidate = 1
    while candidate in existing:
        candidate += 1
    return candidate


def _display_is_in_use(display_num: int) -> bool:
    """Check whether a given display number already has a socket file."""
    socket_path = _X11_SOCKET_DIR / f"X{display_num}"
    return socket_path.exists()


# ═════════════════════════════════════════════════════════════════════════════
#  X11Guard
# ═════════════════════════════════════════════════════════════════════════════


class X11Guard:
    """
    X11 input isolation via Xephyr.

    Manages a nested Xephyr display server that Wine runs against, keeping
    keyboard and mouse input isolated from the host display.

    Usage::

        guard = X11Guard(config_dict)
        guard.create_x11_sandbox()
        … run Wine here (DISPLAY is set) …
        guard.destroy_x11_sandbox()
    """

    def __init__(self, config_dict: dict, session_id: str | None = None) -> None:
        """
        Initialise the guard.

        Parameters
        ----------
        config_dict : dict
            Full WineShield configuration dictionary (from
            ``default_policy.json`` or equivalent).  The following keys are
            consulted under ``xephyr``::

                enabled          bool   (default: False)
                display          int | None  (default: None → auto)
                default_width    int   (default: 1280)
                default_height   int   (default: 720)

        session_id : str or None
            Optional session identifier for event correlation.
        """
        self.config = config_dict
        self.session_id = session_id or str(uuid.uuid4())

        # -- Extract xephyr sub-config --------------------------------------
        xephyr_cfg = config_dict.get("xephyr", {}) if isinstance(config_dict, dict) else {}

        self._enabled: bool = bool(xephyr_cfg.get("enabled", False))
        self._display: int | None = xephyr_cfg.get("display")  # None = auto
        self._width: int = int(xephyr_cfg.get("default_width", 1280))
        self._height: int = int(xephyr_cfg.get("default_height", 720))

        # -- Runtime state ---------------------------------------------------
        self.xephyr_process: subprocess.Popen | None = None
        self.display_num: int | None = None
        self._original_display: str | None = os.environ.get("DISPLAY")
        self._available: bool = pathlib.Path(_XEPHYR_BINARY).is_file()
        self._running: bool = False

        if not self._available:
            logger.error(
                "Xephyr binary not found at %s — X11 isolation disabled",
                _XEPHYR_BINARY,
            )

    # ── Public API ─────────────────────────────────────────────────────────

    def create_x11_sandbox(self) -> dict:
        """
        Start a Xephyr nested display server and point ``DISPLAY`` at it.

        Returns a structured event dict indicating success or failure.

        Steps:
        1. Detect or resolve the target display number.
        2. Check the display is not already in use.
        3. Save the original ``DISPLAY`` environment variable.
        4. Launch ``/usr/bin/Xephyr`` as a background process.
        5. Wait up to *SOCKET_TIMEOUT_SEC* for the X11 socket to appear.
        6. Set ``DISPLAY`` in the environment.

        Raises
        ------
        RuntimeError
            If Xephyr is not available, the display is already in use, or
            Xephyr fails to start within the timeout.
        """
        if not self._available:
            msg = "Xephyr binary is not available — cannot create X11 sandbox"
            logger.error(msg)
            raise RuntimeError(msg)

        if self._running:
            logger.warning("X11 sandbox is already running (display :%d)", self.display_num)
            return _make_event("warning", "create_x11_sandbox", "already running", self.session_id)

        # --- 1. Resolve display number ------------------------------------
        if self._display is not None:
            display_num = self._display
        else:
            display_num = _find_free_display()

        # --- 2. Sanity-check the display ----------------------------------
        if _display_is_in_use(display_num):
            msg = (
                f"Display :{display_num} is already in use "
                f"(socket /tmp/.X11-unix/X{display_num} exists)"
            )
            logger.error(msg)
            raise RuntimeError(msg)

        # --- 3. Save original DISPLAY -------------------------------------
        self._original_display = os.environ.get("DISPLAY")

        # --- 4. Build the Xephyr command ----------------------------------
        xephyr_cmd = [
            _XEPHYR_BINARY,
            f":{display_num}",
            "-screen", f"{self._width}x{self._height}",
            "-ac",       # disable access control (needed by Wine)
            "-br",       # blank root window
            "-noreset",  # persist after last client disconnects
        ]

        # Optional: create temporary X authority file if requested
        xauth_path: pathlib.Path | None = None
        if self._enabled:
            # Generate a .Xauthority for the sandbox display
            try:
                xauth_dir = pathlib.Path(os.path.expanduser("~/.wineshield"))
                xauth_dir.mkdir(parents=True, exist_ok=True)
                xauth_path = xauth_dir / f"Xauthority_{self.session_id}"
                # Create a cookie and add it to the file via xauth tool
                cookie = uuid.uuid4().hex
                subprocess.run(
                    [
                        "xauth",
                        "-f", str(xauth_path),
                        "add", f":{display_num}",
                        "MIT-MAGIC-COOKIE-1", cookie,
                    ],
                    capture_output=True,
                    timeout=5,
                )
                os.environ["XAUTHORITY"] = str(xauth_path)
                logger.info("Created temporary X authority at %s", xauth_path)
            except Exception as exc:
                logger.warning("Could not create X authority file: %s", exc)

        # --- 5. Launch Xephyr ---------------------------------------------
        logger.info(
            "Starting Xephyr on display :%d  (%dx%d)",
            display_num, self._width, self._height,
        )

        try:
            self.xephyr_process = subprocess.Popen(
                xephyr_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
        except FileNotFoundError:
            logger.error("Xephyr binary not found at %s", _XEPHYR_BINARY)
            self._available = False
            raise RuntimeError(f"Xephyr binary not found at {_XEPHYR_BINARY}")
        except Exception as exc:
            logger.error("Failed to start Xephyr: %s", exc)
            self._restore_display()
            raise RuntimeError(f"Failed to start Xephyr: {exc}") from exc

        # --- 6. Wait for the X11 socket to appear -------------------------
        socket_path = _X11_SOCKET_DIR / f"X{display_num}"
        deadline = time.monotonic() + _SOCKET_TIMEOUT_SEC
        found = False

        while time.monotonic() < deadline:
            poll = self.xephyr_process.poll()
            if poll is not None:
                # Process died before creating the socket
                stderr_output = ""
                if self.xephyr_process.stderr is not None:
                    try:
                        raw = self.xephyr_process.stderr.read()
                        stderr_output = raw.decode(
                            "utf-8", errors="replace"
                        )[:500]
                    except Exception:
                        pass
                self.xephyr_process = None
                self._restore_display()
                msg = (
                    f"Xephyr exited prematurely (return code {poll}). "
                    f"Stderr: {stderr_output}"
                )
                logger.error(msg)
                raise RuntimeError(msg)

            if socket_path.exists():
                found = True
                break
            time.sleep(0.1)

        if not found:
            # Timeout — kill and clean up
            self._kill_xephyr()
            self._restore_display()
            msg = (
                f"Xephyr did not create socket after {_SOCKET_TIMEOUT_SEC}s "
                f"(expected {socket_path})"
            )
            logger.error(msg)
            raise RuntimeError(msg)

        # --- 7. Set DISPLAY in environment ---------------------------------
        os.environ["DISPLAY"] = f":{display_num}"
        self.display_num = display_num
        self._running = True

        logger.info(
            "Xephyr started successfully — DISPLAY set to :%d (PID %d)",
            display_num, self.xephyr_process.pid,
        )

        return _make_event(
            "info",
            "create_x11_sandbox",
            f"Xephyr started on :{display_num} (PID {self.xephyr_process.pid})",
            self.session_id,
        )

    def destroy_x11_sandbox(self) -> dict:
        """
        Terminate the Xephyr process and restore the original ``DISPLAY``.

        Returns a structured event dict.
        """
        if not self._running or self.xephyr_process is None:
            logger.debug("X11 sandbox not running — nothing to destroy")
            return _make_event(
                "info", "destroy_x11_sandbox", "not running", self.session_id
            )

        pid = self.xephyr_process.pid
        display = self.display_num

        self._kill_xephyr()
        self._restore_display()
        self._running = False
        self.display_num = None

        # Clean up temporary X authority file
        xauth_path = pathlib.Path(
            os.environ.get("XAUTHORITY", "")
        )
        if xauth_path.exists() and "wineshield" in str(xauth_path):
            try:
                xauth_path.unlink(missing_ok=True)
                logger.debug("Removed temporary X authority %s", xauth_path)
            except Exception as exc:
                logger.warning("Could not remove X authority %s: %s", xauth_path, exc)

        # Remove XAUTHORITY if we set it
        if "XAUTHORITY" in os.environ and "wineshield" in os.environ.get("XAUTHORITY", ""):
            del os.environ["XAUTHORITY"]

        logger.info("Xephyr stopped (display :%d, PID %d)", display, pid)

        return _make_event(
            "info",
            "destroy_x11_sandbox",
            f"Xephyr stopped (display :{display}, PID {pid})",
            self.session_id,
        )

    def get_status(self) -> dict:
        """
        Return a snapshot of the current guard state.

        Returns
        -------
        dict with keys:
            - "available"  : bool  — whether the Xephyr binary was found
            - "running"    : bool  — whether Xephyr is currently active
            - "display"    : int | None  — display number (if running)
            - "xephyr_pid" : int | None  — Xephyr process PID (if running)
            - "enabled"    : bool  — whether the layer is enabled in config
        """
        still_alive = (
            self._running
            and self.xephyr_process is not None
            and self.xephyr_process.poll() is None
        )
        if self._running and not still_alive:
            # Process died unexpectedly
            logger.warning(
                "Xephyr process (PID %s) died unexpectedly — marking as stopped",
                self.xephyr_process.pid if self.xephyr_process else "?",
            )
            self._running = False
            self.xephyr_process = None
            self._restore_display()

        return {
            "available": self._available,
            "running": still_alive,
            "display": self.display_num if still_alive else None,
            "xephyr_pid": self.xephyr_process.pid if still_alive and self.xephyr_process else None,
            "enabled": self._enabled,
        }

    def cleanup(self) -> dict:
        """
        Full teardown: destroy the X11 sandbox and log the event.

        This is the idempotent cleanup method intended to be called from
        session tear-down logic (``finally`` blocks, context managers, etc.).
        """
        event = self.destroy_x11_sandbox()
        logger.info("X11Guard cleanup complete")
        return event

    # ── Internal helpers ──────────────────────────────────────────────────

    def _kill_xephyr(self) -> None:
        """Send SIGTERM (then SIGKILL after a short grace) to Xephyr."""
        if self.xephyr_process is None:
            return

        pid = self.xephyr_process.pid
        try:
            os.kill(pid, signal.SIGTERM)
            try:
                self.xephyr_process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                logger.warning("Xephyr (PID %d) did not exit in 3s — sending SIGKILL", pid)
                os.kill(pid, signal.SIGKILL)
                self.xephyr_process.wait(timeout=2)
        except ProcessLookupError:
            logger.debug("Xephyr (PID %d) already exited", pid)
        except Exception as exc:
            logger.warning("Error while killing Xephyr (PID %d): %s", pid, exc)

        self.xephyr_process = None

    def _restore_display(self) -> None:
        """Restore the DISPLAY environment variable to its original value."""
        if self._original_display is not None:
            os.environ["DISPLAY"] = self._original_display
        else:
            os.environ.pop("DISPLAY", None)
        logger.debug("DISPLAY restored to %s", self._original_display)

    # ── Context-manager support ────────────────────────────────────────────

    def __enter__(self) -> "X11Guard":
        self.create_x11_sandbox()
        return self

    def __exit__(self, *exc_info) -> None:
        self.cleanup()


# ═════════════════════════════════════════════════════════════════════════════
#  Standalone entry point (for testing / debugging)
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )

    config = {
        "xephyr": {
            "enabled": True,
            "display": None,           # auto
            "default_width": 1280,
            "default_height": 720,
        }
    }

    guard = X11Guard(config, session_id="test-cli")

    try:
        result = guard.create_x11_sandbox()
        print(json.dumps(result, indent=2))
        print("--- Status ---")
        print(json.dumps(guard.get_status(), indent=2))
        print("--- Xephyr is running; press Ctrl+C to stop ---")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        guard.cleanup()
