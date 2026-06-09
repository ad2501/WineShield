#!/usr/bin/env python3
"""
WineShield — AppArmor Manager (Layer 6)

AppArmor profile management layer for WineShield.  Handles loading,
unloading, verification, and mode toggling of AppArmor profiles that
confine Wine, wineserver, and the WineShield framework daemon.

This module is complementary to the seccomp-BPF filter (Layer 1);
AppArmor provides mandatory access control (MAC) at the filesystem and
network level, while seccomp restricts the system-call surface.

Usage::

    manager = AppArmorManager(config_dict, session_id="abc-123")
    profiles = manager.load_profiles()
    status = manager.check_status()
    manager.set_enforce("wineshield-wine")
    manager.cleanup()

On systems without AppArmor (e.g. WSL, containers), the manager
operates in "syntax-check only" mode — it validates profile syntax
but skips loading/unloading.
"""

from __future__ import annotations

import logging
import os
import pathlib
import re
import subprocess
import uuid
from datetime import datetime

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────
_APARMOR_PARSER = "/usr/sbin/apparmor_parser"
_AA_STATUS = "/usr/sbin/aa-status"
_SYSFS_PROFILES = "/sys/kernel/security/apparmor/profiles"
_PROFILE_DIR = "config/apparmor"

# The canonical profiles managed by WineShield (in load order).
# The first key is the internal label; the value is the filename
# inside the profile directory.
_CANONICAL_PROFILES: dict[str, str] = {
    "wineshield-wine": "wineshield.wine",
    "wineshield-wineserver": "wineshield.wineserver",
    "wineshield-framework": "wineshield.framework",
}

# ═════════════════════════════════════════════════════════════════════════════
#  Unified event builder
# ═════════════════════════════════════════════════════════════════════════════


def _make_event(
    severity: str,
    action: str,
    details: str,
    session: str | None = None,
) -> dict:
    """Build a structured event dict in the unified WineShield format.

    Parameters
    ----------
    severity : str
        ``"info"`` or ``"warning"``.
    action : str
        Human-readable action label (e.g. ``"Profile loaded"``).
    details : str
        Free-form detail string (e.g. ``"profile=wineshield-wine, mode=enforce"``).
    session : str, optional
        Session identifier for event correlation.

    Returns
    -------
    dict
    """
    now = datetime.now()
    return {
        "id": str(uuid.uuid4()),
        "timestamp": now.isoformat(),
        "date": now.strftime("%Y-%m-%d"),
        "severity": severity,
        "layer": "apparmor",
        "action": action,
        "details": details,
        "pid": os.getpid(),
        "process": "wineshield",
        "session": session or "unknown",
    }


# ═════════════════════════════════════════════════════════════════════════════
#  Helpers
# ═════════════════════════════════════════════════════════════════════════════


def _extract_profile_name(file_path: str) -> str | None:
    """Parse the profile name from an AppArmor profile file.

    Looks for a line matching ``profile <name>``, ``profile <name> <path>``,
    or ``profile <name> /path/to/binary {``.

    Parameters
    ----------
    file_path : str
        Path to the AppArmor profile file.

    Returns
    -------
    str or None
        The profile name if found, otherwise ``None``.
    """
    try:
        with open(file_path, "r") as fh:
            for line in fh:
                line = line.strip()
                # Skip comments, includes, and empty lines
                if not line or line.startswith("#") or line.startswith("#include"):
                    continue
                m = re.match(
                    r'^profile\s+([^\s{]+)',
                    line,
                )
                if m:
                    return m.group(1)
    except OSError as exc:
        logger.warning("Cannot read %s to extract profile name: %s", file_path, exc)
    return None


def _sudo_cmd() -> list[str]:
    """Return the prefix needed to run a command with root privileges.

    On systems where sudo is available and non-interactive, returns
    ``["sudo"]``; otherwise returns an empty list (the caller should
    check :attr:`AppArmorManager.available` before relying on this).

    Returns
    -------
    list[str]
    """
    try:
        result = subprocess.run(
            ["sudo", "-n", "true"],
            capture_output=True,
            timeout=10,
        )
        if result.returncode == 0:
            return ["sudo"]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return []


# ═════════════════════════════════════════════════════════════════════════════
#  AppArmorManager
# ═════════════════════════════════════════════════════════════════════════════


class AppArmorManager:
    """AppArmor profile management for WineShield.

    Handles syntax validation, loading, unloading, status checking, and
    mode toggling (enforce ↔ complain) for the three canonical WineShield
    AppArmor profiles.

    On systems where AppArmor is not active (e.g. WSL) the manager detects
    this and operates in a degraded "syntax-check only" mode — profiles are
    validated but not loaded into the kernel.

    Parameters
    ----------
    config_dict : dict
        The full WineShield configuration dictionary (from
        ``config/default_policy.json`` or equivalent).
    session_id : str, optional
        An optional session identifier for logging and event correlation.
        A UUID is generated if not provided.
    """

    def __init__(
        self,
        config_dict: dict,
        session_id: str | None = None,
    ) -> None:
        self.config = config_dict
        self.session_id = session_id or str(uuid.uuid4())

        # ── AppArmor availability ──────────────────────────────
        self._parser_path: str | None = None
        self._sudo_prefix: list[str] = []
        self.available: bool = False

        self._detect_apparmor()

        # ── Profile file paths (resolved during load) ──────────
        self._profile_dir: str = self._resolve_profile_dir()
        self._loaded_profiles: list[str] = []

        logger.debug(
            "AppArmorManager initialised (session=%s, available=%s)",
            self.session_id,
            self.available,
        )

    # ───────────────────────────────────────────────────────────
    #  Public API
    # ───────────────────────────────────────────────────────────

    def load_profiles(self) -> list[str]:
        """Parse and load all WineShield AppArmor profiles.

        For each canonical profile file:
        1. Resolves the full path under ``config/apparmor/``.
        2. Extracts the declared profile name from inside the file.
        3. Validates syntax with ``apparmor_parser -o /dev/null`` (compile-only, no kernel load).
        4. Loads (or replaces) the profile with ``sudo apparmor_parser -r -W``.

        If AppArmor is not available on this system, only syntax
        validation is performed (step 3) and the method returns an
        empty list.

        Returns
        -------
        list[str]
            Names of the profiles that were successfully loaded.
            Profiles that fail validation or are already in a bad
            state are skipped with a warning.
        """
        self._loaded_profiles = []
        profile_dir = pathlib.Path(self._profile_dir)

        if not profile_dir.is_dir():
            logger.warning(
                "AppArmor profile directory '%s' not found — aborting load",
                profile_dir,
            )
            return []

        for label, filename in _CANONICAL_PROFILES.items():
            file_path = profile_dir / filename

            if not file_path.is_file():
                logger.warning(
                    "Profile file '%s' not found — skipping '%s'",
                    file_path,
                    label,
                )
                continue

            logger.debug("Processing AppArmor profile file: %s", file_path)

            # ── Validate syntax ────────────────────────────────
            if not self._validate(file_path):
                logger.warning(
                    "Syntax validation failed for '%s' (%s) — skipping",
                    label,
                    file_path,
                )
                continue

            # ── Extract the declared profile name ──────────────
            profile_name = _extract_profile_name(str(file_path))
            if not profile_name:
                logger.warning(
                    "Could not extract profile name from '%s' — skipping",
                    file_path,
                )
                continue

            # ── Load (or replace) the profile ──────────────────
            if self.available and self._sudo_prefix:
                try:
                    self._run_parser(["-r", "-W", str(file_path)])
                    self._loaded_profiles.append(profile_name)
                    ev = _make_event(
                        "info",
                        "Profile loaded",
                        f"profile={profile_name}, mode=enforce",
                        session=self.session_id,
                    )
                    logger.info("Loaded AppArmor profile '%s'", profile_name)
                    logger.info("AppArmor event: %s", ev)
                except subprocess.CalledProcessError as exc:
                    logger.warning(
                        "Failed to load profile '%s' (%s): %s",
                        profile_name,
                        file_path,
                        exc.stderr.strip() if exc.stderr else str(exc),
                    )
                except OSError as exc:
                    logger.warning(
                        "OS error loading profile '%s': %s",
                        profile_name,
                        exc,
                    )
            else:
                # Degraded mode: syntax-check only
                logger.info(
                    "AppArmor not available — validated but skipped loading "
                    "profile '%s' (%s)",
                    profile_name,
                    file_path,
                )

        return list(self._loaded_profiles)

    def unload_profiles(self) -> list[str]:
        """Unload all previously loaded WineShield AppArmor profiles.

        For each profile listed in :attr:`_loaded_profiles`, looks up
        the corresponding file and runs ``sudo apparmor_parser -R``.

        Returns
        -------
        list[str]
            Names of profiles that were successfully unloaded.
        """
        unloaded: list[str] = []
        if not self.available or not self._sudo_prefix:
            logger.info(
                "AppArmor not available — skipping profile unload",
            )
            return unloaded

        # Build a reverse map: profile name → filename
        name_to_file: dict[str, str] = {
            v: k for k, v in _CANONICAL_PROFILES.items()
        }

        profile_dir = pathlib.Path(self._profile_dir)

        for profile_name in list(self._loaded_profiles):
            filename = name_to_file.get(profile_name)
            if not filename:
                logger.warning(
                    "Unknown profile name '%s' — cannot determine file to unload",
                    profile_name,
                )
                continue

            file_path = profile_dir / filename
            if not file_path.is_file():
                logger.warning(
                    "Profile file '%s' for '%s' not found — cannot unload",
                    file_path,
                    profile_name,
                )
                continue

            try:
                self._run_parser(["-R", str(file_path)])
                unloaded.append(profile_name)
                ev = _make_event(
                    "info",
                    "Profile unloaded",
                    f"profile={profile_name}",
                    session=self.session_id,
                )
                logger.info("Unloaded AppArmor profile '%s'", profile_name)
                logger.info("AppArmor event: %s", ev)
            except subprocess.CalledProcessError as exc:
                logger.warning(
                    "Failed to unload profile '%s' (%s): %s",
                    profile_name,
                    file_path,
                    exc.stderr.strip() if exc.stderr else str(exc),
                )
            except OSError as exc:
                logger.warning(
                    "OS error unloading profile '%s': %s",
                    profile_name,
                    exc,
                )

        # Remove unloaded profiles from the tracking list
        for name in unloaded:
            if name in self._loaded_profiles:
                self._loaded_profiles.remove(name)

        return unloaded

    def check_status(self) -> dict[str, str]:
        """Check the current mode of each canonical profile.

        Reads the AppArmor profiles from ``/sys/kernel/security/apparmor/profiles``
        (or falls back to ``sudo aa-status``) and maps each WineShield profile
        to one of:

        * ``"enforce"`` — profile is loaded and enforcing.
        * ``"complain"`` — profile is loaded in complain (learning) mode.
        * ``"not-loaded"`` — profile is not currently loaded.

        Returns
        -------
        dict[str, str]
            Mapping of profile names → status string.
        """
        # Initialise all profiles as "not-loaded"
        status: dict[str, str] = {
            label: "not-loaded" for label in _CANONICAL_PROFILES
        }

        raw = self._read_sysfs_profiles()

        if raw is None:
            # Fallback: try aa-status
            raw = self._read_aa_status()

        if raw is None:
            logger.warning(
                "Cannot read AppArmor status — no /sys fs and aa-status "
                "not available. Returning 'not-loaded' for all profiles.",
            )
            return status

        # Parse profile entries.
        # /sys/kernel/security/apparmor/profiles format:
        #   /usr/bin/wine64-preloader (enforce)
        #   /usr/bin/wineserver (complain)
        #
        # aa-status output contains lines like:
        #   profile-name (enforce)
        # We match by checking if any known WineShield profile name
        # appears in each line.
        for line in raw.splitlines():
            line = line.strip()
            # Determine the mode from the parenthesised suffix
            mode = self._parse_mode_from_line(line)
            if mode is None:
                continue

            for label in _CANONICAL_PROFILES:
                if label in line:
                    status[label] = mode

        return status

    def set_enforce(self, profile_name: str) -> bool:
        """Switch a profile to enforce mode.

        Uses ``sudo aa-enforce <profile_name>`` (or falls back to
        ``sudo apparmor_parser -r`` with the profile file if
        ``aa-enforce`` is not available).

        Parameters
        ----------
        profile_name : str
            The internal profile label (e.g. ``"wineshield-wine"``).

        Returns
        -------
        bool
            ``True`` if the mode switch succeeded, ``False`` otherwise.
        """
        return self._set_mode(profile_name, "enforce")

    def set_complain(self, profile_name: str) -> bool:
        """Switch a profile to complain (learning) mode.

        Uses ``sudo aa-complain <profile_name>`` (or falls back to
        ``sudo apparmor_parser -C`` with the profile file).

        Parameters
        ----------
        profile_name : str
            The internal profile label (e.g. ``"wineshield-wine"``).

        Returns
        -------
        bool
            ``True`` if the mode switch succeeded, ``False`` otherwise.
        """
        return self._set_mode(profile_name, "complain")

    def cleanup(self) -> None:
        """Tear down all AppArmor profiles.

        Calls :meth:`unload_profiles` and logs a summary event with
        the total number of profiles that were unloaded.

        This is a safe, best-effort method — errors are logged but
        not raised.
        """
        logger.info(
            "AppArmorManager cleanup starting (session=%s)",
            self.session_id,
        )

        unloaded = self.unload_profiles()

        if unloaded:
            summary = f"Unloaded {len(unloaded)} profile(s): {', '.join(unloaded)}"
        else:
            summary = "No profiles were unloaded"

        ev = _make_event(
            "info",
            "Cleanup complete",
            summary,
            session=self.session_id,
        )
        logger.info("AppArmor event: %s", ev)

    # ───────────────────────────────────────────────────────────
    #  Internal helpers
    # ───────────────────────────────────────────────────────────

    def _detect_apparmor(self) -> None:
        """Detect whether AppArmor is available on this system.

        Sets :attr:`_parser_path` to the path of ``apparmor_parser``
        (or ``None``), builds the sudo prefix, and sets
        :attr:`available` to ``True`` only if both the parser binary
        and sudo are present.
        """
        # 1. Find apparmor_parser
        parser = shutil_which("apparmor_parser")
        if parser:
            self._parser_path = parser
        else:
            # Fallback: check common locations
            for candidate in [_APARMOR_PARSER, "/sbin/apparmor_parser"]:
                if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                    self._parser_path = candidate
                    break

        if not self._parser_path:
            logger.warning(
                "apparmor_parser not found — AppArmor profile management "
                "will operate in syntax-check only mode",
            )
            self.available = False
            return

        # 2. Check sudo availability
        self._sudo_prefix = _sudo_cmd()
        if not self._sudo_prefix:
            logger.warning(
                "sudo not available — AppArmor profile loading/unloading "
                "requires root privileges. Will operate in syntax-check only mode",
            )
            self.available = False
            return

        # 3. Quick sanity check: can the parser actually run?
        try:
            result = subprocess.run(
                [self._parser_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                logger.warning(
                    "apparmor_parser at %s returned non-zero exit code — "
                    "marking unavailable",
                    self._parser_path,
                )
                self.available = False
                return
        except (subprocess.TimeoutExpired, OSError) as exc:
            logger.warning(
                "apparmor_parser sanity check failed: %s", exc,
            )
            self.available = False
            return

        self.available = True
        logger.debug(
            "AppArmor detected: parser=%s, sudo=%s",
            self._parser_path,
            bool(self._sudo_prefix),
        )

    def _resolve_profile_dir(self) -> str:
        """Resolve the AppArmor profile directory path from config.

        Uses ``config["apparmor"]["profile_dir"]`` if present and
        absolute/relative, otherwise falls back to ``config/apparmor/``
        relative to the working directory.

        Returns
        -------
        str
            Absolute path to the profile directory.
        """
        apparmor_cfg = self.config.get("apparmor", {})
        configured = apparmor_cfg.get("profile_dir", _PROFILE_DIR)

        # If it's already absolute, use as-is
        if os.path.isabs(configured):
            return configured

        # Relative: resolve from the project root (current working directory)
        # or expand user home
        expanded = os.path.expanduser(configured)
        if os.path.isabs(expanded):
            return expanded

        candidate = os.path.join(os.getcwd(), expanded)
        return candidate

    def _validate(self, file_path: pathlib.Path) -> bool:
        """Validate the syntax of an AppArmor profile file.

        Runs ``apparmor_parser -o /dev/null {file}`` which compiles and
        checks the profile without loading it into the kernel.  The
        compiled output is written to ``/dev/null`` (discarded).

        Parameters
        ----------
        file_path : pathlib.Path
            Path to the profile file.

        Returns
        -------
        bool
            ``True`` if syntax is valid, ``False`` otherwise.
        """
        if not self._parser_path:
            logger.warning(
                "No apparmor_parser available — cannot validate '%s'",
                file_path,
            )
            return False

        try:
            result = subprocess.run(
                [self._parser_path, "-o", "/dev/null", str(file_path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                logger.debug(
                    "Syntax OK: %s",
                    file_path,
                )
                return True

            # Validation failed — log the parser output
            stderr = result.stderr.strip()
            logger.warning(
                "Syntax validation FAILED for '%s': %s",
                file_path,
                stderr or "(no stderr output)",
            )
            return False

        except subprocess.TimeoutExpired:
            logger.warning(
                "Syntax validation timed out for '%s'",
                file_path,
            )
            return False
        except OSError as exc:
            logger.warning(
                "Cannot run apparmor_parser for validation of '%s': %s",
                file_path,
                exc,
            )
            return False

    def _run_parser(self, args: list[str]) -> subprocess.CompletedProcess:
        """Run ``apparmor_parser`` with sudo and the given arguments.

        Parameters
        ----------
        args : list[str]
            Arguments to pass to ``apparmor_parser`` (e.g. ``["-r", "-W", "/path/to/profile"]``).

        Returns
        -------
        subprocess.CompletedProcess

        Raises
        ------
        subprocess.CalledProcessError
            If the parser exits with a non-zero status.
        OSError
            If the parser binary is not found.
        """
        assert self._parser_path is not None, "apparmor_parser not set"
        cmd = list(self._sudo_prefix) + [self._parser_path] + args

        logger.debug("Running: %s", " ".join(cmd))

        return subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def _read_sysfs_profiles(self) -> str | None:
        """Read the list of loaded AppArmor profiles from sysfs.

        Reads ``/sys/kernel/security/apparmor/profiles`` which contains
        one line per loaded profile in the format::

            /path/to/binary (enforce)

        Returns
        -------
        str or None
            The raw content of the profiles file, or ``None`` if
            the file could not be read (e.g. AppArmor not mounted).
        """
        try:
            with open(_SYSFS_PROFILES, "r") as fh:
                return fh.read()
        except (FileNotFoundError, PermissionError, OSError) as exc:
            logger.debug(
                "Cannot read %s: %s",
                _SYSFS_PROFILES,
                exc,
            )
            return None

    def _read_aa_status(self) -> str | None:
        """Fallback: read AppArmor status via ``aa-status``.

        Runs ``sudo aa-status --pretty-json`` (or plain ``aa-status``)
        and returns the output.

        Returns
        -------
        str or None
            The raw output of ``aa-status``, or ``None`` if the
            command is not available or fails.
        """
        if not self._sudo_prefix:
            return None

        # Find aa-status
        aa_status_path = shutil_which("aa-status")
        if not aa_status_path:
            aa_status_path = _AA_STATUS
            if not (os.path.isfile(aa_status_path) and os.access(aa_status_path, os.X_OK)):
                return None

        try:
            result = subprocess.run(
                list(self._sudo_prefix) + [aa_status_path],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                return result.stdout
            return result.stderr if result.stderr else None
        except (subprocess.TimeoutExpired, OSError) as exc:
            logger.debug("aa-status failed: %s", exc)
            return None

    @staticmethod
    def _parse_mode_from_line(line: str) -> str | None:
        """Extract the AppArmor mode from a status line.

        Handles both sysfs format (``/path (enforce)``) and
        ``aa-status`` format.

        Parameters
        ----------
        line : str
            A single line from ``/sys/kernel/security/apparmor/profiles``
            or ``aa-status`` output.

        Returns
        -------
        str or None
            ``"enforce"``, ``"complain"``, or ``None`` if the line
            does not contain a mode indicator.
        """
        m = re.search(r"\((\w+)\)\s*$", line)
        if m:
            mode = m.group(1).lower()
            if mode in ("enforce", "complain"):
                return mode
        return None

    def _set_mode(self, profile_name: str, target_mode: str) -> bool:
        """Internal helper to switch a profile's mode.

        Tries ``aa-enforce`` / ``aa-complain`` first, then falls
        back to ``apparmor_parser -r`` / ``apparmor_parser -C``
        using the profile's file.

        Parameters
        ----------
        profile_name : str
            Profile label (e.g. ``"wineshield-wine"``).
        target_mode : str
            ``"enforce"`` or ``"complain"``.

        Returns
        -------
        bool
            ``True`` on success, ``False`` on failure.
        """
        if not self.available or not self._sudo_prefix:
            logger.warning(
                "AppArmor not available — cannot set '%s' to %s mode",
                profile_name,
                target_mode,
            )
            return False

        # Map profile label → filename
        filename = _CANONICAL_PROFILES.get(profile_name)
        if not filename:
            logger.warning(
                "Unknown profile label '%s' — not a canonical WineShield profile",
                profile_name,
            )
            return False

        file_path = pathlib.Path(self._profile_dir) / filename
        if not file_path.is_file():
            logger.warning(
                "Profile file '%s' for '%s' not found",
                file_path,
                profile_name,
            )
            return False

        # Strategy 1: use aa-enforce / aa-complain utility
        if target_mode == "enforce":
            tool = shutil_which("aa-enforce") or "/usr/sbin/aa-enforce"
            parser_flag = "-r"
        else:
            tool = shutil_which("aa-complain") or "/usr/sbin/aa-complain"
            parser_flag = "-C"

        if os.path.isfile(tool) and os.access(tool, os.X_OK):
            try:
                subprocess.run(
                    list(self._sudo_prefix) + [tool, profile_name],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                ev = _make_event(
                    "info",
                    f"Profile mode changed to {target_mode}",
                    f"profile={profile_name}, mode={target_mode}",
                    session=self.session_id,
                )
                logger.info("Set '%s' to %s mode", profile_name, target_mode)
                logger.info("AppArmor event: %s", ev)
                return True
            except (subprocess.CalledProcessError, OSError) as exc:
                logger.debug(
                    "aa-%s for '%s' failed (%s) — trying parser fallback",
                    target_mode,
                    profile_name,
                    exc,
                )

        # Strategy 2: fallback to apparmor_parser with mode flag
        try:
            self._run_parser([parser_flag, "-W", str(file_path)])
            ev = _make_event(
                "info",
                f"Profile mode changed to {target_mode}",
                f"profile={profile_name}, mode={target_mode}",
                session=self.session_id,
            )
            logger.info("Set '%s' to %s mode (via parser)", profile_name, target_mode)
            logger.info("AppArmor event: %s", ev)
            return True
        except (subprocess.CalledProcessError, OSError) as exc:
            logger.warning(
                "Failed to set '%s' to %s mode: %s",
                profile_name,
                target_mode,
                exc,
            )
            return False


# ═════════════════════════════════════════════════════════════════════════════
#  shutil.which replacement (avoid extra import)
# ═════════════════════════════════════════════════════════════════════════════


def shutil_which(cmd: str) -> str | None:
    """Minimal ``which(1)`` — find an executable in ``$PATH``.

    Avoids importing ``shutil`` just for this one function.  Checks
    each directory in ``$PATH`` for the named executable.

    Parameters
    ----------
    cmd : str
        The command name to locate (e.g. ``"apparmor_parser"``).

    Returns
    -------
    str or None
        Full path to the executable, or ``None`` if not found.
    """
    try:
        path_env = os.environ.get("PATH", "")
        for directory in path_env.split(os.pathsep):
            candidate = os.path.join(directory, cmd)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
    except Exception:
        pass
    return None
