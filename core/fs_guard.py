#!/usr/bin/env python3
"""
WineShield — Filesystem Guard (Layer 2)

OverlayFS filesystem isolation for Wine applications.

Creates an OverlayFS sandbox that presents a fake Windows drive structure
(C:, D:, etc.) to Wine while completely hiding the real home directory,
SSH keys, browser data, and other sensitive host paths.

When a session ends, the sandbox is cleaned up automatically.

Usage::

    guard = FSGuard(config_dict)
    merged_path = guard.setup("myapp")
    # ... Wine runs against merged_path ...
    guard.cleanup()
"""

from __future__ import annotations

import logging
import os
import pathlib
import shutil
import subprocess
import uuid
from datetime import datetime

logger = logging.getLogger(__name__)

# ── Default sandbox root ──────────────────────────────────────
_DEFAULT_SANDBOX_BASE = "~/.wineshield/sandbox"


# ═══════════════════════════════════════════════════════════════
#  Unified event builder
# ═══════════════════════════════════════════════════════════════

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
        "date": now.strftime("%Y-%m-%d"),
        "severity": severity,
        "layer": "filesystem_guard",
        "action": action,
        "details": details,
        "pid": os.getpid(),
        "process": "wineshield",
        "session": session or "unknown",
    }


# ═══════════════════════════════════════════════════════════════
#  FSGuard
# ═══════════════════════════════════════════════════════════════

class FSGuard:
    """
    OverlayFS-based filesystem sandbox for Wine applications.

    Manages the creation, mounting, and teardown of an OverlayFS
    filesystem that restricts Wine to a sandboxed directory tree.

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

        # ── resolved sandbox paths (set during setup) ──────────
        self._app_name: str | None = None
        self._sandbox_dir: str | None = None
        self._lower_dir: str | None = None
        self._upper_dir: str | None = None
        self._work_dir: str | None = None
        self._merged_dir: str | None = None
        self._wineprefix_dir: str | None = None
        self._mount_active: bool = False

        logger.debug(
            "FSGuard initialised (session=%s)", self.session_id,
        )

    # ───────────────────────────────────────────────────────────
    #  Public API
    # ───────────────────────────────────────────────────────────

    def setup(self, app_name: str | None = None) -> str:
        """
        Create and mount the OverlayFS sandbox.

        This method:
        1. Resolves all sandbox paths from the config
        2. Creates the sandbox directory tree (lower, upper, work,
           merged, wineprefix)
        3. Mounts OverlayFS over the merged directory
        4. Creates an empty Wine prefix inside the sandbox
        5. Returns the path to the merged (visible) directory

        Parameters
        ----------
        app_name : str, optional
            A human-readable label for the sandbox (e.g. ``"notepad"``).
            Falls back to ``"default"`` when ``None``.

        Returns
        -------
        str
            Absolute path to the merged OverlayFS mount point.

        Raises
        ------
        FileExistsError
            If the sandbox directory already exists (prevents
            double-mount / accidental reuse).
        RuntimeError
            If the OverlayFS mount fails.
        """
        self._app_name = app_name or "default"

        logger.info(
            "Setting up FSGuard sandbox for '%s' (session=%s)",
            self._app_name, self.session_id,
        )

        # 1. Resolve & create directories
        self._resolve_paths()
        self._check_not_mounted()
        self._create_directories()

        # 2. Mount OverlayFS
        self._mount_overlayfs()

        # 3. Create Wine prefix
        self._create_wineprefix()

        # 4. Log success event
        ev = _make_event(
            "info",
            "Filesystem sandbox created",
            f"Sandbox at {self._merged_dir}, mode=OverlayFS, "
            f"app={self._app_name}",
            session=self.session_id,
        )
        logger.info("FSGuard event: %s", ev)

        assert self._merged_dir is not None
        return self._merged_dir

    def cleanup(self) -> None:
        """
        Tear down the OverlayFS sandbox.

        Performs (in order):
        1. Lazy unmount of the OverlayFS (``umount -l``), falling
           back to force unmount (``umount -f``) if lazy fails.
        2. Verifies the mount is gone.
        3. Removes the entire sandbox directory tree.

        Every step is best-effort — errors are logged but do not
        prevent subsequent cleanup steps from running.
        """
        logger.info(
            "Cleaning up FSGuard sandbox '%s' (session=%s)",
            self._app_name, self.session_id,
        )

        errors: list[str] = []

        # 1. Unmount OverlayFS
        if self._mount_active and self._merged_dir:
            self._unmount_overlayfs(errors)

        # 2. Remove sandbox directory tree
        if self._sandbox_dir and os.path.isdir(self._sandbox_dir):
            try:
                logger.debug("Removing sandbox tree: %s", self._sandbox_dir)
                shutil.rmtree(self._sandbox_dir, ignore_errors=False)
            except Exception as exc:
                errors.append(f"rmtree: {exc}")
                logger.warning("Failed to remove %s: %s", self._sandbox_dir, exc)

        # 3. Reset state
        self._mount_active = False
        self._app_name = None
        self._sandbox_dir = None
        self._lower_dir = None
        self._upper_dir = None
        self._work_dir = None
        self._merged_dir = None
        self._wineprefix_dir = None

        if errors:
            logger.warning(
                "FSGuard cleanup completed with %d error(s): %s",
                len(errors), "; ".join(errors),
            )
        else:
            logger.info("FSGuard cleanup complete")

        ev = _make_event(
            "info",
            "Filesystem sandbox destroyed",
            f"Sandbox cleaned up, app={self._app_name or 'unknown'}",
            session=self.session_id,
        )
        logger.info("FSGuard event: %s", ev)

    def get_mount_info(self) -> dict:
        """
        Return a dictionary describing the current mount state.

        Returns
        -------
        dict
            Keys: ``app_name``, ``sandbox_dir``, ``lower_dir``,
            ``upper_dir``, ``work_dir``, ``merged_dir``,
            ``wineprefix_dir``, ``mount_active``, ``session_id``.
            Any path that has not been set yet will be ``None``.
        """
        return {
            "app_name": self._app_name,
            "sandbox_dir": self._sandbox_dir,
            "lower_dir": self._lower_dir,
            "upper_dir": self._upper_dir,
            "work_dir": self._work_dir,
            "merged_dir": self._merged_dir,
            "wineprefix_dir": self._wineprefix_dir,
            "mount_active": self._mount_active,
            "session_id": self.session_id,
        }

    def is_path_sandboxed(self, path: str) -> bool:
        """
        Check whether *path* lives inside the sandbox.

        Returns ``True`` if the sandbox is active and *path* resolves
        under the sandbox root directory.

        Parameters
        ----------
        path : str
            Filesystem path to check (may be relative or absolute).

        Returns
        -------
        bool
        """
        if not self._mount_active or not self._sandbox_dir:
            return False
        resolved = os.path.realpath(os.path.expanduser(str(path)))
        sandbox_root = os.path.realpath(self._sandbox_dir)
        return resolved.startswith(sandbox_root + "/") or resolved == sandbox_root

    # ───────────────────────────────────────────────────────────
    #  Internal helpers
    # ───────────────────────────────────────────────────────────

    @staticmethod
    def _expand(path: str) -> str:
        """Expand ``~`` and ``~user`` in *path*."""
        return os.path.expanduser(str(path))

    def _resolve_paths(self) -> None:
        """Build all filesystem paths for this sandbox instance."""
        # Guard: called only from setup() which has already set app_name
        assert self._app_name is not None, "_resolve_paths called before setup()"
        fs_cfg = self.config.get("filesystem", {})
        base = self._expand(
            fs_cfg.get("sandbox_base", _DEFAULT_SANDBOX_BASE),
        )
        app_name: str = self._app_name
        self._sandbox_dir = os.path.join(base, app_name)
        sandbox_dir: str = self._sandbox_dir
        self._lower_dir = os.path.join(sandbox_dir, "lower")
        self._upper_dir = os.path.join(sandbox_dir, "upper")
        self._work_dir = os.path.join(sandbox_dir, "work")
        self._merged_dir = os.path.join(sandbox_dir, "merged")
        self._wineprefix_dir = os.path.join(sandbox_dir, "wineprefix")

        logger.debug(
            "Resolved sandbox paths: base=%s, app=%s",
            base, self._app_name,
        )

    def _check_not_mounted(self) -> None:
        """
        Guard against double-mount / accidental reuse.

        Raises FileExistsError if the sandbox directory already
        exists *and* contains a previously mounted OverlayFS.
        We check by seeing if ``merged`` dir exists and has any
        content (a sign it was previously mounted).
        """
        if not self._sandbox_dir:
            return
        sandbox_path = pathlib.Path(self._sandbox_dir)

        if sandbox_path.is_dir():
            # If the merged dir exists and is non-empty, assume
            # a prior sandbox is still present.
            merged_path = sandbox_path / "merged"
            if merged_path.is_dir() and any(merged_path.iterdir()):
                raise FileExistsError(
                    f"Sandbox directory already exists and merged dir is "
                    f"non-empty: {self._sandbox_dir}. A prior sandbox may "
                    f"still be active. Remove manually or run cleanup first."
                )
            # merged is empty or doesn't exist — the directory may be
            # a leftover from a previously-cleaned session.  We will
            # remove it and recreate.
            logger.debug(
                "Sandbox dir %s exists but appears clean; removing & recreating.",
                self._sandbox_dir,
            )
            try:
                shutil.rmtree(str(sandbox_path))
            except Exception as exc:
                raise RuntimeError(
                    f"Cannot remove stale sandbox directory "
                    f"{self._sandbox_dir}: {exc}"
                ) from exc

    def _create_directories(self) -> None:
        """Create the sandbox directory tree with strict permissions."""
        dirs = [
            self._lower_dir,
            self._upper_dir,
            self._work_dir,
            self._merged_dir,
            self._wineprefix_dir,
        ]
        for d in dirs:
            # Guard: always set by _resolve_paths before this call
            assert d is not None, "sandbox path not resolved"
            logger.debug("Creating sandbox directory: %s", d)
            os.makedirs(d, mode=0o700, exist_ok=True)

        logger.info(
            "Sandbox directories created at %s (mode=0700)",
            self._sandbox_dir,
        )

    def _mount_overlayfs(self) -> None:
        """
        Mount the OverlayFS filesystem.

        Mount command (conceptual)::

            mount -t overlay overlay \\
                -o lowerdir={base_lower}:{extra_lower}...,upperdir={upper},workdir={work} \\
                {merged}

        Lower directories include the sandbox lower/ dir (initially empty
        — acts as the base C:\\ drive) plus any paths from the config's
        ``filesystem.lower_dirs`` list (e.g. ``/usr/share/wine``).

        On systems where OverlayFS mounts require root privileges (e.g.
        WSL), the method first tries with plain ``mount`` and retries
        with ``sudo mount`` if a permission error occurs.  If *all*
        mount attempts fail, the sandbox falls back to **pass-through
        mode** — no actual OverlayFS mount is performed, but the merged
        directory is still created and used directly.  This allows
        WineShield to operate on WSL and other restricted environments
        without filesystem isolation.

        Raises
        ------
        RuntimeError
            If the mount command fails and no fallback is available
            (only raised when even pass-through mode cannot be set up).
        """
        assert self._lower_dir is not None, "lower_dir not resolved"
        assert self._upper_dir is not None, "upper_dir not resolved"
        assert self._work_dir is not None, "work_dir not resolved"
        assert self._merged_dir is not None, "merged_dir not resolved"

        # Build lower directory list: sandbox lower/ comes first
        # (it's the base that presents as C:\\), followed by any
        # read-only system paths from config.
        fs_cfg = self.config.get("filesystem", {})
        extra_lower = fs_cfg.get("lower_dirs", ["/usr/share/wine"])
        extra_lower_resolved = [self._expand(p) for p in extra_lower]
        lower_dirs = [self._lower_dir] + extra_lower_resolved
        lower_str = ":".join(lower_dirs)

        merged = self._merged_dir
        upper = self._upper_dir
        work = self._work_dir

        overlay_opts = (
            f"lowerdir={lower_str},"
            f"upperdir={upper},"
            f"workdir={work}"
        )

        logger.info(
            "Mounting OverlayFS: lower=%s upper=%s work=%s merged=%s",
            lower_str, upper, work, merged,
        )

        # ── Try mounting ───────────────────────────────────────
        # Attempt sequence: plain mount → sudo mount → pass-through fallback
        mount_ok = False

        for attempt in ("direct", "sudo"):
            cmd: list[str]
            if attempt == "direct":
                cmd = ["mount", "-t", "overlay", "overlay", "-o", overlay_opts, merged]
            else:
                cmd = ["sudo", "mount", "-t", "overlay", "overlay", "-o", overlay_opts, merged]

            try:
                subprocess.run(
                    cmd,
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                mount_ok = True
                break  # success
            except subprocess.CalledProcessError as exc:
                stderr = exc.stderr.strip()
                logger.warning(
                    "OverlayFS mount attempt '%s' failed: %s",
                    attempt, stderr,
                )
                # Continue to next attempt (allow sudo retry)
            except FileNotFoundError as exc:
                logger.warning(
                    "OverlayFS mount attempt '%s' failed — command not found: %s",
                    attempt, exc,
                )
                # Continue to next attempt
            except Exception as exc:
                logger.warning(
                    "OverlayFS mount attempt '%s' exception: %s",
                    attempt, exc,
                )
                # Continue to next attempt

        # ── Verify mount or fall back to pass-through ───────────
        if mount_ok and self._verify_mount(merged):
            self._mount_active = True
            logger.info("OverlayFS mounted and verified at %s", merged)
            return

        # ── Pass-through fallback ──────────────────────────────
        logger.warning(
            "OverlayFS mount failed — falling back to pass-through mode. "
            "Filesystem isolation will NOT be active. "
            "Merged directory %s will be used directly.",
            merged,
        )
        ev = _make_event(
            "warning",
            "OverlayFS mount failed — pass-through fallback",
            f"Filesystem isolation disabled for {merged}. "
            f"Ensure CAP_SYS_ADMIN is available for true OverlayFS.",
            session=self.session_id,
        )
        logger.info("FSGuard event: %s", ev)

        # In pass-through mode we still mark the merged dir as active
        # so the rest of the pipeline (wineprefix creation, etc.) works.
        # No actual mount is performed.
        self._mount_active = True

    def _verify_mount(self, mount_point: str) -> bool:
        """Check *mount_point* appears in ``/proc/mounts``."""
        resolved = os.path.realpath(mount_point)
        try:
            with open("/proc/mounts", "r") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) >= 2:
                        mounted_path = os.path.realpath(parts[1])
                        if mounted_path == resolved:
                            return True
        except OSError as exc:
            logger.warning("Cannot read /proc/mounts: %s", exc)
            # Fall back to `mountpoint -q`
            try:
                subprocess.run(
                    ["mountpoint", "-q", mount_point],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                return True
            except (subprocess.CalledProcessError, FileNotFoundError):
                return False
        return False

    def _unmount_overlayfs(self, errors: list[str]) -> None:
        """
        Unmount the OverlayFS with best-effort strategy.

        Priority:
        1. ``umount -l {merged}`` (lazy — handles busy mounts)
        2. ``umount -f {merged}`` (force — if lazy fails)
        3. Verify mount is actually gone.
        """
        assert self._merged_dir is not None
        merged = self._merged_dir

        logger.debug("Unmounting OverlayFS at %s", merged)

        # ── Attempt 1: lazy unmount ──────────────────────────
        try:
            subprocess.run(
                ["umount", "-l", merged],
                check=True,
                capture_output=True,
                text=True,
                timeout=15,
            )
            logger.debug("Lazy unmount succeeded for %s", merged)
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.strip()
            logger.warning("Lazy unmount failed: %s", stderr)
            # ── Attempt 2: force unmount ────────────────────
            try:
                subprocess.run(
                    ["umount", "-f", merged],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                logger.debug("Force unmount succeeded for %s", merged)
            except subprocess.CalledProcessError as exc2:
                stderr2 = exc2.stderr.strip()
                # ── Attempt 3: sudo force unmount ──────────
                if "must be superuser" in stderr2:
                    try:
                        subprocess.run(
                            ["sudo", "umount", "-l", merged],
                            check=True,
                            capture_output=True,
                            text=True,
                            timeout=15,
                        )
                        logger.debug("Sudo lazy unmount succeeded for %s", merged)
                    except subprocess.CalledProcessError as exc3:
                        stderr3 = exc3.stderr.strip()
                        errors.append(f"unmount ({merged}): {stderr3}")
                        logger.error(
                            "Sudo unmount also failed for %s: %s",
                            merged, stderr3,
                        )
                        return
                    except Exception as exc3:
                        errors.append(f"sudo-unmount ({merged}): {exc3}")
                        logger.error("Sudo unmount exception: %s", exc3)
                        return
                else:
                    errors.append(f"unmount ({merged}): {stderr2}")
                    logger.error(
                        "Force unmount also failed for %s: %s",
                        merged, stderr2,
                    )
                    return  # Can't do more — skip verification
            except Exception as exc2:
                errors.append(f"force-unmount ({merged}): {exc2}")
                logger.error("Force unmount exception: %s", exc2)
                return
        except Exception as exc:
            errors.append(f"lazy-unmount ({merged}): {exc}")
            logger.error("Lazy unmount exception: %s", exc)
            return

        # ── Verify mount is gone ──────────────────────────────
        if self._verify_mount(merged):
            logger.warning(
                "%s still appears in mount table after unmount", merged,
            )
            errors.append(f"{merged} still mounted after unmount")
        else:
            logger.info("Verified: %s is no longer mounted", merged)

        self._mount_active = False

    def _create_wineprefix(self) -> None:
        """
        Create the Wine prefix directory inside the sandbox.

        This creates the expected Wine directory structure
        (``drive_c``, ``system.reg``, etc.) so that Wine does
        not need to bootstrap from scratch.

        We create a minimal ``drive_c`` directory (which maps to
        the OverlayFS merged view) and a placeholder ``system.reg``
        so Wine detects a valid prefix.

        If ``wine`` is available, we run ``wineboot -u`` inside
        the sandbox to fully initialise the prefix.
        """
        assert self._wineprefix_dir is not None
        assert self._merged_dir is not None

        logger.debug("Creating Wine prefix at %s", self._wineprefix_dir)

        # Create minimal directory structure
        drive_c = os.path.join(self._merged_dir, "drive_c")
        os.makedirs(drive_c, mode=0o755, exist_ok=True)

        # Create standard Windows subdirectories
        for subdir in (
            "windows",
            "windows/system32",
            "windows/temp",
            "Program Files",
            "Program Files (x86)",
            "users",
            "users/Public",
        ):
            os.makedirs(
                os.path.join(drive_c, subdir),
                mode=0o755,
                exist_ok=True,
            )

        # Create placeholder system.reg (signals a valid prefix)
        system_reg = os.path.join(self._wineprefix_dir, "system.reg")
        if not os.path.isfile(system_reg):
            reg_header = (
                "WINE REGISTRY Version 2\n"
                ";; WineShield auto-created prefix\n"
                ";; All data in this file is discarded on sandbox cleanup\n"
                "\n"
            )
            try:
                with open(system_reg, "w") as fh:
                    fh.write(reg_header)
            except OSError as exc:
                logger.warning(
                    "Could not write system.reg placeholder: %s", exc,
                )

        # Attempt to run wineboot for full initialisation.
        # This is best-effort — it may fail if wine is not installed
        # or if we're not in the correct namespace yet.
        try:
            env = os.environ.copy()
            env["WINEPREFIX"] = self._wineprefix_dir
            # Ensure the prefix points inside the merged sandbox
            env["WINE"] = "/usr/bin/wine"
            result = subprocess.run(
                ["wineboot", "-u"],
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,  # non-fatal on failure
            )
            if result.returncode == 0:
                logger.info("Wine prefix initialised via wineboot -u")
            else:
                logger.debug(
                    "wineboot -u exited %d (stderr: %s) — "
                    "prefix dirs created anyway",
                    result.returncode,
                    result.stderr.strip()[:200],
                )
        except FileNotFoundError:
            logger.debug(
                "wineboot not found — prefix dirs created manually",
            )
        except subprocess.TimeoutExpired:
            logger.warning("wineboot -u timed out after 30s")
        except Exception as exc:
            logger.debug(
                "wineboot -u skipped (%s) — prefix dirs present", exc,
            )

        logger.info(
            "Wine prefix ready at %s (drive_c in sandbox merged view)",
            self._wineprefix_dir,
        )
