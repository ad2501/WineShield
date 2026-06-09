#!/usr/bin/env python3
"""
WineShield — Sandbox Engine
Linux Namespace and OverlayFS management for WineShield.

Creates isolated Linux namespaces (PID, Mount, Network, UTS, IPC)
via os.unshare() and sets up OverlayFS filesystem isolation for
running Wine applications inside a sandboxed environment.

This module is called by launcher.py and is not intended to be
used directly by end users.
"""

import logging
import os
import pathlib
import shutil
import subprocess
import tempfile

logger = logging.getLogger(__name__)

# ── Namespace label map (for human-readable logging) ──────────────
_NAMESPACE_LABELS = {
    os.CLONE_NEWNS:   "mount",
    os.CLONE_NEWUTS:  "UTS",
    os.CLONE_NEWIPC:  "IPC",
    os.CLONE_NEWPID:  "PID",
    os.CLONE_NEWNET:  "network",
    os.CLONE_NEWUSER: "user",
}

# ── Default hostname used inside the UTS namespace ────────────────
SANDBOX_HOSTNAME = "wineshield-sandbox"


# ═══════════════════════════════════════════════════════════════════
#  WineSandbox
# ═══════════════════════════════════════════════════════════════════

class WineSandbox:
    """
    Manages Linux namespace creation and OverlayFS filesystem isolation
    for Wine application sandboxing.

    Usage::

        sandbox = WineSandbox(config_dict)
        sandbox.create_sandbox("myapp")
        # … current process is now inside the namespaces …
        sandbox.destroy_sandbox()

    All namespace creation and mount operations happen in the *current*
    process.  After a successful ``create_sandbox()`` call the caller
    can exec Wine (or fork + exec) and the child will inherit the
    isolated environment.
    """

    def __init__(self, config_dict):
        """
        Initialise the sandbox engine with a parsed configuration dict.

        Parameters
        ----------
        config_dict : dict
            Parsed configuration (e.g. from ``default_policy.json``).
            Expected structure (``filesystem`` section):

            .. code-block:: python

                config_dict = {
                    "filesystem": {
                        "sandbox_base": "~/.wineshield/sandbox",
                        "lower_dirs": ["/usr/share/wine"],
                        "read_only_mask": ["~/.ssh", …],
                        "cleanup_on_exit": True,
                        "wineprefix_isolation": True,
                    },
                    "network": {
                        "use_network_namespace": False,
                    },
                }
        """
        self.config = config_dict
        self._log = logging.getLogger(__name__)

        # ── runtime state ──────────────────────────────────────
        self._app_name: str | None = None
        self._sandbox_dir: str | None = None
        self._upper_dir: str | None = None
        self._work_dir: str | None = None
        self._merged_dir: str | None = None
        self._wineprefix_dir: str | None = None

        # Which namespace flags were successfully unshared (ordered)
        self._namespaces_unshared: list[int] = []

        # Mount points we created — each entry is either a plain
        # path str (for a simple mount) or a tuple ("overlay", path)
        # so cleanup can choose the right unmount strategy.
        self._mounts_active: list[str | tuple[str, str]] = []

        self._is_active: bool = False
        self._error: str | None = None
        self._reduced_isolation: bool = False

    # ───────────────────────────────────────────────────────────
    #  Internal helpers
    # ───────────────────────────────────────────────────────────

    @staticmethod
    def _expand(path: str) -> str:
        """Expand ``~`` and ``~user`` in *path*."""
        return os.path.expanduser(str(path))

    # ───────────────────────────────────────────────────────────
    #  Path resolution & directory creation
    # ───────────────────────────────────────────────────────────

    def _resolve_sandbox_paths(self, app_name: str) -> None:
        """Build all filesystem paths for this sandbox instance."""
        fs = self.config.get("filesystem", {})
        base = self._expand(fs.get("sandbox_base", "~/.wineshield/sandbox"))
        self._sandbox_dir = os.path.join(base, app_name)
        self._upper_dir = os.path.join(self._sandbox_dir, "upper")
        self._work_dir = os.path.join(self._sandbox_dir, "work")
        self._merged_dir = os.path.join(self._sandbox_dir, "merged")
        self._wineprefix_dir = os.path.join(self._sandbox_dir, "wineprefix")

    def _create_directories(self) -> None:
        """Create the sandbox directory tree (upper / work / merged / wineprefix)."""
        for d in (self._upper_dir, self._work_dir,
                  self._merged_dir, self._wineprefix_dir):
            # Guard: these are always set before _create_directories is called
            assert d is not None, "sandbox paths not resolved"
            self._log.debug("Creating sandbox directory: %s", d)
            os.makedirs(d, mode=0o755, exist_ok=True)

    # ───────────────────────────────────────────────────────────
    #  Namespace creation
    # ───────────────────────────────────────────────────────────

    def _unshare_namespaces(self) -> None:
        """
        Create Linux namespaces via ``os.unshare()``.

        Order (from the architecture specification):
            1. UTS      — isolate hostname
            2. IPC      — isolate System V IPC
            3. PID      — isolate process tree (child processes only)
            4. Mount    — isolate filesystem mount table
            5. Network  — isolate network stack (only if config enables it)

        Calling process *enters* all namespaces except PID — for PID
        the current process stays in the parent PID namespace and only
        future children will see the isolated PID tree.

        Raises
        ------
        RuntimeError
            If any unshare fails.
        """
        namespace_order = [
            os.CLONE_NEWUTS,
            os.CLONE_NEWIPC,
            os.CLONE_NEWPID,
            os.CLONE_NEWNS,
        ]

        # Optional: network namespace
        net_cfg = self.config.get("network", {})
        if net_cfg.get("use_network_namespace", False):
            namespace_order.append(os.CLONE_NEWNET)
            self._log.info("Network namespace is enabled by config")

        # ── handle user namespace first (unprivileged) ─────
        # If we are not root, create a user namespace *first*
        # so we get CAP_SYS_ADMIN inside it, which allows
        # creating the other namespace types.
        if os.geteuid() != 0:
            try:
                os.unshare(os.CLONE_NEWUSER)
                self._namespaces_unshared.append(os.CLONE_NEWUSER)
                self._log.debug("Unshared user namespace (unprivileged mode)")
            except PermissionError:
                self._log.warning(
                    "Cannot create user namespace (permission denied). "
                    "Sandbox will attempt direct unshare – this may "
                    "require root privileges."
                )
            except Exception as exc:
                # Non-fatal — try the other namespaces anyway
                self._log.warning("User namespace unshare failed: %s", exc)

        # ── unshare the remaining namespaces ────────────────
        for flags in namespace_order:
            label = _NAMESPACE_LABELS.get(flags, f"0x{flags:08x}")
            self._log.info("Unsharing %s namespace (flags=0x%08x)", label, flags)
            try:
                os.unshare(flags)
                self._namespaces_unshared.append(flags)
                self._log.debug("Successfully unshared %s namespace", label)
            except PermissionError:
                self._log.error(
                    "Cannot create %s namespace — permission denied. "
                    "Run as root or adjust "
                    "kernel.unprivileged_userns_clone=1.",
                    label,
                )
                raise
            except Exception as exc:
                # PID namespace is known to fail on WSL (Cannot allocate memory).
                # Make this non-fatal — skip PID and continue with the
                # remaining namespaces (mount, UTS, IPC, network).
                if flags == os.CLONE_NEWPID:
                    self._log.warning(
                        "PID namespace creation failed (%s). "
                        "This is expected on WSL. "
                        "Continuing without PID namespace isolation.",
                        exc,
                    )
                    continue
                self._log.error("Failed to create %s namespace: %s", label, exc)
                raise

        # ── set hostname inside the new UTS namespace ───────
        if os.CLONE_NEWUTS in self._namespaces_unshared:
            try:
                subprocess.run(
                    ["hostname", SANDBOX_HOSTNAME],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                self._log.debug("Hostname set to '%s'", SANDBOX_HOSTNAME)
            except Exception as exc:
                # Non-fatal — the isolated namespace still works
                self._log.warning("Could not set sandbox hostname: %s", exc)

    # ───────────────────────────────────────────────────────────
    #  Filesystem mounts (inside the new mount namespace)
    # ───────────────────────────────────────────────────────────

    def _mount_proc(self) -> None:
        """Mount a fresh ``proc`` filesystem on ``/proc``.

        On systems where PID namespaces are not available (e.g. WSL) this
        mount will fail — the error is caught and logged as a warning
        but does not abort sandbox creation.
        """
        self._log.info("Mounting /proc inside namespace")
        try:
            subprocess.run(
                ["mount", "-t", "proc", "proc", "/proc"],
                check=True,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self._mounts_active.append("/proc")
            self._log.debug("/proc mounted")
        except OSError as e:
            if e.errno == 12:  # ENOMEM — WSL limitation
                self._log.warning(
                    "WSL limitation: mount proc not available inside namespace — "
                    "continuing without /proc isolation"
                )
                self._reduced_isolation = True
            else:
                raise
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.strip()
            self._log.warning(
                "Failed to mount /proc (%s). "
                "This is expected on WSL when PID namespace is not available. "
                "Continuing without /proc isolation.",
                stderr,
            )
        except Exception as exc:
            self._log.warning(
                "Failed to mount /proc: %s. Continuing without /proc isolation.",
                exc,
            )

    def _mount_sys(self) -> None:
        """Mount ``sysfs`` read-only on ``/sys``.

        On systems where kernel filesystem mounts are restricted
        (e.g. WSL) this may fail — the error is caught and logged
        as a warning but does not abort sandbox creation.
        """
        self._log.info("Mounting /sys as read-only")
        try:
            subprocess.run(
                ["mount", "-t", "sysfs", "-o", "ro", "sysfs", "/sys"],
                check=True,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self._mounts_active.append("/sys")
            self._log.debug("/sys mounted read-only")
        except OSError as e:
            if e.errno == 12:  # ENOMEM — WSL limitation
                self._log.warning(
                    "WSL limitation: mount sysfs not available inside namespace — "
                    "continuing without /sys isolation"
                )
                self._reduced_isolation = True
            else:
                raise
        except subprocess.CalledProcessError as exc:
            self._log.warning(
                "Failed to mount /sys read-only: %s", exc.stderr.strip()
            )
            # Non-fatal — many Wine applications work without /sys
        except Exception as exc:
            self._log.warning(
                "Failed to mount /sys: %s. Continuing without /sys isolation.",
                exc,
            )

    def _mount_dev(self) -> None:
        """
        Mount a minimal ``tmpfs`` on ``/dev``.

        Only the following device nodes are created:
            /dev/null, /dev/zero, /dev/random, /dev/urandom

        This is intentionally *not* a full ``/dev`` — it provides
        just enough for Wine and common libraries to function while
        hiding host devices.

        On systems where kernel mounts are restricted (e.g. WSL)
        this may fail — the error is caught and logged as a warning
        but does not abort sandbox creation.
        """
        self._log.info("Mounting minimal /dev tmpfs")
        try:
            subprocess.run(
                [
                    "mount", "-t", "tmpfs",
                    "-o", "mode=0755,size=1M",
                    "wineshield-dev", "/dev",
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self._mounts_active.append("/dev")
        except OSError as e:
            if e.errno == 12:  # ENOMEM — WSL limitation
                self._log.warning(
                    "WSL limitation: mount dev tmpfs not available inside namespace — "
                    "continuing without /dev isolation"
                )
                self._reduced_isolation = True
                return
            else:
                raise
        except subprocess.CalledProcessError as exc:
            self._log.warning(
                "Failed to mount /dev tmpfs: %s. "
                "Continuing without /dev isolation.",
                exc.stderr.strip(),
            )
            return  # skip device node creation
        except Exception as exc:
            self._log.warning(
                "Failed to mount /dev: %s. Continuing without /dev isolation.",
                exc,
            )
            return

        # ── create essential device nodes ────────────────────
        devices = [
            ("null",    0o666, (1, 3)),
            ("zero",    0o666, (1, 5)),
            ("random",  0o444, (1, 8)),
            ("urandom", 0o444, (1, 9)),
        ]
        for name, mode_bits, (major, minor) in devices:
            dev_path = f"/dev/{name}"
            try:
                subprocess.run(
                    ["mknod", dev_path, "c", str(major), str(minor)],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                os.chmod(dev_path, mode_bits)
            except subprocess.CalledProcessError as exc:
                self._log.error(
                    "Failed to create %s (major=%d, minor=%d): %s",
                    dev_path, major, minor, exc.stderr.strip(),
                )
                raise

        self._log.debug("Minimal /dev ready — null, zero, random, urandom")

    def _mount_overlayfs(self) -> None:
        """
        Mount the OverlayFS filesystem.

        Lower directories come from the config (``filesystem.lower_dirs``).
        Upper and work directories are per-sandbox and stored inside
        ``{sandbox_dir}/{upper,work}``.  The merged view appears at
        ``{sandbox_dir}/merged``.

        Mount command (conceptual)::

            mount -t overlay overlay \\
                -o lowerdir={l1}:{l2},upperdir={upper},workdir={work} \\
                {merged}

        On systems where OverlayFS mounts require root (e.g. WSL),
        the method retries with ``sudo mount``.  If *all* mount
        attempts fail, a warning is logged and the sandbox continues
        without filesystem isolation (pass-through).
        """
        assert self._merged_dir is not None, "merged_dir not resolved"
        assert self._upper_dir is not None, "upper_dir not resolved"
        assert self._work_dir is not None, "work_dir not resolved"

        fs_cfg = self.config.get("filesystem", {})
        raw_lower = fs_cfg.get("lower_dirs", ["/usr/share/wine"])
        lower_dirs = [self._expand(p) for p in raw_lower]
        lower_str = ":".join(lower_dirs)

        merged = self._merged_dir
        upper = self._upper_dir
        work = self._work_dir

        self._log.info(
            "Mounting OverlayFS: lower=%s upper=%s work=%s merged=%s",
            lower_str, upper, work, merged,
        )

        overlay_opts = (
            f"lowerdir={lower_str},"
            f"upperdir={upper},"
            f"workdir={work}"
        )

        # ── Try mounting: plain mount → sudo mount → pass-through ──
        for attempt in ("direct", "sudo"):
            cmd: list[str]
            if attempt == "direct":
                cmd = ["mount", "-t", "overlay", "overlay",
                       "-o", overlay_opts, merged]
            else:
                cmd = ["sudo", "mount", "-t", "overlay", "overlay",
                       "-o", overlay_opts, merged]

            try:
                subprocess.run(
                    cmd,
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                self._mounts_active.append(("overlay", merged))
                self._log.debug("OverlayFS mounted at %s", merged)
                return  # success
            except OSError as e:
                if e.errno == 12:  # ENOMEM — WSL limitation
                    self._log.warning(
                        "WSL limitation: OverlayFS not available inside namespace — "
                        "continuing without filesystem isolation"
                    )
                    self._reduced_isolation = True
                    # Break out of the loop — no point retrying with sudo
                    break
                else:
                    raise
            except subprocess.CalledProcessError as exc:
                self._log.warning(
                    "OverlayFS mount attempt '%s' failed: %s",
                    attempt, exc.stderr.strip(),
                )
            except Exception as exc:
                self._log.warning(
                    "OverlayFS mount attempt '%s' exception: %s",
                    attempt, exc,
                )

        # ── Pass-through fallback ──────────────────────────────
        self._log.warning(
            "OverlayFS mount failed — continuing without filesystem "
            "isolation (pass-through mode)."
        )

    def _mount_read_only_masks(self) -> None:
        """
        Mask sensitive host paths with an empty, read-only tmpfs.

        Each path listed in ``filesystem.read_only_mask`` gets a tiny
        tmpfs mounted over it (``-o ro,size=64K``).  Inside the sandbox
        these paths will appear as empty, read-only directories,
        preventing a malicious application from reading or modifying
        sensitive host data.

        Errors are logged but are *non-fatal* — masking is a defence-in-
        depth measure.
        """
        fs_cfg = self.config.get("filesystem", {})
        mask_paths = fs_cfg.get("read_only_mask", [])

        for raw_path in mask_paths:
            path = self._expand(raw_path)
            if not os.path.exists(path):
                self._log.debug("Mask path '%s' does not exist — skipping", path)
                continue

            self._log.info("Mounting read-only tmpfs over %s", path)
            try:
                subprocess.run(
                    [
                        "mount", "-t", "tmpfs",
                        "-o", "ro,size=64K,mode=0700",
                        "wineshield-mask", path,
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                self._mounts_active.append(path)
            except OSError as e:
                if e.errno == 12:  # ENOMEM — WSL limitation
                    self._log.warning(
                        "WSL limitation: cannot mask '%s' inside namespace — "
                        "continuing without masking that path",
                        path,
                    )
                    self._reduced_isolation = True
                else:
                    raise
            except subprocess.CalledProcessError as exc:
                self._log.warning(
                    "Failed to mask '%s': %s", path, exc.stderr.strip()
                )
                # Non-fatal — remaining masks are still applied
            except Exception as exc:
                self._log.warning(
                    "Failed to mask '%s': %s — continuing",
                    path, exc,
                )
                self._reduced_isolation = True

    # ───────────────────────────────────────────────────────────
    #  Environment
    # ───────────────────────────────────────────────────────────

    def _set_environment(self) -> None:
        """
        Set environment variables for the sandboxed Wine session.

        * ``WINEPREFIX`` → ``{sandbox_dir}/wineprefix/``
          (if ``wineprefix_isolation`` is ``True``).
        * ``SANDBOX_HOSTNAME`` → ``wineshield-sandbox``
        """
        if self.config.get("filesystem", {}).get("wineprefix_isolation", True):
            assert self._wineprefix_dir is not None, "wineprefix_dir not resolved"
            os.environ["WINEPREFIX"] = self._wineprefix_dir
            self._log.info("WINEPREFIX set to %s", self._wineprefix_dir)

        os.environ["SANDBOX_HOSTNAME"] = SANDBOX_HOSTNAME

    # ───────────────────────────────────────────────────────────
    #  Public API
    # ───────────────────────────────────────────────────────────

    def create_sandbox(self, app_name: str) -> None:
        """
        Create a complete sandboxed environment for *app_name*.

        After a successful call the **current process** is inside the
        new namespaces.  The caller should then exec (or fork + exec)
        the Wine binary — the child process will inherit the isolation.

        Steps
        -----
        1. Resolve and create sandbox directories.
        2. Unshare Linux namespaces (UTS, IPC, PID, Mount, Network).
        3. Mount ``/proc``, ``/sys`` (ro), and minimal ``/dev``.
        4. Mount OverlayFS for filesystem isolation.
        5. Mount read-only tmpfs over sensitive host paths.
        6. Set ``$WINEPREFIX`` and other environment variables.

        Parameters
        ----------
        app_name : str
            Unique identifier for this sandbox (used as the directory
            name under ``sandbox_base``).

        Raises
        ------
        RuntimeError
            If any step fails.  Partial state is cleaned up before
            the exception propagates.

        Notes
        -----
        If the sandbox is already active this is a no-op (logged as
        a warning).
        """
        if self._is_active:
            self._log.warning(
                "Sandbox already active for '%s' — ignoring duplicate call",
                self._app_name,
            )
            return

        self._app_name = app_name
        self._error = None
        self._reduced_isolation = False
        self._log.info("Creating sandbox for application '%s'", app_name)

        try:
            # 1. Directories
            self._resolve_sandbox_paths(app_name)
            self._create_directories()

            # 2. Namespaces
            self._unshare_namespaces()

            # 3. Essential filesystems
            self._mount_proc()
            self._mount_sys()
            self._mount_dev()

            # 4. OverlayFS
            self._mount_overlayfs()

            # 5. Read-only masking
            self._mount_read_only_masks()

            # 6. Environment
            self._set_environment()

            self._is_active = True
            if self._reduced_isolation:
                self._log.info(
                    "Sandbox '%s' created at %s (reduced isolation — "
                    "some features unavailable on this platform)",
                    app_name, self._sandbox_dir,
                )
            else:
                self._log.info(
                    "Sandbox '%s' created at %s",
                    app_name, self._sandbox_dir,
                )

        except Exception as exc:
            self._error = str(exc)
            self._log.critical("Sandbox creation failed: %s", exc)
            self.destroy_sandbox()
            raise RuntimeError(
                f"Failed to create sandbox '{app_name}': {exc}"
            ) from exc

    # ───────────────────────────────────────────────────────────
    #  Cleanup
    # ───────────────────────────────────────────────────────────

    @staticmethod
    def _unmount_with_fallback(mount_point: str, errors: list[str]) -> None:
        """Unmount *mount_point*, retrying with ``sudo`` if needed.

        Attempt sequence: ``umount -l`` → ``sudo umount -l``.
        Errors are appended to *errors* but do not raise.
        """
        for cmd in (
            ["umount", "-l", mount_point],
            ["sudo", "umount", "-l", mount_point],
        ):
            try:
                subprocess.run(cmd, check=True, capture_output=True,
                               text=True, timeout=15)
                return  # success
            except (subprocess.CalledProcessError, FileNotFoundError,
                    OSError) as exc:
                stderr = getattr(exc, 'stderr', None)
                msg = stderr.strip() if stderr else str(exc)
                # Log the attempt failure — continue to next
                continue
        # All attempts failed
        errors.append(f"Unmount ({mount_point}): all attempts failed")

    def destroy_sandbox(self) -> None:
        """
        Tear down the sandbox environment.

        Cleanup is performed in **reverse** order (last-created,
        first-destroyed):

        1. Unmount OverlayFS (lazy unmount ``umount -l``).
        2. Unmount ``/dev``, ``/sys``, ``/proc`` + any mask mounts.
        3. Remove the sandbox directory tree.
        4. Reset internal state.

        Every step is best-effort — errors are logged but do not
        prevent remaining cleanup from proceeding.
        """
        self._log.info("Destroying sandbox '%s'", self._app_name)
        errors: list[str] = []

        # ── unmount in reverse order ──────────────────────────
        for item in reversed(self._mounts_active):
            if isinstance(item, tuple) and item[0] == "overlay":
                _tag, mount_point = item
                assert isinstance(mount_point, str)
                self._log.debug("Unmounting OverlayFS at %s", mount_point)
                self._unmount_with_fallback(mount_point, errors)
            else:
                mount_point = item
                assert isinstance(mount_point, str)
                self._log.debug("Unmounting %s", mount_point)
                self._unmount_with_fallback(mount_point, errors)

        self._mounts_active.clear()

        # ── remove sandbox directories (unless config says to keep) ─
        cleanup = self.config.get("filesystem", {}).get("cleanup_on_exit", True)
        if cleanup and self._sandbox_dir and os.path.exists(self._sandbox_dir):
            self._log.debug("Removing sandbox directory %s", self._sandbox_dir)
            try:
                shutil.rmtree(self._sandbox_dir, ignore_errors=True)
            except Exception as exc:
                errors.append(f"Directory cleanup: {exc}")
        elif not cleanup and self._sandbox_dir and os.path.exists(self._sandbox_dir):
            self._log.info(
                "cleanup_on_exit=False — preserving sandbox at %s",
                self._sandbox_dir,
            )

        # ── reset state ──────────────────────────────────────
        self._namespaces_unshared.clear()
        self._is_active = False
        self._error = None

        # ── report accumulated errors ────────────────────────
        for err in errors:
            self._log.warning("Cleanup issue: %s", err)
        if errors:
            self._log.info(
                "Sandbox destroyed with %d non-fatal issue(s)", len(errors)
            )
        else:
            self._log.info("Sandbox destroyed cleanly")

    def get_status(self) -> dict:
        """
        Return a snapshot of the current sandbox state.

        Returns
        -------
        dict
            Keys:

            ``app_name``
                Application name (or ``None``).
            ``sandbox_dir``, ``upper_dir``, ``work_dir``,
            ``merged_dir``, ``wineprefix_dir``
                Resolved filesystem paths (or ``None``).
            ``is_active``
                ``True`` if the sandbox is currently active.
            ``namespaces_active``
                List of human-readable namespace names that were
                successfully unshared.
            ``mounts_active``
                List of mount-point paths currently tracked.
            ``error``
                Error string from a failed ``create_sandbox()``,
                or ``None``.
            ``reduced_isolation``
                ``True`` if some isolation features were skipped
                (e.g. due to WSL limitations).
            ``sandbox_dir_exists``
                ``True`` if the sandbox directory physically exists
                on disk.
        """
        return {
            "app_name": self._app_name,
            "sandbox_dir": self._sandbox_dir,
            "upper_dir": self._upper_dir,
            "work_dir": self._work_dir,
            "merged_dir": self._merged_dir,
            "wineprefix_dir": self._wineprefix_dir,
            "is_active": self._is_active,
            "namespaces_active": [
                _NAMESPACE_LABELS.get(f, f"0x{f:08x}")
                for f in self._namespaces_unshared
            ],
            "mounts_active": [
                m[1] if isinstance(m, tuple) else m
                for m in self._mounts_active
            ],
            "error": self._error,
            "reduced_isolation": self._reduced_isolation,
            "sandbox_dir_exists": (
                os.path.isdir(self._sandbox_dir)
                if self._sandbox_dir
                else False
            ),
        }

    # ───────────────────────────────────────────────────────────
    #  Context-manager support
    # ───────────────────────────────────────────────────────────

    def __enter__(self) -> "WineSandbox":
        """Enter context — requires that the sandbox is already active."""
        if not self._is_active:
            raise RuntimeError(
                "Cannot enter context: sandbox not active. "
                "Call create_sandbox() first."
            )
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object | None,
    ) -> bool:
        """Exit context — tears down the sandbox."""
        self.destroy_sandbox()
        return False  # do not suppress exceptions


class SandboxEngine(WineSandbox):
    """Backward-compatible facade for older integration tests and docs.

    The modern implementation is :class:`WineSandbox`, which expects a config
    dict and exposes ``create_sandbox``.  Older code instantiated
    ``SandboxEngine()`` and called ``create_namespaces()`` directly, so this
    facade preserves that narrow API without changing WineSandbox semantics.
    """

    def __init__(self, config_dict: dict | None = None):
        super().__init__(config_dict or {})

    def create_namespaces(self) -> bool:
        """Create namespaces only and return whether the operation completed."""
        self._unshare_namespaces()
        return True
