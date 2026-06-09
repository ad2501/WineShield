# WineShield Troubleshooting Guide

## Known Issues

### 1. Sandbox Creation Fails: `[Errno 12] Cannot allocate memory`

**Symptom:** `os.unshare()` returns ENOMEM when creating PID or mount namespaces.

**Cause:** WSL2's lightweight virtualisation does not fully support nested namespace creation with `CLONE_NEWPID` or `CLONE_NEWNS`. This is a known WSL limitation (Microsoft/WSL#4550).

**Solution:** WineShield automatically enters **reduced isolation mode** when this error is detected. The sandbox still provides:
- Filesystem root (via sandbox directory)
- Event logging
- Layer initialisation

On a **real Linux system**, full namespace isolation works without issue.

### 2. AppArmor: `[Errno 95] Operation not supported`

**Symptom:** `OSError: [Errno 95] Operation not supported` during AppArmor initialisation.

**Cause:** The WSL kernel does not include AppArmor LSM support.

**Solution:** The AppArmor layer detects this and disables itself gracefully with a log warning. AppArmor profiles are pre-configured and will activate automatically on a native Linux kernel with AppArmor support.

### 3. OverlayFS Mount Fails

**Symptom:** OverlayFS mount returns an error during sandbox creation.

**Cause:** On WSL, `mount(2)` with `overlay` filesystem type may fail due to missing kernel support or permission restrictions.

**Solution:** The filesystem guard falls back to a bind-mount approach. This provides read-only access to the host filesystem while still isolating Wine writes to the sandbox directory.

### 4. Wine GUI Not Displaying

**Symptom:** Wine GUI applications (Notepad++, explorer) launch but no window appears.

**Cause:** No X display server is available.

**Solutions (in order of preference):**

1. **WSLg (Windows 11 WSL2):** Native display support. Check with `echo $DISPLAY`. If it returns `:0`, WSLg is active.
2. **Xvfb (virtual framebuffer):**
   ```bash
   Xvfb :99 -screen 0 1024x768x24 &
   export DISPLAY=:99
   ```
3. **VcXsrv / X410 (Windows X server):** Install on Windows, then set `export DISPLAY=$(hostname).local:0`.

### 5. Wine Runs Slowly on First Launch

**Symptom:** First `wine` command takes 30–180 seconds.

**Cause:** Wine is initialising the Wine Prefix (`~/.wine`). This creates the directory structure, sets up the registry, and installs default DLLs.

**Solution:** Pre-initialise the prefix:
```bash
wine wineboot -u
```
Wait for it to complete. Subsequent Wine launches are fast.

### 6. `sudo -E` Does Not Preserve Environment

**Symptom:** Environment variables like `DISPLAY`, `WINEPREFIX` are lost when running through sudo.

**Cause:** WSL's sudo configuration ignores `-E` (preserve environment) even when `env_reset` is disabled in `/etc/sudoers`.

**Solution:** Pass variables explicitly before the sudo command:
```bash
sudo DISPLAY=:0 WINEPREFIX=$HOME/.wine ./core/syscall_monitor --mode monitor --user $(whoami) -- wine notepad
```

### 7. `pytest` Not Found Under Sudo

**Symptom:** `sudo python3 -m pytest` returns `No module named pytest`.

**Cause:** Pytest is installed in the user's local pip directory (`~/.local/`), which is not in root's `PYTHONPATH`.

**Solution:**
```bash
sudo PYTHONPATH="$HOME/.local/lib/python3.14/site-packages:$PYTHONPATH" \
  python3 -m pytest tests/ -v
```

### 8. Dashboard Shows No Events

**Symptom:** Dashboard starts but shows `total_events: 0` even after running the launcher.

**Cause:** The launcher runs under `sudo` and writes events to `/root/.wineshield/events.log` instead of `~/.wineshield/events.log`.

**Solution:** The launcher now detects `SUDO_USER` and resolves the log path to the original user's home directory. Ensure you're using the latest version of `core/launcher.py`.

### 9. `seccomp strict` Mode Kills Wine

**Symptom:** `wine notepad` exits immediately with code 159 (SIGSYS) in strict mode.

**Cause:** The strict-mode seccomp whitelist only includes syscalls that `/bin/true` and `/bin/ls` need. Wine requires a broader set (threading, shared memory, IPC, etc.).

**Solution:** Use **monitor** or **balanced** mode for Wine. Strict mode is for research/targeted lock-down of specific programs. To run Wine in strict mode, the whitelist in `config/wine_syscall_whitelist.conf` must be expanded.

## Logs and Diagnostics

### Event Log

All security events are recorded to `~/.wineshield/events.log` in JSON format (one event per line):

```json
{"timestamp":"2026-06-09T23:55:07","layer":"network_guard","severity":"info","action":"NetworkGuard initialised","details":{"max_connections":100,"detection_window":10}}
```

### Checking System State

```bash
# Check which layers are available
python3 -c "from core.launcher import load_config; c=load_config(); print(c['enabled_layers'])"

# Check seccomp binary
./core/syscall_monitor --help

# Check log file
tail -f ~/.wineshield/events.log
```

## Getting Help

If you encounter an issue not listed here:

1. Check the event log for error messages
2. Review `docs/ARCHITECTURE.md` for system design
3. Open an issue on the GitHub repository
