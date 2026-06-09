# WineShield Testing Guide

## Test Suite Overview

The project has **124 tests** across 4 test files:

| File | Tests | Scope |
|------|-------|-------|
| `tests/test_behavior_analyzer.py` | 52 | Behavior analysis rules, scoring, thresholds |
| `tests/test_launcher.py` | 32 | CLI parsing, layer initialization, session lifecycle |
| `tests/test_sandbox.py` | 24 | Namespace creation, OverlayFS, context manager |
| `tests/test_seccomp_unit.py` | 16 | C binary invocation, seccomp modes, syscall blocking |

Additional verification scripts:

| File | Purpose |
|------|---------|
| `tests/test_simulations.py` | Malware simulation scenarios (ransomware, keylogger, backdoor) |
| `tests/test_wine.sh` | Shell script for running Wine under seccomp |

## Running Tests

### Quick check (all tests):

```bash
cd /path/to/WineShield
python3 -m pytest tests/ -v
```

### Unit tests only (no root required):

```bash
python3 -m pytest tests/test_behavior_analyzer.py -v
python3 -m pytest tests/test_seccomp_unit.py -v
```

### Root-required tests:

Three sandbox tests require namespace creation and must run as root:

```bash
sudo python3 -m pytest tests/test_sandbox.py -v
```

When not running as root, these tests automatically skip with a message:
```
SKIPPED: requires root privileges — run with 'sudo python3 -m pytest ...'
```

### Full test suite as root:

```bash
sudo PYTHONPATH="$HOME/.local/lib/python3.14/site-packages:$PYTHONPATH" \
  python3 -m pytest tests/ -v
```

## Malware Simulations

The simulation scripts test the detection capabilities of each layer:

```bash
python3 -m tests.test_simulations
```

This runs three scenarios:
1. **Ransomware** — Creates 120 files rapidly (triggers behavior_analyzer threshold)
2. **Keylogger** — Attempts to read `/dev/input` (blocked by syscall_filter or filesystem guard)
3. **Network Backdoor** — Connects to 8 external hosts (tracked by network_guard)

**Note:** On WSL, the namespace sandbox cannot be created (`os.unshare()` returns `EINVAL`), so detection threads do not see simulation traffic. These simulations require a real Linux system with unprivileged user namespaces enabled.

## Testing WineShield End-to-End

### 1. Verify Seccomp Isolation

```bash
sudo ./core/syscall_monitor --mode balanced --user $(whoami) -- /bin/true
# Exit code 0 = success

sudo ./core/syscall_monitor --mode strict --user $(whoami) -- /bin/ls /
# Exit code 0 = success (ls allowed in whitelist)
```

### 2. Verify GUI Application

```bash
# With WSLg (native display):
export DISPLAY=$(echo $DISPLAY)
timeout 30 sudo ./core/syscall_monitor --mode monitor --user $(whoami) -- wine notepad

# With Xvfb:
Xvfb :99 -screen 0 1024x768x24 &
export DISPLAY=:99
timeout 30 sudo WINEPREFIX=$HOME/.wine DISPLAY=:99 \
  ./core/syscall_monitor --mode monitor --user $(whoami) -- wine notepad
```

### 3. Run the Full Security Stack

```bash
# Terminal 1: Start the dashboard
python3 dashboard/app.py

# Terminal 2: Launch Wine under WineShield
sudo python3 -m core.launcher --mode balanced --app "wine"

# Check events in the dashboard at http://127.0.0.1:5000
# Or directly from the log:
cat ~/.wineshield/events.log
```

## Expected Test Outcomes

| Test | WSL2 | Native Linux |
|------|------|-------------|
| seccomp filter (all 3 modes) | ✅ Pass | ✅ Pass |
| Seccomp privilege drop (--user) | ✅ Pass | ✅ Pass |
| Behavior analysis rules | ✅ Pass | ✅ Pass |
| Dashboard + WebSocket | ✅ Pass | ✅ Pass |
| Sandbox namespace (as user) | ⚠️ 3 skip | ✅ Pass |
| Sandbox namespace (as root) | ✅ Pass | ✅ Pass |
| Full stack end-to-end | ⚠️ WSL limitations | ✅ Pass |
| AppArmor profiles | ❌ Kernel disabled | ✅ Active |
