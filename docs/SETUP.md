# WineShield Setup Guide

## System Requirements

- **OS:** Ubuntu 22.04 LTS or later (also tested on WSL2)
- **Kernel:** Linux 5.15+ (for seccomp-BPF, namespaces, OverlayFS)
- **Python:** 3.10+
- **Wine:** 8.0+ (install via `sudo apt install wine`)
- **C compiler:** gcc + `libseccomp-dev`

## Quick Install

```bash
# Clone or copy the project
cd WineShield

# Build the C seccomp module
make -C core all

# Install Python dependencies
pip install flask flask-socketio gevent gevent-websocket

# Run the setup script (Ubuntu 22.04)
sudo bash install.sh
```

## Manual Setup

### 1. Build the Seccomp Filter

```bash
cd core
make clean all
```

This compiles `syscall_monitor.c` into a binary with three operation modes:
- `monitor` — log-only, allows everything
- `balanced` — blocks dangerous syscalls
- `strict` — whitelist-only

### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

If `requirements.txt` is not present:

```bash
pip install flask flask-socketio gevent gevent-websocket pytest
```

### 3. Configure

Edit `config/default_policy.json` to set your preferences:

- `log_file` — path to the events log (default: `~/.wineshield/events.log`)
- `seccomp_mode` — one of `monitor`, `balanced`, `strict`
- `layers` — list of security layers to enable

### 4. Start the Dashboard

```bash
python3 dashboard/app.py
```

Open http://127.0.0.1:5000 in your browser.

## Running Wine Under WineShield

### Basic usage:

```bash
# Monitor mode (record all, block nothing)
sudo python3 -m core.launcher --mode monitor --app "wine"

# Balanced mode (block dangerous operations)
sudo python3 -m core.launcher --mode balanced --app "wine"

# With specific layers
sudo python3 -m core.launcher --mode balanced --app "wine" --layer syscall,network,behavior
```

### Direct seccomp usage (without the full stack):

```bash
# Run a command under seccomp monitoring as a normal user
sudo ./core/syscall_monitor --mode balanced --user $(whoami) -- /path/to/program

# With arguments
sudo ./core/syscall_monitor --mode monitor --user $(whoami) -- wine notepad.exe
```

## WSL Notes

On WSL2, some features are unavailable:
- **PID/Mount namespaces** return `ENOMEM` — sandbox uses reduced isolation mode
- **AppArmor** is disabled in the WSL kernel — profiles are configured but inactive
- **GUI apps** require either WSLg (native display on Windows 11) or Xvfb

See [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) for details.
