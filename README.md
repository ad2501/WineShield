# WineShield 🛡️

> Multi-layer security framework for running Windows applications on Linux via Wine — without exposing the host system.

![Platform](https://img.shields.io/badge/platform-Ubuntu%2022.04%20LTS-blue)
![Language](https://img.shields.io/badge/language-Python%203.10%2B%20|%20C%20|%20Bash-blue)
![Status](https://img.shields.io/badge/status-alpha-orange)
![License](https://img.shields.io/badge/license-MIT-green)

---

## What is WineShield?

WineShield wraps Wine — the Windows compatibility layer for Linux — with **5 independent security layers** that protect against malware, exploits, and data theft. Each layer targets a specific attack vector:

| # | Layer | Threat |
|---|-------|--------|
| 1 | **Syscall Filter** (seccomp-BPF) | Kernel-level exploits, privilege escalation |
| 2 | **Filesystem Guard** (OverlayFS) | File theft, ransomware, data access |
| 3 | **Network Guard** (netns) | Data exfiltration, C2 communication |
| 4 | **Behavior Analyzer** | Ransomware, keyloggers, worms |
| 5 | **Xephyr Guard** (X11 isolation) | Keystroke logging, screen capture |
| 6 | **AppArmor** (optional) | Mandatory Access Control at file level |

All layers are **individually toggleable** via the dashboard or CLI.

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/ad2501/WineShield.git
cd WineShield

# 2. Build the C module
make -C core clean all

# 3. Install dependencies
pip install -e .    # uses pyproject.toml

# 4. Run (requires Wine installed)
python3 core/launcher.py --wine notepad.exe
```

For full installation: see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Project Status

| Component | Status |
|-----------|--------|
| Syscall monitor (`core/syscall_monitor.c`) | 🟡 Partial — BPF filter working, whitelist needs expansion |
| All Python guards | 🔴 Stub — structure ready, implementation pending |
| Dashboard (Flask + WebSocket) | 🔴 Stub — templates and backend pending |
| Tests | 🔴 Stub — test framework ready, cases pending |
| Documentation | 🟢 Active — see [docs/](docs/) |

---

## For AI Agents & Contributors

This project is designed to be developed with AI assistance. If you are an AI agent:

1. **Read [docs/AGENTS.md](docs/AGENTS.md) first** — it contains everything you need to contribute.
2. Then read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design.
3. Check [docs/RESEARCH.md](docs/RESEARCH.md) for the academic context.

These docs explain the file structure, coding conventions, event format, pitfalls, and layer-by-layer implementation details.

---

## License

MIT — see LICENSE file (coming soon).

---

*Built as a graduation research project for IEEE/Elsevier publication.*
