# WineShield Architecture

> **Target audience:** Developers, researchers, and AI agents.
> **Purpose:** Complete architectural reference — threat model, layer design, integration points, and technology decisions.

---

## 1. High-Level Architecture

```
┌──────────────────────────────────────────────────────────┐
│                     User Desktop (X11/Wayland)            │
│  ┌────────────────────────────────────────────────────┐  │
│  │  WineShield Dashboard (localhost:5000)             │  │
│  │  ┌──────────┐  ┌───────────┐  ┌────────────────┐  │  │
│  │  │ Stats    │  │ Layer     │  │ Event Feed     │  │  │
│  │  │ Cards    │  │ Toggles   │  │ (WebSocket)    │  │  │
│  │  └──────────┘  └───────────┘  └────────────────┘  │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────────┬───────────────────────────────┘
                           │ reads events from
                           ▼
┌──────────────────────────────────────────────────────────┐
│  WineShield Framework                                    │
│                                                          │
│  ┌──────────────┐    ┌────────────────────────────────┐  │
│  │  launcher.py │───▶│  sandbox_engine.py             │  │
│  │  (CLI entry) │    │  - PID namespace               │  │
│  └──────────────┘    │  - Mount namespace              │  │
│          │           │  - Network namespace            │  │
│          │           │  - UTS namespace                │  │
│          │           │  - IPC namespace                │  │
│          │           └──────────┬─────────────────────┘  │
│          │                      │                        │
│  ┌───────┴──────────────────────┴──────────────────────┐ │
│  │                  Security Layers                     │ │
│  │  ┌────────────┐  ┌────────────┐  ┌───────────────┐ │ │
│  │  │ syscall_   │  │  fs_guard  │  │ network_guard │ │ │
│  │  │ monitor.c  │  │  (Overlay) │  │  (netns)      │ │ │
│  │  │ (seccomp)  │  │            │  │               │ │ │
│  │  └────────────┘  └────────────┘  └───────────────┘ │ │
│  │  ┌────────────┐  ┌────────────┐  ┌───────────────┐ │ │
│  │  │behavior_   │  │xephyr_guard│  │  apparmor_    │ │ │
│  │  │analyzer.py │  │  (X11)     │  │  manager.py   │ │ │
│  │  └────────────┘  └────────────┘  └───────────────┘ │ │
│  └─────────────────────────────────────────────────────┘ │
│                                                          │
│  ALL layers write → unified JSON events → wineshield.log │
└──────────────────────────────────────────────────────────┘
                           │
                           ▼
                    ┌──────────────┐
                    │    Wine +    │
                    │  Windows App │  ← sandboxed target
                    └──────────────┘
```

---

## 2. Threat Model

### 2.1 What WineShield Protects Against

| Threat | Severity | Layers Involved | Protection |
|--------|----------|----------------|------------|
| Ransomware (file encryption) | 🔴 Critical | 1, 2, 4, 6 | ~95% |
| Data exfiltration via network | 🔴 Critical | 1, 3, 4, 6 | ~95% |
| Privilege escalation (kernel) | 🔴 Critical | 1, 6 | ~90% |
| Process injection / ptrace | 🔴 Critical | 1 | ~100% |
| Kernel module loading | 🔴 Critical | 1 | ~100% |
| SSH key / credential theft | 🟠 High | 2, 6 | ~90% |
| Keylogging (X11 global) | 🟠 High | 5 | ~100% (with Xephyr) |
| Keylogging (X11 inside Wine) | 🟡 Medium | 4 | ~70% |
| Network C2 beaconing | 🟠 High | 3, 4 | ~85% |
| Screen capture (X11) | 🟡 Medium | 5 | ~100% (with Xephyr) |

### 2.2 Out of Scope

- Zero-day kernel exploits using only whitelisted syscalls
- Side-channel attacks (timing, cache, power)
- Physical attacks (cold boot, hardware keyloggers)
- Social engineering of the user
- Vulnerabilities in Wine itself (WineShield wraps Wine, it doesn't patch it)

### 2.3 Attack Surface of Wine (Why WineShield Exists)

Wine translates Windows API calls into Linux syscalls. This means a Windows application running through Wine has, by default:

- **Full filesystem access** — the user's home directory is visible
- **Full process visibility** — can ptrace any process
- **Full network access** — raw sockets, any port
- **Full X11 access** — keylogging, screen capture
- **Full kernel access** — module loading, sysctl

WineShield closes each of these doors independently.

---

## 3. The 5+1 Security Layers

### 3.1 Layer 1 — Syscall Filter (`core/syscall_monitor.c`)

| Property | Value |
|----------|-------|
| Language | C (raw BPF) |
| Mechanism | `seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog)` |
| Execution | Fork-exec'd from Python, filter applied before exec'ing Wine |
| Privilege | `PR_SET_NO_NEW_PRIVS` (no capability needed) |

**Three modes:**

| Mode | Default Action | Blocked | Use Case |
|------|---------------|---------|----------|
| `monitor` | `SECCOMP_RET_LOG` | Nothing | Profiling, building whitelist |
| `balanced` | `SECCOMP_RET_ALLOW` | ~15 dangerous syscalls | Daily use (default) |
| `strict` | `SECCOMP_RET_KILL_PROCESS` | Everything except whitelist | Research, high-security |

**Balanced mode blocklist** (the ~15 syscalls that make Linux attacks possible):

```
ptrace, init_module, finit_module, delete_module,
kexec_load, kexec_file_load, reboot, bpf,
perf_event_open, process_vm_writev, swapon, swapoff,
syslog, setns, mount, umount2, pivot_root, chroot
```

These are syscalls that no Windows application ever needs via Wine.

**Important:** The whitelist in STRICT mode is NOT complete. It is a research output of this project. See `docs/RESEARCH.md` for the methodology.

### 3.2 Layer 2 — Filesystem Guard (`core/fs_guard.py`)

| Property | Value |
|----------|-------|
| Language | Python |
| Mechanism | OverlayFS mount |
| Privilege | Requires `CAP_SYS_ADMIN` (falls back to tmpfs bind-mount) |

**Sandbox directory structure:**
```
~/.wineshield/sandbox/<sandbox_id>/
├── lower/       ← read-only base (or empty tmpfs)
├── upper/       ← writable layer (all modifications captured here)
├── work/        ← OverlayFS internal metadata
└── merged/      ← mounted overlay (Wine sees this as C:\ drive)
```

**Flow:**
1. Create sandbox directory structure
2. Mount OverlayFS: `mount -t overlay overlay -o lowerdir=...,upperdir=...,workdir=... merged`
3. Set `WINEPREFIX` to inside `merged/`
4. Bind-mount sandbox over `~/.wine` to prevent escape
5. On exit: unmount, delete upper/work, keep or discard base

**Fallback:** If OverlayFS mount fails (EPERM), use a bind-mounted tmpfs over `~/.wine`. Weaker isolation (tmpfs is per-session only) but works without root.

### 3.3 Layer 3 — Network Guard (`core/network_guard.py`)

| Property | Value |
|----------|-------|
| Language | Python |
| Mechanism | Network namespace + /proc/net monitoring |
| Privilege | `CAP_NET_ADMIN` for namespace isolation |

**Monitor mode:** Reads `/proc/<pid>/net/{tcp,tcp6,udp}` every N seconds, logs connections, checks against `config/network_rules.json` blocklist.

**Strict mode:** Creates isolated network namespace. Only loopback available. Optional veth pair for controlled network access (DNS only, specific hosts, etc.).

### 3.4 Layer 4 — Behavior Analyzer (`core/behavior_analyzer.py`)

| Property | Value |
|----------|-------|
| Language | Python |
| Mechanism | Sliding window pattern detection |

**Detection patterns:**

| Threat | Pattern | Threshold |
|--------|---------|-----------|
| Ransomware | Mass high-entropy file writes | >50 files / 10 seconds |
| Keylogger | Repeated keyboard state queries | >100 calls / minute |
| Worm | Rapid unique outbound connections | >20 IPs / minute |
| Data exfiltration | Read sensitive files then large outbound | >10MB outbound / 60s |
| Privilege escalation | Child process spawning unexpected shells | Any /bin/sh from Wine |

**Response actions:** `log` | `warn` | `suspend` | `kill` — configurable per pattern.

### 3.5 Layer 5 — Xephyr Guard (`core/xephyr_guard.py`)

| Property | Value |
|----------|-------|
| Language | Python |
| Mechanism | Xephyr nested X server |
| Privilege | None (user-level) |

**Why it's needed:** X11 has no application-level isolation. Any application can call `XGrabKeyboard` and capture every keystroke on the system.

**How it works:**
1. Launch Xephyr on a free display (`:1`, `:2`, etc.)
2. Set `DISPLAY=:<n>` before launching Wine
3. All Wine windows appear inside the Xephyr window
4. A keylogger in Wine can only see keystrokes within Xephyr — the host desktop is invisible

**Fallback:** If Xephyr is not installed, log a warning and run on the host display. The layer fails open (usable but less secure) rather than blocking the application.

### 3.6 Layer 6 — AppArmor (`core/apparmor_manager.py`)

| Property | Value |
|----------|-------|
| Language | Python (subprocess to `apparmor_parser`) |
| Profiles | 3: wine, wineserver, framework |
| Privilege | Requires root |

**Profiles:** See `config/apparmor/` for the full profile definitions.

**Relationship with seccomp:** AppArmor controls *what files and resources* can be accessed by name. Seccomp controls *what kernel operations* can be performed. They are complementary — not redundant.

---

## 4. Namespace Design

`sandbox_engine.py` creates isolated Linux namespaces in this order:

```
1. UTS namespace     — isolate hostname
2. IPC namespace     — isolate SysV IPC
3. PID namespace     — isolate process tree
4. Mount namespace   — isolate filesystem mounts
5. Network namespace — isolate network stack
```

Each is created via `os.unshare(flags)`. On Ubuntu 22.04, unprivileged user namespaces are enabled by default, so `CLONE_NEWNS`, `CLONE_NEWPID`, `CLONE_NEWNET` work without root.

---

## 5. Event System

Every security layer writes events to `~/.wineshield/wineshield.log` in NDJSON format (one JSON object per line):

```json
{
  "id": "evt_001a2b3c",
  "timestamp": "2026-06-09T03:54:01.123456+03:00",
  "date": "2026-06-09",
  "severity": "blocked",
  "layer": "seccomp",
  "action": "Syscall denied",
  "details": "Process 'wine64' attempted syscall ptrace (101)",
  "pid": 12345,
  "process": "wine64",
  "sandbox_id": "sb_abc123"
}
```

The dashboard tails this file and pushes new events to the browser via WebSocket. Events are also stored in SQLite for historical queries.

**Severity levels:** `info` (informational), `allowed` (permitted action), `warning` (suspicious but permitted), `blocked` (action denied), `error` (internal failure).

---

## 6. Configuration

WineShield uses a single central configuration file (`wineshield.conf`), loaded by `core/config.py` (to be implemented). The search order is:

1. `$HOME/.wineshield/wineshield.conf` (user override)
2. `/etc/wineshield/wineshield.conf` (system config)
3. `config/wineshield.conf` (repo default)

No values are hardcoded. The config controls:
- Which layers are enabled
- Mode settings per layer
- Thresholds for the behavior analyzer
- Dashboard port and host
- Log level and file path

See `docs/AGENTS.md` Section 5 for the full config schema.

---

## 7. Technology Decisions

| Decision | Choice | Why Not the Alternative |
|----------|--------|------------------------|
| Syscall filter language | C (raw BPF) | Python can't inject seccomp filters before exec; raw BPF avoids libseccomp dependency |
| Filesystem isolation | OverlayFS | More performant than bind-mounts; cleaner cleanup than unionfs |
| Network isolation | Linux netns | Simpler than iptables/nftables; kernel-native |
| Dashboard language | Flask + SocketIO | Lighter than React; no build toolchain; WebSocket-native |
| X11 isolation | Xephyr | Lighter than full Xvfb; user sees what's happening |
| MAC system | AppArmor | Ubuntu default; SELinux can't coexist |
| Containerization | None | Docker conflicts with the namespaces we depend on |
| Package format | .deb | Ubuntu target; RPM is unnecessary overhead |

---

## 8. File Structure

```
WineShield/
├── core/                     # Security engine
│   ├── launcher.py           # CLI entry point
│   ├── sandbox_engine.py     # Namespace creation
│   ├── syscall_monitor.c     # seccomp-BPF (3 modes)
│   ├── fs_guard.py           # OverlayFS isolation
│   ├── network_guard.py      # Network isolation + monitoring
│   ├── behavior_analyzer.py  # Pattern detection
│   ├── xephyr_guard.py       # X11 isolation
│   ├── apparmor_manager.py   # AppArmor control
│   └── Makefile
├── dashboard/                # Web UI
├── config/                   # All configuration
│   └── apparmor/             # AppArmor profiles
├── tests/                    # Unit + integration tests
├── scripts/                  # Helper utilities
├── benchmarks/               # Performance measurement
├── installer/                # Installation system
│   └── systemd/              # Service files
└── docs/                     # Documentation
    ├── AGENTS.md             # AI agent reference
    ├── ARCHITECTURE.md       # This file
    └── RESEARCH.md           # Research notes
```

---

## 9. Building & Running

```bash
# Build C module
make -C core clean all

# Install Python deps
pip install -e .

# Run launcher (only syscall monitor active)
python3 core/launcher.py --wine /path/to/app.exe

# Run dashboard
python3 -m flask --app dashboard/app.py run --port 5000

# Build .deb package (output: installer/wineshield_*.deb)
bash installer/build_deb.sh
```

For testing, see `docs/AGENTS.md` Section 9.

---

## 10. Key Design Principles

1. **Defense in depth.** No single layer is trusted. Multiple independent layers each block different attack vectors.
2. **Fail open for usability.** If a layer can't activate (e.g., Xephyr not available), log a warning and continue. The user may have weaker protection but can still use their application.
3. **No modification to Wine.** WineShield is a wrapper, not a fork. All mechanisms are external.
4. **Toggleable independence.** Any layer can be enabled/disabled without affecting others.
5. **Observability is security.** Every decision is logged in a machine-parseable format. The dashboard makes security visible.
6. **Defaults to practical security.** BALANCED mode (blacklist, not whitelist) is the default. STRICT whitelist mode is for research only.
