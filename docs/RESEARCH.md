# WineShield — Research Notes

> **Purpose:** Academic context, contribution statements, methodology, references, and open research questions.
> **Target audience:** Researchers, thesis advisors, and AI agents writing the paper.

---

## 1. Research Identity

| Field | Detail |
|-------|--------|
| **Project type** | Undergraduate graduation thesis |
| **Student** | Ahmed (Computer Systems Engineering) |
| **Target venue** | IEEE Security & Privacy or Elsevier *Computers & Security* |
| **Topic** | Multi-layer security framework for Wine-based Windows application execution on Linux |
| **Key innovation** | First systematically designed, multi-layer sandboxing solution tailored specifically for Wine's attack surface |

---

## 2. Claimed Contributions

| # | Contribution | Evidence | Novelty |
|---|-------------|----------|---------|
| 1 | **Wine-specific syscall whitelist** — the minimum set of syscalls needed for Windows applications to function under Wine | `config/wine_syscall_whitelist.conf` + profiling methodology | First systematic Wine syscall profiling published in academic literature |
| 2 | **Wine-optimized AppArmor profiles** that confine Wine without breaking application compatibility | `config/apparmor/wineshield.wine`, `.wineserver`, `.framework` | First published AppArmor profiles designed specifically for Wine's complex runtime behaviour |
| 3 | **Multi-layer security framework architecture** that combines seccomp, namespaces, OverlayFS, Xephyr, and behavior analysis | This document + full implementation | Existing tools provide isolated layers; WineShield integrates them into a unified, toggleable framework |
| 4 | **Empirical overhead evaluation** of each layer's performance impact on real Windows applications | `benchmarks/` | Quantitative data for researchers choosing security vs performance tradeoffs |
| 5 | **Wine-specific threat model** that maps Wine's unique attack surface to concrete mitigation strategies | Section 4 of this document | Reference model for future Wine security research |

---

## 3. Related Work & Differentiation

### Existing Tools

| Tool | Approach | Limitations vs WineShield |
|------|----------|--------------------------|
| **[Firejail](https://github.com/netblue30/firejail)** | SUID sandbox using namespaces + seccomp + capabilities | General-purpose; no Wine-specific profiling, no behavior analysis, no dashboard, no Xephyr isolation |
| **[sandwine](https://github.com/hartwork/sandwine)** | Python + bubblewrap for Wine | No behavior analysis, no dashboard, uses host X11 (not Xephyr), no AppArmor profiles |
| **[Bottles](https://usebottles.com/)** | Flatpak-based Wine prefix manager | Primarily a compatibility tool, not a security framework; isolation is via Flatpak's bubblewrap |
| **[Firejail Wine profile](https://man.archlinux.org/man/firejail.1)** | Pre-built firejail profile for Wine | One-size-fits-all, no support for mode switching, no unified monitoring |
| **Flatpak** | bubblewrap-based application sandbox | No Wine-specific threat model, no behavior analysis |
| **Docker-based Wine** | Docker container for Wine | Nested containerization conflicts with kernel features; defeats the purpose (see Architecture notes) |

### Academic Gap

A systematic literature review (conducted during the design phase) found **no peer-reviewed publications** that:

1. Profile the syscall footprint of common Windows applications running under Wine
2. Design AppArmor profiles specifically for Wine's dynamic runtime behaviour
3. Evaluate the effectiveness of combining seccomp + OverlayFS + namespaces + Xephyr for Wine security
4. Present a layered security framework for Wine with an integrated real-time dashboard

This confirms the novelty of the proposed contributions.

---

## 4. Wine-Specific Threat Model

### 4.1 Threat Vectors

```
Windows App running in Wine
│
├── Filesystem
│   ├── Read ~/.ssh/id_rsa, ~/.gnupg/*, browser passwords
│   ├── Encrypt ~/Documents/* (ransomware)
│   └── Modify ~/.bashrc, ~/.profile (persistence)
│
├── Network
│   ├── Open raw sockets (port scanning host network)
│   ├── Connect to C2 server (botnet)
│   └── DNS tunnelling (data exfiltration)
│
├── Processes
│   ├── ptrace into host processes (credential theft)
│   ├── Inject into browser process
│   └── Spawn shell → reverse shell
│
├── Kernel
│   ├── Load kernel module (rootkit)
│   ├── Modify sysctl (disable ASLR, etc.)
│   └── kexec (reboot into malicious kernel)
│
├── Desktop (X11)
│   ├── XGrabKeyboard (global keylogger)
│   ├── XGetImage (screen capture)
│   └── XTest (inject keystrokes/clicks)
│
└── Shared resources
    ├── DBus → system manipulation
    └── Clipboard → credential theft
```

### 4.2 Mitigation Mapping

| Threat Vector | Primary Layer | Secondary Layer |
|---------------|---------------|-----------------|
| File access | Layer 2 (OverlayFS) | Layer 6 (AppArmor) |
| Network access | Layer 3 (netns) | Layer 4 (Behavior) |
| Process injection | Layer 1 (seccomp) | Layer 6 (AppArmor) |
| Kernel exploitation | Layer 1 (seccomp) | — |
| X11 keylogging | Layer 5 (Xephyr) | Layer 4 (Behavior) |
| Ransomware | Layer 2 (OverlayFS) | Layer 4 (Behavior) |

---

## 5. Syscall Whitelist Research Methodology

The STRICT mode whitelist in `syscall_monitor.c` is a research output. The methodology to complete it:

### Phase 1 — Monitor Mode Profiling (straces)

For each target application:
1. Install app in a fresh Wine prefix
2. Run with `strace -qcf -o /tmp/syscalls.csv wine app.exe`
3. Exercise all major features (open/save files, network calls, UI interaction)
4. Close the application
5. Extract unique syscalls: `cut -d' ' -f2 /tmp/syscalls.csv | sort -u`

### Phase 2 — Aggregation

| Application | Category | Syscall Count |
|-------------|----------|---------------|
| notepad.exe | Built-in (test) | TBD |
| winver.exe | Built-in (test) | TBD |
| 7-Zip | Utility | TBD |
| Notepad++ | Editor | TBD |
| Firefox / Chrome | Browser | TBD |
| VLC Media Player | Media | TBD |
| SumatraPDF | Reader | TBD |

Minimum target: profile 15-20 applications across 5 categories (utilities, browsers, media, office, games).

### Phase 3 — Whitelist Construction

```
WINE_WHITELIST = (⋂ apps_base_syscalls) ∪ (⋃ app_specific_syscalls)
```

Where `apps_base_syscalls` = syscalls used by EVERY profiled app, and `app_specific_syscalls` = syscalls needed by specific apps but not all.

The strict mode whitelist ships with the base set. Users can generate app-specific whitelists using `scripts/generate_whitelist.py`.

---

## 6. AppArmor Profile Design Notes

Writing AppArmor profiles for Wine is technically challenging because:

1. **Dynamic library loading** — Wine loads Windows DLLs at runtime from paths that depend on the application
2. **Varying WINEPREFIX layouts** — Different apps create different filesystem structures
3. **Wineserver behaviour** — The background server process needs different rules from the main Wine process
4. **Registry access** — Wine stores registry in binary files under `~/.wine/`

**Our approach:** Start with a permissive profile that covers normal operation, then iteratively tighten by monitoring denials in complain mode:

```bash
# Set profile to complain mode
sudo aa-complain /etc/apparmor.d/wineshield.wine

# Run Wine application, collect denials
sudo tail -f /var/log/syslog | grep wineshield-wine

# Adjust profile, repeat
```

**Three profiles:**

| Profile | Target | Purpose |
|---------|--------|---------|
| `wineshield.wine` | `/usr/bin/wine{64,}{,-preloader}` | Main Wine process — most restrictive |
| `wineshield.wineserver` | `/usr/bin/wineserver` | Wine server — broader IPC access |
| `wineshield.framework` | Python3 | WineShield itself — needs kernel access |

---

## 7. Performance Evaluation Plan

Benchmarks will measure overhead per layer and in combination:

| Test | What it measures | Tool |
|------|-----------------|------|
| Syscall latency | Time per syscall with/without seccomp | `latency_benchmark.py` |
| File I/O throughput | Read/write MB/s with/without OverlayFS | `cpu_benchmark.py` |
| Network throughput | Connection rate with/without netns | `cpu_benchmark.py` |
| Memory overhead | RSS increase per layer | `memory_benchmark.py` |
| Application startup | Time to open notepad.exe with all layers | Full integration test |
| CPU overhead | % CPU consumed by monitoring layers (behavior, network) | `cpu_benchmark.py` |

**Target metrics:**
- seccomp overhead: <5% on CPU-bound workloads
- OverlayFS overhead: <3% on file I/O
- Network isolation: <2% on network throughput
- Behavior analyzer: <1% CPU (polling-based)
- Xephyr: 50-100MB memory, <5% GPU impact

---

## 8. Open Research Questions

1. **Whitelist portability:** How much does the syscall whitelist vary between kernel versions (5.15 → 6.2 → 6.8)? Can we define a portable minimal set?
2. **AppArmor vs seccomp overlap:** How much of the attack surface covered by seccomp is ALSO covered by AppArmor? Can AppArmor replace seccomp for some attack vectors?
3. **Behavior analyzer accuracy:** What is the false positive rate for each detection pattern? How does it compare to established tools?
4. **Xephyr alternative:** Can Wayland's native security model replace Xephyr? How would the framework adapt?
5. **Unprivileged operation:** How much isolation can WineShield provide without root/setuid? Can we use user namespaces to mount OverlayFS without CAP_SYS_ADMIN?
6. **ML-based behavior analysis:** Would a supervised ML model trained on Wine malware traces outperform the rule-based analyzer?
7. **Integration with anti-cheat:** Can WineShield's AppArmor profiles be adapted for gaming anti-cheat compatibility?

---

## 9. References

### Linux Security

1. Corbet, J. "Seccomp and friends." LWN.net, 2015.
2. Edge, J. "Yet another new security feature: no_new_privs." LWN.net, 2012.
3. `seccomp(2)` — Linux Programmer's Manual
4. `namespaces(7)` — Linux Programmer's Manual
5. AppArmor documentation — Ubuntu Community Help Wiki

### Wine

6. WineHQ. "Wine Developer's Guide." https://wiki.winehq.org/
7. The Wine Project. https://www.winehq.org/
8. Amstadt, B. and Julliard, A. "Wine Architecture Overview." WineConf, 2004.

### Related Security Research

9. Firejail project. https://github.com/netblue30/firejail
10. Container isolation: what we wish we knew. Edera Engineering Blog, 2024.
11. "Server-side sandboxing: Containers and seccomp." Figma Engineering Blog, 2019.
12. Sandwine: run Windows apps with Wine and Bubblewrap. https://github.com/hartwork/sandwine

### Sandboxing Patterns

13. `bubblewrap` — Low-level unprivileged sandboxing. https://github.com/containers/bubblewrap
14. Project Zero. "A deep dive into Linux namespaces." Google Project Zero Blog.
15. Linux kernel selftests for seccomp. `tools/testing/selftests/seccomp/` in kernel tree.

---

> **Note to AI agents:** This research document is a living record. Update it as findings are made, especially:
> - Whistlist profiling results (add counts per application)
> - Benchmark results (add actual numbers)
> - AppArmor refinement notes (add denial patterns)
> - Literature review additions (add new relevant papers)
