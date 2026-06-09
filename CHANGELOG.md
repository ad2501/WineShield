# Changelog

## [1.0.0-alpha] — 2026-06-09

### Added
- Initial project structure with 5-layer security architecture
- Syscall monitor (seccomp-BPF) with 3 modes: monitor, balanced, strict
- AppArmor profile skeletons for Wine, wineserver, and framework
- Network rules configuration (network_rules.json)
- OverlayFS-based filesystem isolation design
- Xephyr-based X11 input isolation design
- Behavior analyzer design with ransomware/keylogger/worm detection
- Flask + WebSocket dashboard design
- Complete AI agent reference manual (docs/AGENTS.md)
- pyproject.toml with proper Python packaging
- Debian package builder (installer/build_deb.sh)

### Fixed
- Corrected README project name from "whinesheald" to "WineShield"
- Unified seccomp implementation (removed duplicate wineshield_seccomp.c)
- Updated .gitignore to exclude .deb and build artefacts
- Removed placeholder files from docs/ — replaced with real documentation

### Changed
- Consolidated 7 placeholder docs into 3 comprehensive documents
- Seccomp approach: blacklist-based BALANCED mode as default (not whitelist)
- Replaced stored .deb binary with build_deb.sh build script
