# Tool Checker Design

**Date**: 2026-02-15
**Status**: Draft

## Overview

Centralize all tool availability checks and cross-platform installation logic into a single `ToolChecker` utility (`wstg_orchestrator/utils/tool_checker.py`). Called at the top of `main.py` before scope builder runs. Replaces all scattered tool checks across modules.

## Architecture

```
main.py starts
    → ToolChecker.run()
        → Detect OS (Windows/macOS/Linux + distro)
        → Windows? → Check WSL2 → Check distros → Install Kali if needed → Re-launch inside WSL
        → Collect all required tools from central TOOL_REGISTRY
        → Check each tool's presence via shutil.which()
        → Display summary table
        → If missing tools → prompt: install all / select / skip
        → Install using tiered strategy
        → Re-check and report final status
        → Return dict of {tool_name: bool} to main.py
    → main.py passes tool_status to Orchestrator
    → Modules read tool_status instead of checking themselves
```

## OS Detection

`PlatformInfo` dataclass:

| Field       | Values                                          |
|-------------|------------------------------------------------|
| os_type     | "windows", "macos", "linux"                    |
| distro      | "kali", "ubuntu", "debian", "fedora", "arch"   |
| pkg_manager | "apt", "brew", "dnf", "pacman"                 |
| is_wsl      | True if /proc/version contains "microsoft"     |

Detection methods:
- `platform.system()` → "Windows", "Darwin", "Linux"
- Linux distro → parse `/etc/os-release` for `ID=` field
- WSL detection → `/proc/version` contains "microsoft" or "WSL"
- Package manager mapping:
  - `apt` → Debian, Ubuntu, Kali, Pop!_OS, Mint
  - `dnf` → Fedora, RHEL 8+, CentOS Stream
  - `pacman` → Arch, Manjaro
  - `brew` → macOS

## Windows / WSL Flow

1. Detect Windows via `platform.system() == "Windows"`
2. Run `wsl --status` to check if WSL2 is installed
3. If no WSL2 → print error with install instructions (`wsl --install` + enable in Windows Features) → `sys.exit(1)`
4. If WSL2 exists → run `wsl -l -q` to list distros
5. If no "kali-linux" distro → prompt user → run `wsl --install -d kali-linux`
6. Re-launch: `os.execvp("wsl", ["wsl", "-d", "kali-linux", "python3", sys.argv[0], *sys.argv[1:]])`

If already running inside WSL (detected via `/proc/version`), skip this flow entirely and proceed as Linux.

## Tool Registry

Central `TOOL_REGISTRY` dict defines every tool with tiered install methods:

```python
TOOL_REGISTRY = {
    "subfinder": {
        "check_cmd": "subfinder",
        "required_by": ["reconnaissance"],
        "install": {
            "go": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "apt": "subfinder",
            "brew": "subfinder",
        }
    },
    "nmap": {
        "check_cmd": "nmap",
        "required_by": ["fingerprinting"],
        "install": {
            "apt": "nmap",
            "dnf": "nmap",
            "pacman": "nmap",
            "brew": "nmap",
        }
    },
    # ... all 19+ tools
}
```

Each entry only lists install methods that actually work for that tool.

### Complete Tool List

**Reconnaissance (11 tools):** subfinder, amass, assetfinder, github-subdomains, gitlab-subdomains, altdns, puredns, whois, gau, httpx, curl, jq

**Fingerprinting (2 tools):** nmap, whatweb

**Configuration Testing (1 tool):** gobuster

**API Testing (1 tool):** kiterunner

**Input Validation (2 tools):** sqlmap, commix

**Wordlists:** seclists

## Install Tier Order

Tried top to bottom per tool:

1. **Language installers** (no sudo): `go install`, `pip install --user` / `pipx`, `cargo install`
2. **System package manager** (sudo): `apt`, `dnf`, `pacman`, `brew` (brew needs no sudo on macOS)
3. **Alternative sources**: GitHub release binaries, `git clone` + build
4. **Skip**: Log warning, mark tool as unavailable, continue

## Install Escalation Chain

```
1. Try language-specific installer (go/pip/cargo) — no sudo
   ↓ language runtime not installed?
2. Offer to install the language runtime itself
   "Go is not installed. Install it? [Y/n]"
   → use system pkg manager to install it
   ↓ user declines?
3. Fall back to system package manager (sudo apt/dnf/pacman/brew)
   ↓ package manager not found?
4. Offer to install the package manager
   "No package manager found. Install <pkg_manager>? [Y/n]"
   ↓ user declines?
5. Friendly exit:
   "Without a package manager or language installer, WSTG-Orc
    has no way to install the tools it needs to operate.
    Please install tools manually and try again. Goodbye!"
   → sys.exit(0)
```

## User Interface

### Summary Table

```
╔══════════════════════════════════════════════════════════════╗
║  WSTG-Orc Tool Checker                                      ║
║  OS: Linux (Kali 2025.1) | Package Manager: apt             ║
╠══════════════════════════════════════════════════════════════╣
║  Tool               Status      Install Via    Used By       ║
║  ─────────────────────────────────────────────────────────── ║
║  subfinder           ✓ Found    —              recon         ║
║  amass               ✓ Found    —              recon         ║
║  nmap                ✗ Missing  apt (sudo)     fingerprint   ║
║  sqlmap              ✗ Missing  pip            input_val     ║
║  gobuster            ✗ Missing  go install     config_test   ║
╠══════════════════════════════════════════════════════════════╣
║  15/18 tools available | 3 missing                           ║
╚══════════════════════════════════════════════════════════════╝
```

### Install Prompt

```
3 tools are missing. What would you like to do?
  [1] Install all missing tools
  [2] Select which to install
  [3] Skip — continue without missing tools
```

Option [2] shows a checklist for selective install.

### Install Progress

```
Installing nmap via apt... ✓ done
Installing sqlmap via pip... ✓ done
Installing gobuster via go... ✗ failed (go not found)
  → Trying apt fallback... ✗ not in repo
  → gobuster unavailable — skipping (affects: configuration_testing)
```

## Integration with main.py

```python
from wstg_orchestrator.utils.tool_checker import ToolChecker

def main():
    checker = ToolChecker()
    tool_status = checker.run()  # {"subfinder": True, "nmap": False, ...}

    scope_builder = ScopeBuilder()
    # ... existing flow
    orchestrator = Orchestrator(config, tool_status)
```

`Orchestrator._check_tools()` is deleted entirely.

## Module Cleanup

Each module receives `tool_status` dict via constructor. Reads `self.tool_status["nmap"]` instead of calling `is_tool_available()`.

Removed from modules:
- `reconnaissance.py`: `TOOL_INSTALL_COMMANDS` dict, `_prompt_install_tool()` method, all inline `is_tool_available()` calls
- `fingerprinting.py`: inline nmap/whatweb availability checks
- `configuration_testing.py`: inline gobuster check
- `input_validation.py`: inline sqlmap/commix checks
- `api_testing.py`: inline kiterunner check

Modules still handle "if tool unavailable, skip this test" logic — they just read from the pre-computed dict.

`CommandRunner` stays as-is. Its `is_tool_available()` remains as a low-level utility but modules stop using it for gating.

## Error Handling

- **Install fails mid-batch**: Each tool is independent. Failures don't stop other installs. Final summary shows results.
- **No internet**: Detect network errors, report to user, mark tool unavailable, continue.
- **Sudo denied**: Catch error, inform user, try next install tier.
- **Homebrew missing on macOS**: Offer to install before proceeding with tool installs.
- **Unknown distro**: Fall back to language-specific installers only. If none available, follow escalation chain.

## Decisions Made

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Permissions | Try non-root first, escalate to sudo | Minimizes privilege requests |
| UX style | Summary table + batch prompt | Full visibility without tedium |
| Version checks | Presence only | Simpler, fewer edge cases |
| WSL flow | Auto re-launch inside WSL | Seamless UX for Windows users |
| Install priority | Language installers first | No sudo needed, always preferred |
