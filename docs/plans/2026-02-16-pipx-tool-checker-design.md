# Design: Replace pip with pipx in ToolChecker + Fix kiterunner

**Date:** 2026-02-16
**Status:** Approved

## Problem

1. **pip3 install fails on Kali** (externally-managed-environment / PEP 668). `pip3 install --user py-altdns` errors with "externally managed environment" on modern Kali.
2. **kiterunner go install path is wrong.** `github.com/assetnote/kiterunner/cmd/kr@latest` doesn't exist — the correct path is `cmd/kiterunner`.
3. **User directive:** Never use pip/pip3 again; always use pipx. Prefer go over pipx.

## Changes

### 1. TOOL_REGISTRY: Rename `"pip"` keys to `"pipx"`

**Files:** `wstg_orchestrator/utils/tool_checker.py` (lines 111-218)

| Tool | Old key | New key | Package |
|------|---------|---------|---------|
| altdns | `"pip": "py-altdns"` | `"pipx": "py-altdns"` | py-altdns |
| sqlmap | `"pip": "sqlmap"` | `"pipx": "sqlmap"` | sqlmap |
| commix | `"pip": "commix"` | `"pipx": "commix"` | commix |

### 2. Fix kiterunner entry

**Before:**
```python
"kiterunner": {
    "check_cmd": "kr",
    "install": {"go": "go install -v github.com/assetnote/kiterunner/cmd/kr@latest"},
}
```

**After:**
```python
"kiterunner": {
    "check_cmd": "kiterunner",
    "install": {"go": "go install -v github.com/assetnote/kiterunner/cmd/kiterunner@latest"},
}
```

The go install produces a binary named `kiterunner` (not `kr`), so `check_cmd` must match.

### 3. Update `_INSTALL_TIER_ORDER` and constants

**Before:**
```python
_INSTALL_TIER_ORDER = ["go", "pip", "cargo", "apt", "dnf", "pacman", "brew"]
_LANGUAGE_INSTALLERS = {"go", "pip", "cargo"}
```

**After:**
```python
_INSTALL_TIER_ORDER = ["go", "pipx", "cargo", "apt", "dnf", "pacman", "brew"]
_LANGUAGE_INSTALLERS = {"go", "pipx", "cargo"}
```

### 4. Update `get_install_command` pip logic → pipx

**Before (lines 301-316):**
```python
if tier == "pip":
    runtime_available = shutil.which("pip3") or shutil.which("pip")
    ...
    cmd = f"pip3 install --user {package}"
```

**After:**
```python
if tier == "pipx":
    runtime_available = shutil.which("pipx")
    if not runtime_available:
        # Auto-install pipx via apt (no user prompt)
        try:
            subprocess.run(
                ["sudo", "apt", "install", "-y", "pipx"],
                capture_output=True, timeout=120,
            )
            runtime_available = shutil.which("pipx")
        except Exception:
            pass
    if not runtime_available:
        continue
    package = install_info[tier]
    cmd = f"pipx install {package}"
    return (cmd, tier)
```

### 5. Update `install_with_escalation` references

**Line 370:** Change `for lang in ("go", "pip", "cargo"):` → `for lang in ("go", "pipx", "cargo"):`

**Lines 373-374:** Change pip runtime check:
```python
if lang == "pipx":
    runtime_available = shutil.which("pipx")
```

### 6. Update `_RUNTIME_PACKAGES`

**Before:**
```python
"pip": {"apt": "python3-pip", "dnf": "python3-pip", "pacman": "python-pip", "brew": "python3"},
```

**After:**
```python
"pipx": {"apt": "pipx", "dnf": "pipx", "pacman": "python-pipx", "brew": "pipx"},
```

### 7. Update tests

- `test_get_install_command_prefers_pip` → `test_get_install_command_prefers_pipx` — mock `shutil.which("pipx")` instead of `pip3`, assert method is `"pipx"`
- `TestEscalationChain` tests referencing `pip3`/`pip` in `which_side_effect` → reference `pipx`
- `test_registry_has_api_testing_tools` — still passes (no change needed, just checks key exists)

## Files Modified

1. `wstg_orchestrator/utils/tool_checker.py` — all changes above
2. `tests/test_tool_checker.py` — update pip references to pipx

## Not in scope

- Wikipedia 403 errors (separate issue, unrelated to tool installation)
- amass intel failures (runtime issue, not a tool checker problem)
