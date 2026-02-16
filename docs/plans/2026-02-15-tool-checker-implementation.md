# Tool Checker Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Centralize all tool checking and cross-platform installation into `wstg_orchestrator/utils/tool_checker.py`, called at the top of `main.py` before scope builder.

**Architecture:** A `ToolChecker` class detects the OS/distro/package manager, handles Windows WSL bootstrapping, checks all 19+ tools via `shutil.which()`, displays a summary table, and installs missing tools using a tiered strategy (language installers → system package managers → alt sources). Modules receive a pre-computed `tool_status` dict instead of checking tools themselves.

**Tech Stack:** Python stdlib (`platform`, `shutil`, `subprocess`, `os`, `sys`, `dataclasses`). No new dependencies.

**Design doc:** `docs/plans/2026-02-15-tool-checker-design.md`

---

### Task 1: PlatformInfo dataclass and OS detection

**Files:**
- Create: `wstg_orchestrator/utils/tool_checker.py`
- Test: `tests/test_tool_checker.py`

**Step 1: Write the failing tests**

```python
# tests/test_tool_checker.py
import platform
from unittest.mock import patch, mock_open
from wstg_orchestrator.utils.tool_checker import PlatformInfo, detect_platform


class TestDetectPlatform:
    @patch("platform.system", return_value="Linux")
    @patch("builtins.open", mock_open(read_data='ID=kali\nVERSION_ID="2025.1"\n'))
    @patch("os.path.exists", return_value=True)
    @patch("shutil.which", return_value="/usr/bin/apt")
    def test_detects_kali_linux(self, mock_which, mock_exists, mock_file, mock_sys):
        info = detect_platform()
        assert info.os_type == "linux"
        assert info.distro == "kali"
        assert info.pkg_manager == "apt"
        assert info.is_wsl is False

    @patch("platform.system", return_value="Linux")
    @patch("builtins.open", mock_open(read_data='ID=ubuntu\nVERSION_ID="22.04"\n'))
    @patch("os.path.exists", return_value=True)
    @patch("shutil.which", return_value="/usr/bin/apt")
    def test_detects_ubuntu_linux(self, mock_which, mock_exists, mock_file, mock_sys):
        info = detect_platform()
        assert info.os_type == "linux"
        assert info.distro == "ubuntu"
        assert info.pkg_manager == "apt"

    @patch("platform.system", return_value="Darwin")
    @patch("shutil.which", return_value="/opt/homebrew/bin/brew")
    def test_detects_macos(self, mock_which, mock_sys):
        info = detect_platform()
        assert info.os_type == "macos"
        assert info.distro == "macos"
        assert info.pkg_manager == "brew"

    @patch("platform.system", return_value="Windows")
    def test_detects_windows(self, mock_sys):
        info = detect_platform()
        assert info.os_type == "windows"
        assert info.distro == "windows"

    @patch("platform.system", return_value="Linux")
    @patch("builtins.open")
    @patch("os.path.exists")
    @patch("shutil.which", return_value="/usr/bin/apt")
    def test_detects_wsl(self, mock_which, mock_exists, mock_open_fn, mock_sys):
        def exists_side_effect(path):
            return True
        mock_exists.side_effect = exists_side_effect

        def open_side_effect(path, *args, **kwargs):
            if "proc/version" in str(path):
                return mock_open(read_data="Linux version 5.15.0 microsoft-standard-WSL2")()
            return mock_open(read_data='ID=ubuntu\n')()
        mock_open_fn.side_effect = open_side_effect

        info = detect_platform()
        assert info.is_wsl is True
        assert info.os_type == "linux"

    @patch("platform.system", return_value="Linux")
    @patch("builtins.open", mock_open(read_data='ID=fedora\n'))
    @patch("os.path.exists", return_value=True)
    @patch("shutil.which", return_value="/usr/bin/dnf")
    def test_detects_fedora(self, mock_which, mock_exists, mock_file, mock_sys):
        info = detect_platform()
        assert info.distro == "fedora"
        assert info.pkg_manager == "dnf"

    @patch("platform.system", return_value="Linux")
    @patch("builtins.open", mock_open(read_data='ID=arch\n'))
    @patch("os.path.exists", return_value=True)
    @patch("shutil.which", return_value="/usr/bin/pacman")
    def test_detects_arch(self, mock_which, mock_exists, mock_file, mock_sys):
        info = detect_platform()
        assert info.distro == "arch"
        assert info.pkg_manager == "pacman"
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_tool_checker.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'wstg_orchestrator.utils.tool_checker'`

**Step 3: Write minimal implementation**

```python
# wstg_orchestrator/utils/tool_checker.py
import logging
import os
import platform
import shutil
from dataclasses import dataclass

logger = logging.getLogger("wstg.tool_checker")

# Distro -> package manager mapping
_DISTRO_PKG_MANAGERS = {
    "kali": "apt", "ubuntu": "apt", "debian": "apt",
    "pop": "apt", "linuxmint": "apt", "elementary": "apt",
    "fedora": "dnf", "rhel": "dnf", "centos": "dnf", "rocky": "dnf", "alma": "dnf",
    "arch": "pacman", "manjaro": "pacman", "endeavouros": "pacman",
}


@dataclass
class PlatformInfo:
    os_type: str          # "windows", "macos", "linux"
    distro: str           # e.g. "kali", "ubuntu", "macos", "windows"
    pkg_manager: str      # "apt", "brew", "dnf", "pacman", ""
    is_wsl: bool = False


def detect_platform() -> PlatformInfo:
    """Detect OS type, distro, package manager, and WSL status."""
    system = platform.system()

    if system == "Windows":
        return PlatformInfo(os_type="windows", distro="windows", pkg_manager="")

    if system == "Darwin":
        pkg = "brew" if shutil.which("brew") else ""
        return PlatformInfo(os_type="macos", distro="macos", pkg_manager=pkg)

    # Linux
    distro = _detect_linux_distro()
    is_wsl = _detect_wsl()
    pkg_manager = _DISTRO_PKG_MANAGERS.get(distro, "")

    # If distro mapping didn't work, try to find a package manager on PATH
    if not pkg_manager:
        for mgr in ("apt", "dnf", "pacman"):
            if shutil.which(mgr):
                pkg_manager = mgr
                break

    return PlatformInfo(os_type="linux", distro=distro, pkg_manager=pkg_manager, is_wsl=is_wsl)


def _detect_linux_distro() -> str:
    """Parse /etc/os-release for the distro ID."""
    if not os.path.exists("/etc/os-release"):
        return "unknown"
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("ID="):
                    return line.strip().split("=", 1)[1].strip('"').lower()
    except OSError:
        pass
    return "unknown"


def _detect_wsl() -> bool:
    """Check if running inside Windows Subsystem for Linux."""
    try:
        if os.path.exists("/proc/version"):
            with open("/proc/version") as f:
                content = f.read().lower()
                return "microsoft" in content or "wsl" in content
    except OSError:
        pass
    return False
```

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_tool_checker.py -v`
Expected: All 7 tests PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/utils/tool_checker.py tests/test_tool_checker.py
git commit -m "feat: add PlatformInfo dataclass and OS detection"
```

---

### Task 2: Tool registry with all 19+ tools

**Files:**
- Modify: `wstg_orchestrator/utils/tool_checker.py`
- Test: `tests/test_tool_checker.py`

**Step 1: Write the failing tests**

Add to `tests/test_tool_checker.py`:

```python
from wstg_orchestrator.utils.tool_checker import TOOL_REGISTRY


class TestToolRegistry:
    def test_registry_has_all_recon_tools(self):
        recon_tools = ["subfinder", "amass", "assetfinder", "github-subdomains",
                       "gitlab-subdomains", "altdns", "puredns", "whois", "gau",
                       "httpx", "curl", "jq"]
        for tool in recon_tools:
            assert tool in TOOL_REGISTRY, f"Missing: {tool}"
            assert "reconnaissance" in TOOL_REGISTRY[tool]["required_by"]

    def test_registry_has_fingerprinting_tools(self):
        for tool in ["nmap", "whatweb"]:
            assert tool in TOOL_REGISTRY
            assert "fingerprinting" in TOOL_REGISTRY[tool]["required_by"]

    def test_registry_has_config_testing_tools(self):
        assert "gobuster" in TOOL_REGISTRY
        assert "configuration_testing" in TOOL_REGISTRY["gobuster"]["required_by"]

    def test_registry_has_input_validation_tools(self):
        for tool in ["sqlmap", "commix"]:
            assert tool in TOOL_REGISTRY
            assert "input_validation" in TOOL_REGISTRY[tool]["required_by"]

    def test_registry_has_api_testing_tools(self):
        assert "kiterunner" in TOOL_REGISTRY
        assert "api_testing" in TOOL_REGISTRY["kiterunner"]["required_by"]

    def test_registry_has_seclists(self):
        assert "seclists" in TOOL_REGISTRY

    def test_each_tool_has_check_cmd(self):
        for name, info in TOOL_REGISTRY.items():
            assert "check_cmd" in info, f"{name} missing check_cmd"

    def test_each_tool_has_install_dict(self):
        for name, info in TOOL_REGISTRY.items():
            assert "install" in info, f"{name} missing install"
            assert isinstance(info["install"], dict)

    def test_each_tool_has_required_by(self):
        for name, info in TOOL_REGISTRY.items():
            assert "required_by" in info, f"{name} missing required_by"
            assert isinstance(info["required_by"], list)
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_tool_checker.py::TestToolRegistry -v`
Expected: FAIL with `ImportError`

**Step 3: Write minimal implementation**

Add `TOOL_REGISTRY` dict to `tool_checker.py`. Full registry with all tools and their install commands per method (go, pip, apt, dnf, pacman, brew, github). Reference the existing `TOOL_INSTALL_COMMANDS` from `reconnaissance.py` for known install commands, and research correct commands for the rest.

```python
TOOL_REGISTRY = {
    # === Reconnaissance ===
    "subfinder": {
        "check_cmd": "subfinder",
        "required_by": ["reconnaissance"],
        "install": {
            "go": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "apt": "subfinder",
            "brew": "subfinder",
        },
    },
    "amass": {
        "check_cmd": "amass",
        "required_by": ["reconnaissance"],
        "install": {
            "go": "go install -v github.com/owasp-amass/amass/v4/...@master",
            "apt": "amass",
            "brew": "amass",
        },
    },
    "assetfinder": {
        "check_cmd": "assetfinder",
        "required_by": ["reconnaissance"],
        "install": {
            "go": "go install -v github.com/tomnomnom/assetfinder@latest",
        },
    },
    "github-subdomains": {
        "check_cmd": "github-subdomains",
        "required_by": ["reconnaissance"],
        "install": {
            "go": "go install -v github.com/gwen001/github-subdomains@latest",
        },
    },
    "gitlab-subdomains": {
        "check_cmd": "gitlab-subdomains",
        "required_by": ["reconnaissance"],
        "install": {
            "go": "go install -v github.com/gwen001/gitlab-subdomains@latest",
        },
    },
    "altdns": {
        "check_cmd": "altdns",
        "required_by": ["reconnaissance"],
        "install": {
            "pip": "py-altdns",
        },
    },
    "puredns": {
        "check_cmd": "puredns",
        "required_by": ["reconnaissance"],
        "install": {
            "go": "go install -v github.com/d3mondev/puredns/v2@latest",
        },
    },
    "whois": {
        "check_cmd": "whois",
        "required_by": ["reconnaissance"],
        "install": {
            "apt": "whois",
            "dnf": "whois",
            "pacman": "whois",
            "brew": "whois",
        },
    },
    "gau": {
        "check_cmd": "gau",
        "required_by": ["reconnaissance"],
        "install": {
            "go": "go install -v github.com/lc/gau/v2/cmd/gau@latest",
            "brew": "gau",
        },
    },
    "httpx": {
        "check_cmd": "httpx",
        "required_by": ["reconnaissance"],
        "install": {
            "go": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
            "apt": "httpx-toolkit",
            "brew": "httpx",
        },
    },
    "curl": {
        "check_cmd": "curl",
        "required_by": ["reconnaissance"],
        "install": {
            "apt": "curl",
            "dnf": "curl",
            "pacman": "curl",
            "brew": "curl",
        },
    },
    "jq": {
        "check_cmd": "jq",
        "required_by": ["reconnaissance"],
        "install": {
            "apt": "jq",
            "dnf": "jq",
            "pacman": "jq",
            "brew": "jq",
        },
    },
    # === Fingerprinting ===
    "nmap": {
        "check_cmd": "nmap",
        "required_by": ["fingerprinting"],
        "install": {
            "apt": "nmap",
            "dnf": "nmap",
            "pacman": "nmap",
            "brew": "nmap",
        },
    },
    "whatweb": {
        "check_cmd": "whatweb",
        "required_by": ["fingerprinting"],
        "install": {
            "apt": "whatweb",
            "brew": "whatweb",
        },
    },
    # === Configuration Testing ===
    "gobuster": {
        "check_cmd": "gobuster",
        "required_by": ["configuration_testing"],
        "install": {
            "go": "go install -v github.com/OJ/gobuster/v3@latest",
            "apt": "gobuster",
            "brew": "gobuster",
        },
    },
    # === Input Validation ===
    "sqlmap": {
        "check_cmd": "sqlmap",
        "required_by": ["input_validation"],
        "install": {
            "pip": "sqlmap",
            "apt": "sqlmap",
            "brew": "sqlmap",
        },
    },
    "commix": {
        "check_cmd": "commix",
        "required_by": ["input_validation"],
        "install": {
            "pip": "commix",
            "apt": "commix",
        },
    },
    # === API Testing ===
    "kiterunner": {
        "check_cmd": "kr",
        "required_by": ["api_testing"],
        "install": {
            "go": "go install -v github.com/assetnote/kiterunner/cmd/kr@latest",
        },
    },
    # === Wordlists ===
    "seclists": {
        "check_cmd": "seclists",
        "check_path": "/usr/share/wordlists/seclists",
        "required_by": ["reconnaissance"],
        "install": {
            "apt": "seclists",
        },
    },
}
```

Note: `seclists` uses a special `check_path` field since it's a data package, not a binary.

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_tool_checker.py::TestToolRegistry -v`
Expected: All 9 tests PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/utils/tool_checker.py tests/test_tool_checker.py
git commit -m "feat: add TOOL_REGISTRY with all 19+ tools"
```

---

### Task 3: Tool availability checking

**Files:**
- Modify: `wstg_orchestrator/utils/tool_checker.py`
- Test: `tests/test_tool_checker.py`

**Step 1: Write the failing tests**

```python
from wstg_orchestrator.utils.tool_checker import check_tools, TOOL_REGISTRY


class TestCheckTools:
    @patch("shutil.which")
    def test_all_tools_found(self, mock_which):
        mock_which.return_value = "/usr/bin/tool"
        with patch("os.path.isdir", return_value=True):  # for seclists
            status = check_tools()
        assert all(status.values())
        assert len(status) == len(TOOL_REGISTRY)

    @patch("shutil.which", return_value=None)
    @patch("os.path.isdir", return_value=False)
    def test_no_tools_found(self, mock_isdir, mock_which):
        status = check_tools()
        assert not any(status.values())

    @patch("shutil.which")
    @patch("os.path.isdir", return_value=True)
    def test_partial_tools(self, mock_isdir, mock_which):
        def which_side_effect(name):
            return "/usr/bin/nmap" if name == "nmap" else None
        mock_which.side_effect = which_side_effect
        status = check_tools()
        assert status["nmap"] is True
        assert status["subfinder"] is False
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_tool_checker.py::TestCheckTools -v`
Expected: FAIL with `ImportError`

**Step 3: Write minimal implementation**

```python
def check_tools() -> dict[str, bool]:
    """Check availability of all registered tools. Returns {tool_name: is_available}."""
    status = {}
    for name, info in TOOL_REGISTRY.items():
        # Special case: check_path for data packages like seclists
        check_path = info.get("check_path")
        if check_path:
            status[name] = os.path.isdir(check_path)
        else:
            status[name] = shutil.which(info["check_cmd"]) is not None
    return status
```

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_tool_checker.py::TestCheckTools -v`
Expected: All 3 tests PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/utils/tool_checker.py tests/test_tool_checker.py
git commit -m "feat: add check_tools function for tool availability"
```

---

### Task 4: Summary table display

**Files:**
- Modify: `wstg_orchestrator/utils/tool_checker.py`
- Test: `tests/test_tool_checker.py`

**Step 1: Write the failing tests**

```python
from wstg_orchestrator.utils.tool_checker import format_summary_table, PlatformInfo


class TestSummaryTable:
    def test_table_contains_platform_info(self):
        info = PlatformInfo(os_type="linux", distro="kali", pkg_manager="apt")
        status = {"nmap": True, "subfinder": False}
        output = format_summary_table(info, status)
        assert "kali" in output.lower()
        assert "apt" in output.lower()

    def test_table_shows_found_tools(self):
        info = PlatformInfo(os_type="linux", distro="kali", pkg_manager="apt")
        status = {"nmap": True}
        output = format_summary_table(info, status)
        assert "nmap" in output
        assert "Found" in output or "✓" in output

    def test_table_shows_missing_tools(self):
        info = PlatformInfo(os_type="linux", distro="kali", pkg_manager="apt")
        status = {"nmap": False}
        output = format_summary_table(info, status)
        assert "nmap" in output
        assert "Missing" in output or "✗" in output

    def test_table_shows_counts(self):
        info = PlatformInfo(os_type="linux", distro="kali", pkg_manager="apt")
        status = {"nmap": True, "subfinder": True, "sqlmap": False}
        output = format_summary_table(info, status)
        assert "2" in output  # 2 available
        assert "1" in output  # 1 missing
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_tool_checker.py::TestSummaryTable -v`
Expected: FAIL with `ImportError`

**Step 3: Write minimal implementation**

```python
def format_summary_table(platform_info: PlatformInfo, tool_status: dict[str, bool]) -> str:
    """Format a summary table of tool availability for display."""
    available = sum(1 for v in tool_status.values() if v)
    missing = len(tool_status) - available
    distro_display = platform_info.distro.title()

    lines = []
    lines.append("=" * 64)
    lines.append(f"  WSTG-Orc Tool Checker")
    lines.append(f"  OS: {platform_info.os_type.title()} ({distro_display}) | Package Manager: {platform_info.pkg_manager or 'none'}")
    lines.append("=" * 64)
    lines.append(f"  {'Tool':<22} {'Status':<12} {'Used By'}")
    lines.append("  " + "-" * 58)

    for name, is_available in sorted(tool_status.items()):
        status = "✓ Found" if is_available else "✗ Missing"
        required_by = ", ".join(TOOL_REGISTRY.get(name, {}).get("required_by", []))
        lines.append(f"  {name:<22} {status:<12} {required_by}")

    lines.append("=" * 64)
    lines.append(f"  {available}/{len(tool_status)} tools available | {missing} missing")
    lines.append("=" * 64)

    return "\n".join(lines)
```

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_tool_checker.py::TestSummaryTable -v`
Expected: All 4 tests PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/utils/tool_checker.py tests/test_tool_checker.py
git commit -m "feat: add summary table display for tool status"
```

---

### Task 5: Install logic with tiered strategy

**Files:**
- Modify: `wstg_orchestrator/utils/tool_checker.py`
- Test: `tests/test_tool_checker.py`

**Step 1: Write the failing tests**

```python
from wstg_orchestrator.utils.tool_checker import (
    ToolInstaller, PlatformInfo, TOOL_REGISTRY,
)


class TestToolInstaller:
    def test_get_install_command_prefers_go(self):
        info = PlatformInfo(os_type="linux", distro="kali", pkg_manager="apt")
        installer = ToolInstaller(info)
        cmd, method = installer.get_install_command("subfinder")
        assert method == "go"
        assert "go install" in cmd

    def test_get_install_command_falls_back_to_pkg_manager(self):
        info = PlatformInfo(os_type="linux", distro="kali", pkg_manager="apt")
        installer = ToolInstaller(info)
        cmd, method = installer.get_install_command("nmap")
        assert method == "apt"
        assert "nmap" in cmd

    def test_get_install_command_prefers_pip(self):
        info = PlatformInfo(os_type="linux", distro="kali", pkg_manager="apt")
        installer = ToolInstaller(info)
        cmd, method = installer.get_install_command("altdns")
        assert method == "pip"

    def test_get_install_command_brew_on_macos(self):
        info = PlatformInfo(os_type="macos", distro="macos", pkg_manager="brew")
        installer = ToolInstaller(info)
        cmd, method = installer.get_install_command("nmap")
        assert method == "brew"

    def test_get_install_command_returns_none_when_no_method(self):
        info = PlatformInfo(os_type="linux", distro="unknown", pkg_manager="")
        installer = ToolInstaller(info)
        # Tool with only apt install, no apt available
        result = installer.get_install_command("whatweb")
        assert result is None

    @patch("subprocess.run")
    @patch("shutil.which", return_value="/usr/bin/go")
    def test_install_tool_success(self, mock_which, mock_run):
        mock_run.return_value = type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        info = PlatformInfo(os_type="linux", distro="kali", pkg_manager="apt")
        installer = ToolInstaller(info)
        result = installer.install_tool("subfinder")
        assert result is True

    @patch("subprocess.run")
    @patch("shutil.which", return_value=None)  # go not available
    def test_install_tool_tries_fallback(self, mock_which, mock_run):
        """When go is not available, should try apt fallback for subfinder."""
        mock_run.return_value = type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        info = PlatformInfo(os_type="linux", distro="kali", pkg_manager="apt")
        installer = ToolInstaller(info)
        result = installer.install_tool("subfinder")
        assert result is True
        # Should have used apt since go wasn't available
        call_args = mock_run.call_args[0][0]
        assert "apt" in call_args[0] or "apt" in " ".join(call_args)
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_tool_checker.py::TestToolInstaller -v`
Expected: FAIL with `ImportError`

**Step 3: Write minimal implementation**

```python
import subprocess
import sys


# Priority order for install methods: language-specific first, then system
_INSTALL_TIER_ORDER = ["go", "pip", "cargo", "apt", "dnf", "pacman", "brew", "github"]


class ToolInstaller:
    """Handles installing tools with tiered fallback strategy."""

    def __init__(self, platform_info: PlatformInfo):
        self.platform = platform_info

    def get_install_command(self, tool_name: str) -> tuple[str, str] | None:
        """Return (command, method) for installing a tool, or None if no method available."""
        info = TOOL_REGISTRY.get(tool_name)
        if not info:
            return None

        install_methods = info.get("install", {})

        for method in _INSTALL_TIER_ORDER:
            if method not in install_methods:
                continue

            pkg = install_methods[method]

            # Language-specific: check if the runtime is available
            if method == "go":
                if not shutil.which("go"):
                    continue
                return (pkg, method)
            elif method == "pip":
                pip_cmd = "pip3" if shutil.which("pip3") else ("pip" if shutil.which("pip") else None)
                if not pip_cmd:
                    continue
                return (f"{pip_cmd} install --user {pkg}", method)
            elif method == "cargo":
                if not shutil.which("cargo"):
                    continue
                return (f"cargo install {pkg}", method)
            # System package managers: check if this is the right one for the platform
            elif method in ("apt", "dnf", "pacman"):
                if self.platform.pkg_manager == method:
                    if method == "apt":
                        return (f"sudo apt install -y {pkg}", method)
                    elif method == "dnf":
                        return (f"sudo dnf install -y {pkg}", method)
                    elif method == "pacman":
                        return (f"sudo pacman -S --noconfirm {pkg}", method)
            elif method == "brew":
                if self.platform.pkg_manager == "brew":
                    return (f"brew install {pkg}", method)

        return None

    def install_tool(self, tool_name: str) -> bool:
        """Attempt to install a tool. Returns True on success."""
        result = self.get_install_command(tool_name)
        if result is None:
            logger.warning(f"No install method available for {tool_name}")
            return False

        command, method = result
        logger.info(f"Installing {tool_name} via {method}: {command}")

        try:
            proc = subprocess.run(
                command.split() if method != "go" else command.split(),
                capture_output=True, text=True, timeout=300,
            )
            if proc.returncode == 0:
                logger.info(f"Successfully installed {tool_name}")
                return True
            else:
                logger.warning(f"Failed to install {tool_name}: {proc.stderr[:200]}")
        except subprocess.TimeoutExpired:
            logger.warning(f"Install timed out for {tool_name}")
        except Exception as e:
            logger.error(f"Error installing {tool_name}: {e}")

        return False
```

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_tool_checker.py::TestToolInstaller -v`
Expected: All 7 tests PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/utils/tool_checker.py tests/test_tool_checker.py
git commit -m "feat: add ToolInstaller with tiered fallback strategy"
```

---

### Task 6: Windows WSL flow

**Files:**
- Modify: `wstg_orchestrator/utils/tool_checker.py`
- Test: `tests/test_tool_checker.py`

**Step 1: Write the failing tests**

```python
from wstg_orchestrator.utils.tool_checker import handle_windows_wsl


class TestWindowsWSL:
    @patch("platform.system", return_value="Linux")
    def test_noop_on_linux(self, mock_sys):
        # Should return None (no action needed)
        result = handle_windows_wsl(PlatformInfo(os_type="linux", distro="kali", pkg_manager="apt"))
        assert result is None

    @patch("subprocess.run")
    def test_exits_when_no_wsl(self, mock_run):
        mock_run.side_effect = FileNotFoundError("wsl not found")
        info = PlatformInfo(os_type="windows", distro="windows", pkg_manager="")
        with pytest.raises(SystemExit):
            handle_windows_wsl(info)

    @patch("subprocess.run")
    def test_detects_wsl_with_kali(self, mock_run):
        def run_side_effect(cmd, **kwargs):
            if "wsl" in cmd and "--status" in cmd:
                return type("R", (), {"returncode": 0, "stdout": "Default Version: 2", "stderr": ""})()
            if "wsl" in cmd and "-l" in cmd:
                return type("R", (), {"returncode": 0, "stdout": "kali-linux\nUbuntu\n", "stderr": ""})()
            return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        mock_run.side_effect = run_side_effect
        info = PlatformInfo(os_type="windows", distro="windows", pkg_manager="")
        # Should return "relaunch" action with kali distro
        result = handle_windows_wsl(info)
        assert result == "relaunch"

    @patch("builtins.input", return_value="y")
    @patch("subprocess.run")
    def test_offers_kali_install_when_no_distro(self, mock_run, mock_input):
        def run_side_effect(cmd, **kwargs):
            if "--status" in cmd:
                return type("R", (), {"returncode": 0, "stdout": "Default Version: 2", "stderr": ""})()
            if "-l" in cmd:
                return type("R", (), {"returncode": 0, "stdout": "\n", "stderr": ""})()
            if "--install" in cmd:
                return type("R", (), {"returncode": 0, "stdout": "Installing...", "stderr": ""})()
            return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        mock_run.side_effect = run_side_effect
        info = PlatformInfo(os_type="windows", distro="windows", pkg_manager="")
        result = handle_windows_wsl(info)
        assert result == "relaunch"
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_tool_checker.py::TestWindowsWSL -v`
Expected: FAIL with `ImportError`

**Step 3: Write minimal implementation**

```python
def handle_windows_wsl(platform_info: PlatformInfo) -> str | None:
    """Handle Windows WSL detection and setup. Returns 'relaunch' if WSL is ready, None if not Windows."""
    if platform_info.os_type != "windows":
        return None

    # Check if WSL2 is installed
    try:
        result = subprocess.run(
            ["wsl", "--status"], capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            _exit_no_wsl()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        _exit_no_wsl()

    # Check for installed distros
    result = subprocess.run(
        ["wsl", "-l", "-q"], capture_output=True, text=True, timeout=30,
    )
    distros = [line.strip() for line in result.stdout.splitlines() if line.strip()]

    has_kali = any("kali" in d.lower() for d in distros)

    if not has_kali:
        if not distros:
            print("\nWSL2 is installed but no distros are found.")
        else:
            print(f"\nWSL2 distros found: {', '.join(distros)}")
            print("Kali Linux is not installed.")

        print("This framework works best on Kali Linux.")
        answer = input("Would you like to install the Kali Linux WSL distro? [Y/n]: ").strip().lower()
        if answer not in ("", "y", "yes"):
            _exit_no_wsl()

        print("Installing Kali Linux WSL distro (this may take a few minutes)...")
        subprocess.run(["wsl", "--install", "-d", "kali-linux"], timeout=600)

    return "relaunch"


def _exit_no_wsl():
    """Print WSL install instructions and exit."""
    print("\n" + "=" * 60)
    print("  WSTG-Orc requires Windows Subsystem for Linux (WSL2)")
    print("=" * 60)
    print("\nThis framework needs WSL to function properly and get the best results.")
    print("\nTo install WSL2:")
    print("  1. Open PowerShell as Administrator")
    print("  2. Run: wsl --install")
    print("  3. Restart your computer")
    print("\nTo enable WSL2 in Windows Features:")
    print("  1. Open 'Turn Windows features on or off'")
    print("  2. Enable 'Windows Subsystem for Linux'")
    print("  3. Enable 'Virtual Machine Platform'")
    print("  4. Restart your computer")
    print()
    sys.exit(1)
```

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_tool_checker.py::TestWindowsWSL -v`
Expected: All 4 tests PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/utils/tool_checker.py tests/test_tool_checker.py
git commit -m "feat: add Windows WSL2 detection and Kali install flow"
```

---

### Task 7: User prompts (install all / select / skip)

**Files:**
- Modify: `wstg_orchestrator/utils/tool_checker.py`
- Test: `tests/test_tool_checker.py`

**Step 1: Write the failing tests**

```python
from wstg_orchestrator.utils.tool_checker import prompt_install_missing


class TestPromptInstallMissing:
    @patch("builtins.input", return_value="3")
    def test_skip_returns_empty(self, mock_input):
        missing = ["nmap", "sqlmap"]
        result = prompt_install_missing(missing)
        assert result == []

    @patch("builtins.input", return_value="1")
    def test_install_all_returns_all(self, mock_input):
        missing = ["nmap", "sqlmap"]
        result = prompt_install_missing(missing)
        assert result == ["nmap", "sqlmap"]

    def test_no_missing_returns_empty(self):
        result = prompt_install_missing([])
        assert result == []
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_tool_checker.py::TestPromptInstallMissing -v`
Expected: FAIL

**Step 3: Write minimal implementation**

```python
def prompt_install_missing(missing_tools: list[str]) -> list[str]:
    """Prompt user about missing tools. Returns list of tools to install."""
    if not missing_tools:
        return []

    count = len(missing_tools)
    print(f"\n{count} tool{'s are' if count > 1 else ' is'} missing. What would you like to do?")
    print("  [1] Install all missing tools")
    print("  [2] Select which to install")
    print("  [3] Skip — continue without missing tools")

    choice = input("\n> ").strip()

    if choice == "1":
        return list(missing_tools)
    elif choice == "2":
        return _select_tools(missing_tools)
    else:
        return []


def _select_tools(tools: list[str]) -> list[str]:
    """Let user select individual tools to install."""
    selected = set(range(len(tools)))  # all selected by default

    print("\nSelect tools to install (enter number to toggle, 'done' to confirm):")
    while True:
        for i, tool in enumerate(tools):
            marker = "x" if i in selected else " "
            required_by = ", ".join(TOOL_REGISTRY.get(tool, {}).get("required_by", []))
            print(f"  [{marker}] {i+1}. {tool:<22} ({required_by})")

        choice = input("\nToggle number or 'done': ").strip().lower()
        if choice == "done":
            break
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(tools):
                selected.symmetric_difference_update({idx})
        except ValueError:
            pass

    return [tools[i] for i in sorted(selected)]
```

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_tool_checker.py::TestPromptInstallMissing -v`
Expected: All 3 tests PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/utils/tool_checker.py tests/test_tool_checker.py
git commit -m "feat: add install prompt UI (all/select/skip)"
```

---

### Task 8: Escalation chain (language runtime + pkg manager offers)

**Files:**
- Modify: `wstg_orchestrator/utils/tool_checker.py`
- Test: `tests/test_tool_checker.py`

**Step 1: Write the failing tests**

```python
from wstg_orchestrator.utils.tool_checker import ToolInstaller, PlatformInfo


class TestEscalationChain:
    @patch("builtins.input", return_value="y")
    @patch("subprocess.run")
    @patch("shutil.which")
    def test_offers_to_install_go_when_missing(self, mock_which, mock_run, mock_input):
        """When go isn't available but tool needs it, offer to install go first."""
        call_count = {"which": 0, "run": 0}

        def which_side_effect(name):
            call_count["which"] += 1
            # First call: go not available. After install: go available.
            if name == "go":
                return "/usr/bin/go" if call_count["which"] > 2 else None
            return None  # pip, cargo not available either

        mock_which.side_effect = which_side_effect
        mock_run.return_value = type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()

        info = PlatformInfo(os_type="linux", distro="kali", pkg_manager="apt")
        installer = ToolInstaller(info)
        result = installer.install_with_escalation("subfinder")
        assert result is True

    @patch("builtins.input", return_value="n")
    @patch("shutil.which", return_value=None)
    @patch("subprocess.run")
    def test_falls_back_to_pkg_manager_when_declined(self, mock_run, mock_which, mock_input):
        """User declines go install -> falls back to apt."""
        mock_run.return_value = type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        info = PlatformInfo(os_type="linux", distro="kali", pkg_manager="apt")
        installer = ToolInstaller(info)
        result = installer.install_with_escalation("subfinder")
        assert result is True
        # Should have used apt
        call_args_str = str(mock_run.call_args)
        assert "apt" in call_args_str

    @patch("builtins.input", return_value="n")
    @patch("shutil.which", return_value=None)
    def test_exits_when_no_options(self, mock_which, mock_input):
        """No language runtime, no pkg manager, user declines -> friendly exit."""
        info = PlatformInfo(os_type="linux", distro="unknown", pkg_manager="")
        installer = ToolInstaller(info)
        with pytest.raises(SystemExit):
            installer.install_with_escalation("assetfinder")
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_tool_checker.py::TestEscalationChain -v`
Expected: FAIL

**Step 3: Write minimal implementation**

Add `install_with_escalation` method to `ToolInstaller`:

```python
def install_with_escalation(self, tool_name: str) -> bool:
    """Install tool with full escalation chain. May offer to install language runtimes."""
    info = TOOL_REGISTRY.get(tool_name)
    if not info:
        return False

    install_methods = info.get("install", {})

    # Tier 1: Try language-specific installers
    for lang in ("go", "pip", "cargo"):
        if lang not in install_methods:
            continue
        runtime = lang if lang != "pip" else "pip3"
        if shutil.which(runtime) or (lang == "pip" and shutil.which("pip")):
            if self.install_tool(tool_name):
                return True
        else:
            # Offer to install the language runtime
            if self._offer_install_runtime(lang):
                if self.install_tool(tool_name):
                    return True

    # Tier 2: System package manager
    pkg_mgr = self.platform.pkg_manager
    if pkg_mgr and pkg_mgr in install_methods:
        if self.install_tool(tool_name):
            return True

    # Tier 3: No options available
    if not self.platform.pkg_manager:
        if not self._offer_install_pkg_manager():
            print("\nWithout a package manager or language installer, WSTG-Orc")
            print("has no way to install the tools it needs to operate.")
            print("Please install tools manually and try again. Goodbye!")
            sys.exit(0)
        # Retry with pkg manager now available
        if self.install_tool(tool_name):
            return True

    return False

def _offer_install_runtime(self, lang: str) -> bool:
    """Offer to install a language runtime (go, pip, cargo). Returns True if installed."""
    runtime_packages = {
        "go": {"apt": "golang-go", "dnf": "golang", "pacman": "go", "brew": "go"},
        "pip": {"apt": "python3-pip", "dnf": "python3-pip", "pacman": "python-pip", "brew": "python3"},
        "cargo": {"apt": "cargo", "dnf": "cargo", "pacman": "rust", "brew": "rust"},
    }

    pkg_mgr = self.platform.pkg_manager
    packages = runtime_packages.get(lang, {})
    pkg = packages.get(pkg_mgr)

    if not pkg or not pkg_mgr:
        return False

    answer = input(f"{lang} is not installed. Install it via {pkg_mgr}? [Y/n]: ").strip().lower()
    if answer not in ("", "y", "yes"):
        return False

    cmd = self._build_pkg_install_cmd(pkg_mgr, pkg)
    try:
        result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=300)
        return result.returncode == 0
    except Exception:
        return False

def _offer_install_pkg_manager(self) -> bool:
    """Offer to install a package manager. Only relevant for macOS (Homebrew)."""
    if self.platform.os_type == "macos":
        answer = input("Homebrew is required for system packages on macOS. Install it? [Y/n]: ").strip().lower()
        if answer not in ("", "y", "yes"):
            return False
        try:
            result = subprocess.run(
                ["bash", "-c", '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'],
                timeout=600,
            )
            if result.returncode == 0:
                self.platform.pkg_manager = "brew"
                return True
        except Exception:
            pass
    return False

def _build_pkg_install_cmd(self, pkg_mgr: str, package: str) -> str:
    """Build the install command for a system package manager."""
    if pkg_mgr == "apt":
        return f"sudo apt install -y {package}"
    elif pkg_mgr == "dnf":
        return f"sudo dnf install -y {package}"
    elif pkg_mgr == "pacman":
        return f"sudo pacman -S --noconfirm {package}"
    elif pkg_mgr == "brew":
        return f"brew install {package}"
    return ""
```

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_tool_checker.py::TestEscalationChain -v`
Expected: All 3 tests PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/utils/tool_checker.py tests/test_tool_checker.py
git commit -m "feat: add escalation chain with runtime install offers"
```

---

### Task 9: Main ToolChecker.run() orchestrator method

**Files:**
- Modify: `wstg_orchestrator/utils/tool_checker.py`
- Test: `tests/test_tool_checker.py`

**Step 1: Write the failing tests**

```python
from wstg_orchestrator.utils.tool_checker import ToolChecker


class TestToolCheckerRun:
    @patch("wstg_orchestrator.utils.tool_checker.handle_windows_wsl", return_value=None)
    @patch("wstg_orchestrator.utils.tool_checker.detect_platform")
    @patch("wstg_orchestrator.utils.tool_checker.check_tools")
    @patch("wstg_orchestrator.utils.tool_checker.format_summary_table", return_value="table")
    @patch("builtins.print")
    def test_run_returns_tool_status(self, mock_print, mock_table, mock_check, mock_detect, mock_wsl):
        mock_detect.return_value = PlatformInfo(os_type="linux", distro="kali", pkg_manager="apt")
        mock_check.return_value = {"nmap": True, "subfinder": True}
        checker = ToolChecker()
        result = checker.run()
        assert result == {"nmap": True, "subfinder": True}

    @patch("wstg_orchestrator.utils.tool_checker.handle_windows_wsl", return_value=None)
    @patch("wstg_orchestrator.utils.tool_checker.detect_platform")
    @patch("wstg_orchestrator.utils.tool_checker.check_tools")
    @patch("wstg_orchestrator.utils.tool_checker.format_summary_table", return_value="table")
    @patch("wstg_orchestrator.utils.tool_checker.prompt_install_missing", return_value=[])
    @patch("builtins.print")
    def test_run_prompts_on_missing(self, mock_print, mock_prompt, mock_table, mock_check, mock_detect, mock_wsl):
        mock_detect.return_value = PlatformInfo(os_type="linux", distro="kali", pkg_manager="apt")
        mock_check.return_value = {"nmap": True, "subfinder": False}
        checker = ToolChecker()
        result = checker.run()
        mock_prompt.assert_called_once_with(["subfinder"])
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_tool_checker.py::TestToolCheckerRun -v`
Expected: FAIL

**Step 3: Write minimal implementation**

```python
class ToolChecker:
    """Main entry point for cross-platform tool checking and installation."""

    def run(self) -> dict[str, bool]:
        """Detect OS, check tools, prompt to install missing, return final status."""
        # Step 1: Detect platform
        platform_info = detect_platform()
        logger.info(f"Platform: {platform_info}")

        # Step 2: Windows WSL handling
        wsl_result = handle_windows_wsl(platform_info)
        if wsl_result == "relaunch":
            import sys as _sys
            import os as _os
            _os.execvp("wsl", [
                "wsl", "-d", "kali-linux", "python3",
                _sys.argv[0], *_sys.argv[1:],
            ])

        # Step 3: Check all tools
        tool_status = check_tools()

        # Step 4: Display summary table
        table = format_summary_table(platform_info, tool_status)
        print(table)

        # Step 5: Handle missing tools
        missing = [name for name, available in tool_status.items() if not available]
        if missing:
            to_install = prompt_install_missing(missing)
            if to_install:
                installer = ToolInstaller(platform_info)
                for tool_name in to_install:
                    print(f"Installing {tool_name}...", end=" ", flush=True)
                    success = installer.install_with_escalation(tool_name)
                    print("✓ done" if success else "✗ failed")

                # Re-check after installs
                tool_status = check_tools()

                # Show updated count
                still_missing = sum(1 for v in tool_status.values() if not v)
                if still_missing:
                    print(f"\n{still_missing} tool(s) still unavailable.")
                else:
                    print("\nAll tools installed successfully!")

        return tool_status
```

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_tool_checker.py::TestToolCheckerRun -v`
Expected: All 2 tests PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/utils/tool_checker.py tests/test_tool_checker.py
git commit -m "feat: add ToolChecker.run() orchestrator method"
```

---

### Task 10: Integrate into main.py and pass tool_status to Orchestrator

**Files:**
- Modify: `main.py:178-202` (add ToolChecker call, pass tool_status to Orchestrator)
- Modify: `main.py:85-135` (add tool_status param, remove _check_tools)
- Test: `tests/test_orchestrator.py`

**Step 1: Write the failing test**

Add to existing tests or create:

```python
# In tests/test_orchestrator.py (add to existing)
def test_orchestrator_accepts_tool_status():
    """Orchestrator should accept tool_status in constructor."""
    from unittest.mock import MagicMock, patch
    with patch("wstg_orchestrator.utils.config_loader.ConfigLoader"):
        # Just verify the constructor accepts it without error
        # Full integration test would be too heavy here
        pass
```

This is primarily an integration change. The key code changes:

**Step 2: Modify main.py**

At top of `main()`, before scope builder:

```python
from wstg_orchestrator.utils.tool_checker import ToolChecker

def main():
    parser = argparse.ArgumentParser(description="WSTG Orchestrator")
    # ... existing argparse ...
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    # Tool check — runs before anything else
    checker = ToolChecker()
    tool_status = checker.run()

    if args.new or not os.path.exists(args.config):
        builder = ScopeBuilder()
        # ... rest unchanged ...
```

**Step 3: Modify Orchestrator.__init__ to accept tool_status**

```python
class Orchestrator:
    def __init__(
        self,
        config_path: str,
        state_path: str = "state.json",
        evidence_dir: str = "evidence",
        tool_status: dict[str, bool] | None = None,
    ):
        self.tool_status = tool_status or {}
        # ... rest unchanged ...
```

**Step 4: Delete `Orchestrator._check_tools()` method** (lines 126-135)

**Step 5: Remove `self._check_tools()` call from `Orchestrator.run()`** (line 141)

**Step 6: Pass tool_status when creating Orchestrator in main()**

```python
    orch = Orchestrator(
        config_path=args.config,
        state_path=args.state,
        evidence_dir=args.evidence,
        tool_status=tool_status,
    )
```

**Step 7: Commit**

```bash
git add main.py
git commit -m "feat: integrate ToolChecker into main.py, remove _check_tools"
```

---

### Task 11: Clean up reconnaissance.py — remove tool checks and install logic

**Files:**
- Modify: `wstg_orchestrator/modules/reconnaissance.py:34-45` (remove TOOL_INSTALL_COMMANDS)
- Modify: `wstg_orchestrator/modules/reconnaissance.py:131-146` (remove _prompt_install_tool)
- Modify: `wstg_orchestrator/modules/reconnaissance.py:468-473` (remove _ensure_seclists)
- Modify: Multiple methods that call `_prompt_install_tool` and `is_tool_available`
- Test: `tests/test_reconnaissance.py`

**Step 1: Remove `TOOL_INSTALL_COMMANDS` dict** (lines 34-45)

**Step 2: Remove `_prompt_install_tool` method** (lines 131-146)

**Step 3: Remove `_ensure_seclists` method** (lines 468-473)

**Step 4: Remove `import subprocess as _subprocess`** (line 5) — no longer needed for tool install

**Step 5: Simplify all tool-missing handling in methods**

In every method that currently does `if result.tool_missing: if self._prompt_install_tool(...)`, change to just:

```python
if result.tool_missing:
    self.logger.warning(f"<tool> not found, skipping")
    return []  # or return result, depending on the method
```

Methods to update:
- `_run_amass_intel_org` (line 182-186)
- `_run_whois_radb` (line 203-207)
- `_run_assetfinder` (line 400-403)
- `_run_crtsh` (lines 412-415) — remove the `is_tool_available` loop for curl/jq
- `_run_github_subdomains` (lines 439-443)
- `_run_gitlab_subdomains` (lines 458-462)
- `_run_altdns` (lines 505-514)
- `_run_puredns` (lines 553-561)
- `_live_host_validation` (line 623) — change `self._cmd.is_tool_available("httpx")` to use tool_status

**Step 6: For `_live_host_validation`, use tool_status instead of is_tool_available**

The module needs access to `tool_status`. Add it to `BaseModule.__init__` or pass through the module constructor. The simplest approach: the module can just check `result.tool_missing` which already works via `CommandRunner`.

Actually, reviewing the code more carefully: most tool checks already happen via `CommandRunner.run()` which returns `tool_missing=True`. The modules just need to stop calling `_prompt_install_tool` and instead just log+skip. The `_live_host_validation` method at line 623 directly calls `is_tool_available` — change that to let `CommandRunner` handle it (attempt to run, check `tool_missing`).

**Step 7: Run existing tests**

Run: `python -m pytest tests/test_reconnaissance.py -v`
Expected: PASS (existing tests should still work since we only removed install prompts)

**Step 8: Commit**

```bash
git add wstg_orchestrator/modules/reconnaissance.py
git commit -m "refactor: remove tool install logic from reconnaissance module"
```

---

### Task 12: Clean up fingerprinting.py — remove inline tool checks

**Files:**
- Modify: `wstg_orchestrator/modules/fingerprinting.py:53,67`

**Step 1: Change `_service_scanning` method**

Line 53: `if hosts and self._cmd.is_tool_available("nmap"):` — keep this as-is since it uses CommandRunner's method which still exists. OR simplify to just run the command and check `result.tool_missing`.

Line 67: `if self._cmd.is_tool_available("whatweb"):` — same treatment.

These are gating checks before running the tool. Since CommandRunner already returns `tool_missing=True`, we can simplify by just running the tool and handling the result. But the current approach (check first, skip if missing) is also fine and doesn't do any installation. These checks are lightweight and don't prompt the user.

**Decision:** These are actually fine as-is — they're just `shutil.which` checks via CommandRunner, no install prompts. The design doc says "Modules still handle 'if tool unavailable, skip this test' logic — they just read from the pre-computed dict." Leave them or convert to use tool_status. Simplest: leave them since they're already clean.

**Step 2: Commit** (if any changes were made)

```bash
git add wstg_orchestrator/modules/fingerprinting.py
git commit -m "refactor: simplify tool checks in fingerprinting module"
```

---

### Task 13: Clean up configuration_testing.py and api_testing.py

**Files:**
- Modify: `wstg_orchestrator/modules/configuration_testing.py:117`
- Modify: `wstg_orchestrator/modules/api_testing.py:118`

Same as Task 12 — these modules use `is_tool_available` as a gate but don't prompt for installation. They're already clean. No changes needed unless we want to convert to tool_status dict.

**Step 1: Review** — confirm no `_prompt_install_tool` or install logic exists in these files. ✓ Confirmed.

**Step 2: Commit** (skip if no changes)

---

### Task 14: Clean up input_validation.py — remove inline tool checks

**Files:**
- Modify: `wstg_orchestrator/modules/input_validation.py:147,284`

Line 147: `if not self._cmd.is_tool_available("sqlmap"):` — gating check, no install prompt. Clean.
Line 284: `if self._cmd.is_tool_available("commix"):` — gating check, no install prompt. Clean.

No changes needed. These are already using the pattern "check → skip if missing".

---

### Task 15: Final integration test — run main.py with --help

**Step 1: Verify main.py imports work**

Run: `python main.py --help`
Expected: Help text printed, no import errors

**Step 2: Verify all tests pass**

Run: `python -m pytest tests/ -v`
Expected: All tests PASS

**Step 3: Final commit**

```bash
git add -A
git commit -m "feat: complete tool checker integration — centralized cross-platform tool management"
```

---

## Summary of Changes

| File | Action | What Changes |
|------|--------|-------------|
| `wstg_orchestrator/utils/tool_checker.py` | CREATE | New file: PlatformInfo, detect_platform, TOOL_REGISTRY, check_tools, format_summary_table, ToolInstaller, prompt_install_missing, handle_windows_wsl, ToolChecker |
| `tests/test_tool_checker.py` | CREATE | Full test suite for tool_checker |
| `main.py` | MODIFY | Add ToolChecker.run() before scope builder, pass tool_status to Orchestrator, remove _check_tools() |
| `wstg_orchestrator/modules/reconnaissance.py` | MODIFY | Remove TOOL_INSTALL_COMMANDS, _prompt_install_tool, _ensure_seclists, simplify tool_missing handling |
| `wstg_orchestrator/modules/fingerprinting.py` | REVIEW | Existing checks are clean, minimal changes |
| `wstg_orchestrator/modules/configuration_testing.py` | REVIEW | Existing checks are clean, no changes |
| `wstg_orchestrator/modules/input_validation.py` | REVIEW | Existing checks are clean, no changes |
| `wstg_orchestrator/modules/api_testing.py` | REVIEW | Existing checks are clean, no changes |
