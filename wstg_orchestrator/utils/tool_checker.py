import logging
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass

logger = logging.getLogger("wstg.tool_checker")

_DISTRO_PKG_MANAGERS = {
    "kali": "apt", "ubuntu": "apt", "debian": "apt",
    "pop": "apt", "linuxmint": "apt", "elementary": "apt",
    "fedora": "dnf", "rhel": "dnf", "centos": "dnf", "rocky": "dnf", "alma": "dnf",
    "arch": "pacman", "manjaro": "pacman", "endeavouros": "pacman",
}


@dataclass
class PlatformInfo:
    os_type: str
    distro: str
    pkg_manager: str
    is_wsl: bool = False


def detect_platform() -> PlatformInfo:
    system = platform.system()
    if system == "Windows":
        return PlatformInfo(os_type="windows", distro="windows", pkg_manager="")
    if system == "Darwin":
        pkg = "brew" if shutil.which("brew") else ""
        return PlatformInfo(os_type="macos", distro="macos", pkg_manager=pkg)
    distro = _detect_linux_distro()
    is_wsl = _detect_wsl()
    pkg_manager = _DISTRO_PKG_MANAGERS.get(distro, "")
    if not pkg_manager:
        for mgr in ("apt", "dnf", "pacman"):
            if shutil.which(mgr):
                pkg_manager = mgr
                break
    return PlatformInfo(os_type="linux", distro=distro, pkg_manager=pkg_manager, is_wsl=is_wsl)


def _detect_linux_distro() -> str:
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
            "pipx": "py-altdns",
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
            "pipx": "sqlmap",
            "apt": "sqlmap",
            "brew": "sqlmap",
        },
    },
    "commix": {
        "check_cmd": "commix",
        "required_by": ["input_validation"],
        "install": {
            "pipx": "commix",
            "apt": "commix",
        },
    },
    # === API Testing ===
    "kiterunner": {
        "check_cmd": "kiterunner",
        "required_by": ["api_testing"],
        "install": {
            "go": "go install -v github.com/assetnote/kiterunner/cmd/kiterunner@latest",
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


def check_tools() -> dict[str, bool]:
    """Check availability of all registered tools. Returns {tool_name: is_available}."""
    status = {}
    for name, info in TOOL_REGISTRY.items():
        check_path = info.get("check_path")
        if check_path:
            status[name] = os.path.isdir(check_path)
        else:
            status[name] = shutil.which(info["check_cmd"]) is not None
    return status


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
        status = "\u2713 Found" if is_available else "\u2717 Missing"
        required_by = ", ".join(TOOL_REGISTRY.get(name, {}).get("required_by", []))
        lines.append(f"  {name:<22} {status:<12} {required_by}")

    lines.append("=" * 64)
    lines.append(f"  {available}/{len(tool_status)} tools available | {missing} missing")
    lines.append("=" * 64)

    return "\n".join(lines)


_INSTALL_TIER_ORDER = ["go", "pipx", "cargo", "apt", "dnf", "pacman", "brew"]

_LANGUAGE_INSTALLERS = {"go", "pipx", "cargo"}
_SYSTEM_PKG_MANAGERS = {"apt", "dnf", "pacman", "brew"}


class ToolInstaller:
    """Installs tools using a tiered strategy: language installers first, then system pkg managers."""

    def __init__(self, platform_info: PlatformInfo):
        self.platform = platform_info

    def get_install_command(self, tool_name: str) -> tuple[str, str] | None:
        """Return (command_string, method) for the best available install method, or None."""
        if tool_name not in TOOL_REGISTRY:
            return None
        install_info = TOOL_REGISTRY[tool_name]["install"]

        for tier in _INSTALL_TIER_ORDER:
            if tier not in install_info:
                continue

            if tier in _LANGUAGE_INSTALLERS:
                # Check if the runtime is available
                if tier == "pipx":
                    runtime_available = shutil.which("pipx")
                    if not runtime_available:
                        # Auto-install pipx via apt
                        try:
                            subprocess.run(
                                ["sudo", "apt", "install", "-y", "pipx"],
                                capture_output=True, timeout=120,
                            )
                            runtime_available = shutil.which("pipx")
                        except Exception:
                            pass
                else:
                    runtime_available = shutil.which(tier)
                if not runtime_available:
                    continue

                # Build the command
                package = install_info[tier]
                if tier == "go":
                    cmd = package  # Already a full go install command
                elif tier == "pipx":
                    cmd = f"pipx install {package}"
                elif tier == "cargo":
                    cmd = f"cargo install {package}"
                return (cmd, tier)

            if tier in _SYSTEM_PKG_MANAGERS:
                if self.platform.pkg_manager != tier:
                    continue
                package = install_info[tier]
                if tier == "apt":
                    cmd = f"sudo apt install -y {package}"
                elif tier == "dnf":
                    cmd = f"sudo dnf install -y {package}"
                elif tier == "pacman":
                    cmd = f"sudo pacman -S --noconfirm {package}"
                elif tier == "brew":
                    cmd = f"brew install {package}"
                return (cmd, tier)

        return None

    def install_tool(self, tool_name: str) -> bool:
        """Run the install command for a tool. Returns True on success."""
        result = self.get_install_command(tool_name)
        if result is None:
            logger.warning("No install method found for %s", tool_name)
            return False
        cmd, method = result
        logger.info("Installing %s via %s: %s", tool_name, method, cmd)
        try:
            proc = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=300,
            )
            if proc.returncode == 0:
                logger.info("Successfully installed %s", tool_name)
                return True
            logger.error("Failed to install %s: %s", tool_name, proc.stderr)
            return False
        except (subprocess.TimeoutExpired, OSError) as e:
            logger.error("Install command failed for %s: %s", tool_name, e)
            return False

    def install_with_escalation(self, tool_name: str) -> bool:
        """Install a tool with full escalation chain.

        1. Try language installer (go/pip/cargo) -- if runtime missing, offer to install it
        2. If user declines runtime, fall back to system package manager
        3. If no package manager, offer to install one (macOS = Homebrew)
        4. If nothing works, return False (caller decides what to do)
        """
        if tool_name not in TOOL_REGISTRY:
            logger.warning("Unknown tool: %s", tool_name)
            return False

        install_info = TOOL_REGISTRY[tool_name]["install"]

        # Step 1: Try language installers -- offer to install runtime if missing
        for lang in ("go", "pipx", "cargo"):
            if lang not in install_info:
                continue
            if lang == "pipx":
                runtime_available = shutil.which("pipx")
            else:
                runtime_available = shutil.which(lang)

            if not runtime_available:
                if self._offer_install_runtime(lang):
                    runtime_available = True

            if runtime_available:
                # Delegate to install_tool() which uses get_install_command()
                if self.install_tool(tool_name):
                    return True

        # Step 2: Fall back to system package manager
        if self.platform.pkg_manager:
            if self.install_tool(tool_name):
                return True

        # Step 3: Offer to install a package manager if none exists
        if not self.platform.pkg_manager:
            installed_mgr = self._offer_install_pkg_manager()
            if installed_mgr:
                self.platform.pkg_manager = installed_mgr
                if self.install_tool(tool_name):
                    return True

        # Step 4: Nothing worked
        logger.warning("Could not install %s -- no available install method for this platform", tool_name)
        return False

    def _offer_install_runtime(self, runtime: str) -> bool:
        """Offer to install a language runtime (go/pip/cargo) via system pkg manager."""
        if not self.platform.pkg_manager:
            return False
        pkg_name = _RUNTIME_PACKAGES.get(runtime, {}).get(self.platform.pkg_manager)
        if not pkg_name:
            return False

        answer = input(f"  {runtime} is not installed. Install it via {self.platform.pkg_manager}? [y/N] ").strip().lower()
        if answer != "y":
            return False

        cmd = _build_pkg_install_cmd(self.platform.pkg_manager, pkg_name)
        try:
            proc = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=300,
            )
            return proc.returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            return False

    def _offer_install_pkg_manager(self) -> str | None:
        """Offer to install a package manager (Homebrew on macOS)."""
        if self.platform.os_type == "macos":
            answer = input("  Homebrew is not installed. Install it? [y/N] ").strip().lower()
            if answer == "y":
                try:
                    proc = subprocess.run(
                        '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"',
                        shell=True, capture_output=True, text=True, timeout=600,
                    )
                    if proc.returncode == 0:
                        return "brew"
                except (subprocess.TimeoutExpired, OSError):
                    pass
        return None


_RUNTIME_PACKAGES = {
    "go": {"apt": "golang-go", "dnf": "golang", "pacman": "go", "brew": "go"},
    "pipx": {"apt": "pipx", "dnf": "pipx", "pacman": "python-pipx", "brew": "pipx"},
    "cargo": {"apt": "cargo", "dnf": "cargo", "pacman": "rust", "brew": "rust"},
}


def _build_pkg_install_cmd(pkg_manager: str, package: str) -> str:
    """Build a system package install command string."""
    if pkg_manager == "apt":
        return f"sudo apt install -y {package}"
    elif pkg_manager == "dnf":
        return f"sudo dnf install -y {package}"
    elif pkg_manager == "pacman":
        return f"sudo pacman -S --noconfirm {package}"
    elif pkg_manager == "brew":
        return f"brew install {package}"
    return ""


def _exit_no_wsl():
    """Print WSL install instructions and exit."""
    print("\n  WSL2 with Kali Linux is required to run WSTG-Orc on Windows.")
    print("  Install WSL2: https://learn.microsoft.com/en-us/windows/wsl/install")
    print("  Then install Kali: wsl --install -d kali-linux\n")
    sys.exit(1)


def handle_windows_wsl(platform_info: PlatformInfo) -> str | None:
    """Handle Windows WSL detection and setup. Returns 'relaunch' if ready, None if not Windows."""
    if platform_info.os_type != "windows":
        return None

    # Check WSL2 availability
    try:
        result = subprocess.run(
            ["wsl", "--status"], capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            _exit_no_wsl()
    except (FileNotFoundError, OSError):
        _exit_no_wsl()

    # Check for kali-linux distro
    result = subprocess.run(
        ["wsl", "-l", "-q"], capture_output=True, text=True, timeout=30,
    )
    distros = result.stdout.strip().split("\n")
    distros = [d.strip() for d in distros if d.strip()]

    if "kali-linux" in distros:
        return "relaunch"

    # Offer to install kali-linux
    answer = input("  Kali Linux not found in WSL. Install it? [y/N] ").strip().lower()
    if answer != "y":
        _exit_no_wsl()

    print("  Installing Kali Linux via WSL...")
    subprocess.run(
        ["wsl", "--install", "-d", "kali-linux"], capture_output=True, text=True, timeout=600,
    )
    return "relaunch"


def _select_tools(tools: list[str]) -> list[str]:
    """Interactive tool selection: show numbered list and let user pick."""
    print("\n  Available tools to install:")
    for i, tool in enumerate(tools, 1):
        print(f"    [{i}] {tool}")
    print()
    raw = input("  Enter numbers separated by commas (e.g. 1,3,5): ").strip()
    selected = []
    for part in raw.split(","):
        part = part.strip()
        if part.isdigit():
            idx = int(part) - 1
            if 0 <= idx < len(tools):
                selected.append(tools[idx])
    return selected


def prompt_install_missing(missing_tools: list[str]) -> list[str]:
    """Prompt user about missing tools. Returns list of tools to install."""
    if not missing_tools:
        return []

    print(f"\n  {len(missing_tools)} tool(s) missing: {', '.join(missing_tools)}")
    print("  [1] Install all")
    print("  [2] Select which to install")
    print("  [3] Skip")
    choice = input("  Choice [1/2/3]: ").strip()

    if choice == "1":
        return list(missing_tools)
    elif choice == "2":
        return _select_tools(missing_tools)
    else:
        return []


class ToolChecker:
    """Main entry point for cross-platform tool checking and installation."""

    def run(self) -> dict[str, bool]:
        """Detect OS, check tools, prompt to install missing, return final status."""
        # Step 1: Detect platform
        platform_info = detect_platform()
        logger.info("Platform: %s", platform_info)

        # Step 2: Windows WSL handling
        wsl_result = handle_windows_wsl(platform_info)
        if wsl_result == "relaunch":
            os.execvp("wsl", [
                "wsl", "-d", "kali-linux", "python3",
                sys.argv[0], *sys.argv[1:],
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
                installed = 0
                failed = 0
                for tool_name in to_install:
                    print(f"  Installing {tool_name}...", end=" ", flush=True)
                    success = installer.install_with_escalation(tool_name)
                    if success:
                        print("\u2713 done")
                        installed += 1
                    else:
                        print("\u2717 failed")
                        failed += 1

                # Re-check after installs
                tool_status = check_tools()
                still_missing = sum(1 for v in tool_status.values() if not v)
                if still_missing == len(tool_status):
                    print("\n  Without any tools installed, WSTG-Orc cannot operate.")
                    print("  Please install tools manually and try again. Goodbye!")
                    sys.exit(0)
                elif still_missing:
                    print(f"\n  {installed} installed, {failed} failed. {still_missing} tool(s) still unavailable.")
                else:
                    print("\n  All tools installed successfully!")

        return tool_status
