import logging
import os
import platform
import shutil
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


def _detect_wsl() -> bool:
    try:
        if os.path.exists("/proc/version"):
            with open("/proc/version") as f:
                content = f.read().lower()
                return "microsoft" in content or "wsl" in content
    except OSError:
        pass
    return False
