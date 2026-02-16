import os
import platform
import pytest
from unittest.mock import patch, mock_open, MagicMock
from wstg_orchestrator.utils.tool_checker import (
    PlatformInfo, detect_platform, TOOL_REGISTRY, check_tools, format_summary_table,
    ToolInstaller, handle_windows_wsl, prompt_install_missing, ToolChecker,
)


class TestDetectPlatform:
    @patch("platform.system", return_value="Linux")
    @patch("builtins.open", mock_open(read_data='ID=kali\nVERSION_ID="2025.1"\n'))
    @patch("os.path.exists", return_value=True)
    @patch("shutil.which", return_value="/usr/bin/apt")
    def test_detects_kali_linux(self, mock_which, mock_exists, mock_sys):
        info = detect_platform()
        assert info.os_type == "linux"
        assert info.distro == "kali"
        assert info.pkg_manager == "apt"
        assert info.is_wsl is False

    @patch("platform.system", return_value="Linux")
    @patch("builtins.open", mock_open(read_data='ID=ubuntu\nVERSION_ID="22.04"\n'))
    @patch("os.path.exists", return_value=True)
    @patch("shutil.which", return_value="/usr/bin/apt")
    def test_detects_ubuntu_linux(self, mock_which, mock_exists, mock_sys):
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
        mock_exists.return_value = True
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
    def test_detects_fedora(self, mock_which, mock_exists, mock_sys):
        info = detect_platform()
        assert info.distro == "fedora"
        assert info.pkg_manager == "dnf"

    @patch("platform.system", return_value="Linux")
    @patch("builtins.open", mock_open(read_data='ID=arch\n'))
    @patch("os.path.exists", return_value=True)
    @patch("shutil.which", return_value="/usr/bin/pacman")
    def test_detects_arch(self, mock_which, mock_exists, mock_sys):
        info = detect_platform()
        assert info.distro == "arch"
        assert info.pkg_manager == "pacman"


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


class TestCheckTools:
    @patch("shutil.which")
    @patch("os.path.isdir", return_value=True)
    def test_all_tools_found(self, mock_isdir, mock_which):
        mock_which.return_value = "/usr/bin/tool"
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
        assert "Found" in output or "\u2713" in output

    def test_table_shows_missing_tools(self):
        info = PlatformInfo(os_type="linux", distro="kali", pkg_manager="apt")
        status = {"nmap": False}
        output = format_summary_table(info, status)
        assert "nmap" in output
        assert "Missing" in output or "\u2717" in output

    def test_table_shows_counts(self):
        info = PlatformInfo(os_type="linux", distro="kali", pkg_manager="apt")
        status = {"nmap": True, "subfinder": True, "sqlmap": False}
        output = format_summary_table(info, status)
        assert "2" in output
        assert "1" in output


class TestToolInstaller:
    def test_get_install_command_prefers_go(self):
        """Go tools with go available should prefer go install."""
        info = PlatformInfo(os_type="linux", distro="kali", pkg_manager="apt")
        installer = ToolInstaller(info)
        with patch("shutil.which", return_value="/usr/bin/go"):
            cmd, method = installer.get_install_command("subfinder")
        assert method == "go"
        assert "go install" in cmd

    def test_get_install_command_falls_back_to_pkg_manager(self):
        """Tools with no language installer should use system pkg manager."""
        info = PlatformInfo(os_type="linux", distro="kali", pkg_manager="apt")
        installer = ToolInstaller(info)
        cmd, method = installer.get_install_command("nmap")
        assert method == "apt"
        assert "nmap" in cmd

    def test_get_install_command_prefers_pip(self):
        """pip-based tools should use pip when available."""
        info = PlatformInfo(os_type="linux", distro="kali", pkg_manager="apt")
        installer = ToolInstaller(info)
        with patch("shutil.which", return_value="/usr/bin/pip3"):
            cmd, method = installer.get_install_command("altdns")
        assert method == "pip"

    def test_get_install_command_brew_on_macos(self):
        """macOS should use brew."""
        info = PlatformInfo(os_type="macos", distro="macos", pkg_manager="brew")
        installer = ToolInstaller(info)
        cmd, method = installer.get_install_command("nmap")
        assert method == "brew"

    def test_get_install_command_returns_none_when_no_method(self):
        """Tool with only apt/brew installs but wrong platform -> None."""
        info = PlatformInfo(os_type="linux", distro="unknown", pkg_manager="")
        installer = ToolInstaller(info)
        with patch("shutil.which", return_value=None):
            result = installer.get_install_command("whatweb")
        assert result is None

    @patch("subprocess.run")
    def test_install_tool_success(self, mock_run):
        mock_run.return_value = type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        info = PlatformInfo(os_type="linux", distro="kali", pkg_manager="apt")
        installer = ToolInstaller(info)
        with patch("shutil.which", return_value="/usr/bin/go"):
            result = installer.install_tool("subfinder")
        assert result is True

    @patch("subprocess.run")
    def test_install_tool_fallback_when_go_missing(self, mock_run):
        """When go is not available, should try apt fallback for subfinder."""
        mock_run.return_value = type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        info = PlatformInfo(os_type="linux", distro="kali", pkg_manager="apt")
        installer = ToolInstaller(info)
        with patch("shutil.which", return_value=None):
            result = installer.install_tool("subfinder")
        assert result is True


class TestWindowsWSL:
    def test_noop_on_linux(self):
        info = PlatformInfo(os_type="linux", distro="kali", pkg_manager="apt")
        result = handle_windows_wsl(info)
        assert result is None

    @patch("subprocess.run", side_effect=FileNotFoundError("wsl not found"))
    def test_exits_when_no_wsl(self, mock_run):
        info = PlatformInfo(os_type="windows", distro="windows", pkg_manager="")
        with pytest.raises(SystemExit):
            handle_windows_wsl(info)

    @patch("subprocess.run")
    def test_detects_wsl_with_kali(self, mock_run):
        def run_side_effect(cmd, **kwargs):
            if "--status" in cmd:
                return type("R", (), {"returncode": 0, "stdout": "Default Version: 2", "stderr": ""})()
            if "-l" in cmd:
                return type("R", (), {"returncode": 0, "stdout": "kali-linux\nUbuntu\n", "stderr": ""})()
            return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        mock_run.side_effect = run_side_effect
        info = PlatformInfo(os_type="windows", distro="windows", pkg_manager="")
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


class TestPromptInstallMissing:
    @patch("builtins.input", return_value="3")
    def test_skip_returns_empty(self, mock_input):
        result = prompt_install_missing(["nmap", "sqlmap"])
        assert result == []

    @patch("builtins.input", return_value="1")
    def test_install_all_returns_all(self, mock_input):
        result = prompt_install_missing(["nmap", "sqlmap"])
        assert result == ["nmap", "sqlmap"]

    def test_no_missing_returns_empty(self):
        result = prompt_install_missing([])
        assert result == []


class TestEscalationChain:
    @patch("builtins.input", return_value="y")
    @patch("subprocess.run")
    @patch("shutil.which")
    def test_offers_to_install_go_when_missing(self, mock_which, mock_run, mock_input):
        call_count = {"n": 0}
        def which_side_effect(name):
            call_count["n"] += 1
            if name == "go":
                return "/usr/bin/go" if call_count["n"] > 3 else None
            if name in ("pip3", "pip", "cargo"):
                return None
            return None
        mock_which.side_effect = which_side_effect
        mock_run.return_value = type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        info = PlatformInfo(os_type="linux", distro="kali", pkg_manager="apt")
        installer = ToolInstaller(info)
        result = installer.install_with_escalation("subfinder")
        assert result is True

    @patch("builtins.input", return_value="n")
    @patch("subprocess.run")
    @patch("shutil.which", return_value=None)
    def test_falls_back_to_pkg_manager_when_declined(self, mock_which, mock_run, mock_input):
        mock_run.return_value = type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        info = PlatformInfo(os_type="linux", distro="kali", pkg_manager="apt")
        installer = ToolInstaller(info)
        result = installer.install_with_escalation("subfinder")
        assert result is True

    @patch("builtins.input", return_value="n")
    @patch("shutil.which", return_value=None)
    def test_returns_false_when_no_options(self, mock_which, mock_input):
        info = PlatformInfo(os_type="linux", distro="unknown", pkg_manager="")
        installer = ToolInstaller(info)
        result = installer.install_with_escalation("assetfinder")
        assert result is False


class TestToolCheckerRun:
    @patch("wstg_orchestrator.utils.tool_checker.handle_windows_wsl", return_value=None)
    @patch("wstg_orchestrator.utils.tool_checker.detect_platform")
    @patch("wstg_orchestrator.utils.tool_checker.check_tools")
    @patch("wstg_orchestrator.utils.tool_checker.format_summary_table", return_value="table")
    @patch("builtins.print")
    def test_run_returns_tool_status_when_all_found(self, mock_print, mock_table, mock_check, mock_detect, mock_wsl):
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
