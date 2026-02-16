import os
import platform
import pytest
from unittest.mock import patch, mock_open, MagicMock
from wstg_orchestrator.utils.tool_checker import PlatformInfo, detect_platform


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
