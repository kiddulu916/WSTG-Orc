# tests/test_cli_handler.py
import pytest
from unittest.mock import patch, MagicMock


def test_cli_input_returns_user_input():
    """cli_input returns stripped user input."""
    with patch("builtins.input", return_value="  hello  "):
        from wstg_orchestrator.utils.cli_handler import cli_input
        result = cli_input("prompt: ")
    assert result == "hello"


def test_cli_input_enables_readline():
    """cli_input calls readline.parse_and_bind to enable key bindings."""
    mock_readline = MagicMock()
    with patch.dict("sys.modules", {"readline": mock_readline}):
        with patch("builtins.input", return_value="test"):
            from importlib import reload
            import wstg_orchestrator.utils.cli_handler as mod
            reload(mod)
            mod.cli_input("prompt: ")
    mock_readline.parse_and_bind.assert_called()


def test_cli_input_loads_history_file(tmp_path):
    """cli_input loads history from file when provided."""
    history_file = str(tmp_path / ".history")
    with open(history_file, "w") as f:
        f.write("previous_entry\n")
    mock_readline = MagicMock()
    with patch.dict("sys.modules", {"readline": mock_readline}):
        with patch("builtins.input", return_value="test"):
            from importlib import reload
            import wstg_orchestrator.utils.cli_handler as mod
            reload(mod)
            mod.cli_input("prompt: ", history_file=history_file)
    mock_readline.read_history_file.assert_called_with(history_file)


def test_cli_input_saves_history_file(tmp_path):
    """cli_input saves history to file after input when provided."""
    history_file = str(tmp_path / ".history")
    mock_readline = MagicMock()
    with patch.dict("sys.modules", {"readline": mock_readline}):
        with patch("builtins.input", return_value="test"):
            from importlib import reload
            import wstg_orchestrator.utils.cli_handler as mod
            reload(mod)
            mod.cli_input("prompt: ", history_file=history_file)
    mock_readline.write_history_file.assert_called_with(history_file)


def test_cli_input_no_history_file_skips_history():
    """cli_input does not load/save history when no file is provided."""
    mock_readline = MagicMock()
    with patch.dict("sys.modules", {"readline": mock_readline}):
        with patch("builtins.input", return_value="test"):
            from importlib import reload
            import wstg_orchestrator.utils.cli_handler as mod
            reload(mod)
            mod.cli_input("prompt: ")
    mock_readline.read_history_file.assert_not_called()
    mock_readline.write_history_file.assert_not_called()


def test_cli_input_works_without_readline():
    """cli_input works when readline is not available."""
    with patch.dict("sys.modules", {"readline": None}):
        with patch("builtins.input", return_value="  fallback  "):
            from importlib import reload
            import wstg_orchestrator.utils.cli_handler as mod
            reload(mod)
            result = mod.cli_input("prompt: ")
    assert result == "fallback"
