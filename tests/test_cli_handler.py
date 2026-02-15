# tests/test_cli_handler.py
import signal
import threading

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


class TestSignalHandler:
    def _make_handler(self, tmp_path):
        """Helper to create a SignalHandler with a mock StateManager."""
        from wstg_orchestrator.utils.cli_handler import SignalHandler
        state = MagicMock()
        handler = SignalHandler(
            state_manager=state,
            config_path=str(tmp_path / "config.yaml"),
            state_path=str(tmp_path / "state.json"),
            evidence_dir=str(tmp_path / "evidence"),
        )
        return handler, state

    def test_initial_state_not_paused(self, tmp_path):
        handler, _ = self._make_handler(tmp_path)
        assert handler.is_paused() is False

    def test_handle_sigint_sets_paused(self, tmp_path):
        handler, state = self._make_handler(tmp_path)
        with patch("builtins.input", return_value="n"):
            handler.handle_sigint(signal.SIGINT, None)
        assert handler.is_paused() is False  # resumed after "n"
        state.save.assert_called()

    def test_handle_sigint_abort_on_yes(self, tmp_path):
        handler, state = self._make_handler(tmp_path)
        with patch("builtins.input", return_value="y"):
            with pytest.raises(SystemExit):
                handler.handle_sigint(signal.SIGINT, None)
        # save called at least twice: once on pause, once before exit
        assert state.save.call_count >= 2

    def test_handle_sigint_resume_on_no(self, tmp_path):
        handler, state = self._make_handler(tmp_path)
        with patch("builtins.input", return_value="n"):
            handler.handle_sigint(signal.SIGINT, None)
        assert handler.is_paused() is False
        state.save.assert_called()

    def test_resume_instructions_contain_paths(self, tmp_path, capsys):
        handler, _ = self._make_handler(tmp_path)
        with patch("builtins.input", return_value="y"):
            with pytest.raises(SystemExit):
                handler.handle_sigint(signal.SIGINT, None)
        captured = capsys.readouterr()
        assert "python main.py" in captured.out
        assert str(tmp_path / "config.yaml") in captured.out
        assert str(tmp_path / "state.json") in captured.out
        assert str(tmp_path / "evidence") in captured.out

    def test_register_installs_signal_handler(self, tmp_path):
        handler, _ = self._make_handler(tmp_path)
        with patch("signal.signal") as mock_signal:
            handler.register()
        mock_signal.assert_called_once_with(signal.SIGINT, handler.handle_sigint)

    def test_force_exit_on_second_sigint_while_paused(self, tmp_path):
        handler, state = self._make_handler(tmp_path)
        handler._paused = True
        handler._force_exit = True
        with pytest.raises(SystemExit):
            handler.handle_sigint(signal.SIGINT, None)


class TestKeyListener:
    def _make_listener(self, tmp_path):
        from wstg_orchestrator.utils.cli_handler import KeyListener, SignalHandler
        state = MagicMock()
        state.get.return_value = []
        state._state = {
            "completed_phases": {
                "reconnaissance": {"completed": True, "subcategories": {}},
            },
            "discovered_subdomains": ["a.example.com", "b.example.com"],
            "live_hosts": ["a.example.com"],
            "endpoints": ["/api/v1", "/login"],
            "potential_vulnerabilities": [],
            "confirmed_vulnerabilities": [],
        }
        signal_handler = SignalHandler(
            state_manager=state,
            config_path=str(tmp_path / "config.yaml"),
            state_path=str(tmp_path / "state.json"),
            evidence_dir=str(tmp_path / "evidence"),
        )
        orchestrator = MagicMock()
        orchestrator.state = state
        orchestrator.current_phase = "fingerprinting"
        listener = KeyListener(orchestrator, signal_handler)
        return listener, orchestrator, signal_handler, state

    def test_render_menu_contains_all_options(self, tmp_path):
        listener, _, _, _ = self._make_listener(tmp_path)
        menu = listener.render_menu()
        assert "View status" in menu
        assert "Skip current phase" in menu
        assert "Pause" in menu
        assert "Abort" in menu
        assert "Dismiss" in menu

    def test_render_menu_shows_resume_when_paused(self, tmp_path):
        listener, _, signal_handler, _ = self._make_listener(tmp_path)
        signal_handler._paused = True
        menu = listener.render_menu()
        assert "Resume" in menu

    def test_handle_selection_view_status(self, tmp_path, capsys):
        listener, orch, _, _ = self._make_listener(tmp_path)
        listener.handle_selection(1)
        captured = capsys.readouterr()
        assert "fingerprinting" in captured.out
        assert "reconnaissance" in captured.out

    def test_handle_selection_skip_phase(self, tmp_path):
        listener, orch, _, _ = self._make_listener(tmp_path)
        listener.handle_selection(2)
        assert orch._skip_phase is True

    def test_handle_selection_pause(self, tmp_path):
        listener, _, signal_handler, state = self._make_listener(tmp_path)
        listener.handle_selection(3)
        assert signal_handler.is_paused() is True
        state.save.assert_called()

    def test_handle_selection_unpause(self, tmp_path):
        listener, _, signal_handler, _ = self._make_listener(tmp_path)
        signal_handler._paused = True
        listener.handle_selection(3)
        assert signal_handler.is_paused() is False

    def test_handle_selection_abort(self, tmp_path):
        listener, _, _, state = self._make_listener(tmp_path)
        with pytest.raises(SystemExit):
            listener.handle_selection(4)
        state.save.assert_called()

    def test_get_status_text(self, tmp_path, capsys):
        listener, _, _, _ = self._make_listener(tmp_path)
        listener.handle_selection(1)
        captured = capsys.readouterr()
        assert "Subdomains: 2" in captured.out
        assert "Live hosts: 1" in captured.out
        assert "Endpoints: 2" in captured.out
