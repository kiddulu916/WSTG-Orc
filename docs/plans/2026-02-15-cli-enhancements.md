# CLI Enhancements Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add graceful Ctrl+C handling (pause/resume/abort with state save), a hotkey-triggered action menu during scans, and readline-enhanced input prompts with arrow key support.

**Architecture:** A single new module `wstg_orchestrator/utils/cli_handler.py` contains three components: `SignalHandler` (SIGINT pause/resume), `KeyListener` (daemon thread for hotkey menu), and `cli_input()` (readline-enhanced input). The orchestrator gains a `signal_handler` parameter and checks pause state between phases. The scope builder replaces `input()` with `cli_input()`.

**Tech Stack:** Python stdlib only — `signal`, `threading`, `readline`, `sys`, `os`, `tty`, `termios`, `atexit`, `select`

**Design doc:** `docs/plans/2026-02-15-cli-enhancements-design.md`

---

### Task 1: `cli_input()` — readline-enhanced input function

**Files:**
- Create: `wstg_orchestrator/utils/cli_handler.py`
- Test: `tests/test_cli_handler.py`

**Step 1: Write the failing test**

```python
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
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_cli_handler.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'wstg_orchestrator.utils.cli_handler'`

**Step 3: Write minimal implementation**

```python
# wstg_orchestrator/utils/cli_handler.py
import sys

try:
    import readline
except ImportError:
    readline = None


def cli_input(prompt: str, history_file: str = None) -> str:
    """readline-enhanced input() replacement with arrow key support."""
    if readline is not None:
        readline.parse_and_bind("tab: complete")
        readline.parse_and_bind('"\e[A": previous-history')
        readline.parse_and_bind('"\e[B": next-history')
        readline.parse_and_bind('"\e[C": forward-char')
        readline.parse_and_bind('"\e[D": backward-char')
        readline.parse_and_bind('"\e[H": beginning-of-line')
        readline.parse_and_bind('"\e[F": end-of-line')
        if history_file:
            try:
                readline.read_history_file(history_file)
            except FileNotFoundError:
                pass
    result = input(prompt).strip()
    if readline is not None and history_file:
        readline.write_history_file(history_file)
    return result
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cli_handler.py -v`
Expected: All 5 tests PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/utils/cli_handler.py tests/test_cli_handler.py
git commit -m "feat: add cli_input() with readline arrow key support"
```

---

### Task 2: `SignalHandler` — Ctrl+C pause/resume/abort

**Files:**
- Modify: `wstg_orchestrator/utils/cli_handler.py`
- Test: `tests/test_cli_handler.py`

**Step 1: Write the failing tests**

Append to `tests/test_cli_handler.py`:

```python
import signal
import threading


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
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_cli_handler.py::TestSignalHandler -v`
Expected: FAIL — `ImportError: cannot import name 'SignalHandler'`

**Step 3: Write minimal implementation**

Add to `wstg_orchestrator/utils/cli_handler.py`:

```python
import signal
import threading


class SignalHandler:
    def __init__(self, state_manager, config_path: str, state_path: str, evidence_dir: str):
        self._state = state_manager
        self._config_path = config_path
        self._state_path = state_path
        self._evidence_dir = evidence_dir
        self._paused = False
        self._force_exit = False
        self._lock = threading.Lock()

    def register(self):
        signal.signal(signal.SIGINT, self.handle_sigint)

    def is_paused(self) -> bool:
        return self._paused

    def handle_sigint(self, signum, frame):
        if self._paused and self._force_exit:
            self._state.save()
            raise SystemExit(1)

        self._paused = True
        self._force_exit = True
        self._state.save()

        print("\n\nScan paused. State saved.")
        try:
            answer = input("Abort scan? (y/n): ").strip().lower()
        except EOFError:
            answer = "y"

        if answer == "y":
            self._state.save()
            self._print_resume_instructions()
            raise SystemExit(0)
        else:
            self._paused = False
            self._force_exit = False
            print("Resuming scan...\n")

    def _print_resume_instructions(self):
        print(f"\nState saved. To resume, run:")
        print(f"  python main.py -c {self._config_path} -s {self._state_path} -e {self._evidence_dir}\n")
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cli_handler.py -v`
Expected: All tests PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/utils/cli_handler.py tests/test_cli_handler.py
git commit -m "feat: add SignalHandler for Ctrl+C pause/resume/abort"
```

---

### Task 3: `KeyListener` — hotkey menu during scans

**Files:**
- Modify: `wstg_orchestrator/utils/cli_handler.py`
- Test: `tests/test_cli_handler.py`

**Step 1: Write the failing tests**

Append to `tests/test_cli_handler.py`:

```python
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
        assert orch.skip_current_phase is True or orch._skip_phase is True

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
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_cli_handler.py::TestKeyListener -v`
Expected: FAIL — `ImportError: cannot import name 'KeyListener'`

**Step 3: Write minimal implementation**

Add to `wstg_orchestrator/utils/cli_handler.py`:

```python
import atexit
import os
import select

try:
    import termios
    import tty
    HAS_TERMIOS = True
except ImportError:
    HAS_TERMIOS = False


class KeyListener:
    MENU_ITEMS = [
        "View status",
        "Skip current phase",
        "Pause / Resume",
        "Abort (save & exit)",
    ]

    def __init__(self, orchestrator, signal_handler):
        self._orch = orchestrator
        self._signal = signal_handler
        self._running = False
        self._thread = None
        self._old_settings = None

    def start(self):
        if not HAS_TERMIOS or not os.isatty(sys.stdin.fileno()):
            return
        self._running = True
        self._old_settings = termios.tcgetattr(sys.stdin)
        atexit.register(self._restore_terminal)
        self._thread = threading.Thread(target=self._listen_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        self._restore_terminal()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)

    def _restore_terminal(self):
        if self._old_settings is not None:
            try:
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self._old_settings)
            except (termios.error, ValueError):
                pass

    def _listen_loop(self):
        try:
            while self._running:
                if self._signal.is_paused():
                    import time
                    time.sleep(0.1)
                    continue
                try:
                    tty.setraw(sys.stdin.fileno())
                    if select.select([sys.stdin], [], [], 0.5)[0]:
                        ch = sys.stdin.read(1)
                        if ch == "?":
                            self._restore_terminal()
                            self._interactive_menu()
                    else:
                        self._restore_terminal()
                except (termios.error, ValueError, OSError):
                    break
        finally:
            self._restore_terminal()

    def _interactive_menu(self):
        selected = 0
        while True:
            menu = self.render_menu(highlight=selected)
            # Clear and redraw
            print(f"\033[2J\033[H{menu}", end="", flush=True)
            try:
                tty.setraw(sys.stdin.fileno())
                ch = sys.stdin.read(1)
                self._restore_terminal()
            except (termios.error, ValueError, OSError):
                self._restore_terminal()
                return

            if ch == "\x1b":  # Escape sequence
                try:
                    tty.setraw(sys.stdin.fileno())
                    if select.select([sys.stdin], [], [], 0.1)[0]:
                        ch2 = sys.stdin.read(1)
                        if ch2 == "[":
                            ch3 = sys.stdin.read(1)
                            if ch3 == "A":  # Up arrow
                                selected = (selected - 1) % len(self.MENU_ITEMS)
                            elif ch3 == "B":  # Down arrow
                                selected = (selected + 1) % len(self.MENU_ITEMS)
                    else:
                        # Bare Esc — dismiss
                        self._restore_terminal()
                        print("\033[2J\033[H", end="", flush=True)
                        return
                    self._restore_terminal()
                except (termios.error, ValueError, OSError):
                    self._restore_terminal()
                    return
            elif ch == "\r" or ch == "\n":  # Enter
                print("\033[2J\033[H", end="", flush=True)
                self.handle_selection(selected + 1)
                return
            elif ch in ("1", "2", "3", "4"):
                print("\033[2J\033[H", end="", flush=True)
                self.handle_selection(int(ch))
                return
            elif ch == "\x1b":  # Esc without sequence
                print("\033[2J\033[H", end="", flush=True)
                return

    def render_menu(self, highlight: int = -1) -> str:
        width = 40
        pause_label = "Resume" if self._signal.is_paused() else "Pause"
        items = list(self.MENU_ITEMS)
        items[2] = f"{pause_label} / {'Pause' if self._signal.is_paused() else 'Resume'}"

        lines = []
        lines.append(f"+-- WSTG-Orc {'-' * (width - 14)}+")
        for i, item in enumerate(items):
            marker = ">" if i == highlight else " "
            lines.append(f"|{marker} [{i+1}] {item:<{width - 7}}|")
        lines.append(f"|  [Esc] Dismiss{' ' * (width - 16)}|")
        lines.append(f"+{'-' * (width - 1)}+")
        return "\n".join(lines)

    def handle_selection(self, n: int):
        if n == 1:
            self._view_status()
        elif n == 2:
            self._skip_phase()
        elif n == 3:
            self._toggle_pause()
        elif n == 4:
            self._abort()

    def _view_status(self):
        state = self._orch.state._state
        current = getattr(self._orch, "current_phase", "unknown")
        completed = state.get("completed_phases", {})
        completed_names = [p for p, d in completed.items() if d.get("completed")]

        subs = len(state.get("discovered_subdomains", []))
        hosts = len(state.get("live_hosts", []))
        endpoints = len(state.get("endpoints", []))
        pot_vulns = len(state.get("potential_vulnerabilities", []))
        conf_vulns = len(state.get("confirmed_vulnerabilities", []))

        print("\n--- Scan Status ---")
        print(f"Current phase: {current}")
        print(f"Completed: {', '.join(completed_names) if completed_names else 'none'}")
        print(f"Subdomains: {subs}")
        print(f"Live hosts: {hosts}")
        print(f"Endpoints: {endpoints}")
        print(f"Potential vulns: {pot_vulns}")
        print(f"Confirmed vulns: {conf_vulns}")
        print("-------------------\n")

    def _skip_phase(self):
        self._orch._skip_phase = True
        print(f"Skipping current phase after it completes its current operation...\n")

    def _toggle_pause(self):
        if self._signal.is_paused():
            self._signal._paused = False
            print("Scan resumed.\n")
        else:
            self._signal._paused = True
            self._orch.state.save()
            print("Scan paused. State saved.\n")

    def _abort(self):
        self._orch.state.save()
        self._signal._print_resume_instructions()
        raise SystemExit(0)
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cli_handler.py -v`
Expected: All tests PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/utils/cli_handler.py tests/test_cli_handler.py
git commit -m "feat: add KeyListener with hotkey menu overlay"
```

---

### Task 4: Integrate `SignalHandler` and `KeyListener` into `main.py`

**Files:**
- Modify: `main.py:84-161` (Orchestrator class) and `main.py:163-303` (main function)
- Test: `tests/test_main.py`

**Step 1: Write the failing tests**

Append to `tests/test_main.py`:

```python
import asyncio


def test_orchestrator_run_checks_pause(config_file, tmp_dir):
    """Orchestrator.run() checks signal_handler pause state between phases."""
    orch = Orchestrator(
        config_path=config_file,
        state_path=os.path.join(tmp_dir, "state.json"),
        evidence_dir=os.path.join(tmp_dir, "evidence"),
    )
    signal_handler = MagicMock()
    signal_handler.is_paused.return_value = False

    mock_module = MagicMock()
    mock_module.run = AsyncMock()
    orch.register_module("reconnaissance", mock_module)

    with patch.object(orch, '_check_tools'):
        with patch.object(orch.callback_server, 'start'):
            with patch.object(orch.callback_server, 'stop'):
                asyncio.run(orch.run(signal_handler=signal_handler))

    signal_handler.is_paused.assert_called()


def test_orchestrator_run_without_signal_handler(config_file, tmp_dir):
    """Orchestrator.run() works without a signal_handler (backwards compat)."""
    orch = Orchestrator(
        config_path=config_file,
        state_path=os.path.join(tmp_dir, "state.json"),
        evidence_dir=os.path.join(tmp_dir, "evidence"),
    )
    mock_module = MagicMock()
    mock_module.run = AsyncMock()
    orch.register_module("reconnaissance", mock_module)

    with patch.object(orch, '_check_tools'):
        with patch.object(orch.callback_server, 'start'):
            with patch.object(orch.callback_server, 'stop'):
                asyncio.run(orch.run())
    mock_module.run.assert_called_once()


def test_orchestrator_skip_phase_flag(config_file, tmp_dir):
    """Orchestrator skips remaining phases when _skip_phase is set."""
    orch = Orchestrator(
        config_path=config_file,
        state_path=os.path.join(tmp_dir, "state.json"),
        evidence_dir=os.path.join(tmp_dir, "evidence"),
    )
    signal_handler = MagicMock()
    signal_handler.is_paused.return_value = False

    mock_recon = MagicMock()
    mock_recon.run = AsyncMock()
    mock_fingerprint = MagicMock()
    mock_fingerprint.run = AsyncMock()
    orch.register_module("reconnaissance", mock_recon)
    orch.register_module("fingerprinting", mock_fingerprint)

    # Simulate skip being set after recon runs
    async def set_skip():
        orch._skip_phase = True
    mock_recon.run = AsyncMock(side_effect=set_skip)

    with patch.object(orch, '_check_tools'):
        with patch.object(orch.callback_server, 'start'):
            with patch.object(orch.callback_server, 'stop'):
                asyncio.run(orch.run(signal_handler=signal_handler))

    mock_recon.run.assert_called_once()
    # fingerprinting should still run; skip only skips the phase that was running
    # The skip flag resets per phase
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_main.py -v`
Expected: FAIL — `run() got an unexpected keyword argument 'signal_handler'`

**Step 3: Modify `Orchestrator.run()` in `main.py`**

Change `Orchestrator` class in `main.py`:

Add `self._skip_phase = False` and `self.current_phase = None` to `__init__`, then update `run()`:

```python
    async def run(self, signal_handler=None):
        logger.info(f"Starting WSTG scan for {self.config.company_name}")
        logger.info(f"Target domain: {self.config.base_domain}")

        self._check_tools()
        self.callback_server.start()

        try:
            for phase_name in EXECUTION_ORDER:
                if self.state.is_phase_complete(phase_name):
                    logger.info(f"Skipping completed phase: {phase_name}")
                    continue

                self.current_phase = phase_name
                self._skip_phase = False

                module = self._get_module(phase_name)
                if module:
                    await module.run()
                    if self._skip_phase:
                        logger.info(f"Phase skipped by user: {phase_name}")
                        self._skip_phase = False
                        continue
                else:
                    logger.warning(f"No module registered for phase: {phase_name}")

                if signal_handler and signal_handler.is_paused():
                    signal_handler.wait_for_resume()
        finally:
            self.current_phase = None
            self.callback_server.stop()
            self.state.save()
            logger.info("Scan complete")
```

**Step 4: Modify `main()` function in `main.py`**

Update the `main()` function to wire up `SignalHandler` and `KeyListener`:

Add imports at the top of `main.py`:
```python
from wstg_orchestrator.utils.cli_handler import SignalHandler, KeyListener
```

Replace the `asyncio.run(orch.run())` section (lines 290-298) with:

```python
    signal_handler = SignalHandler(
        state_manager=orch.state,
        config_path=args.config,
        state_path=args.state,
        evidence_dir=args.evidence,
    )
    signal_handler.register()

    key_listener = KeyListener(orch, signal_handler)
    key_listener.start()

    try:
        asyncio.run(orch.run(signal_handler=signal_handler))
    finally:
        key_listener.stop()

    # Generate reports after scan completion
    logger.info("Generating reports...")
    report_gen = ReportGenerator(
        orch.state._state,
        orch.evidence_logger.get_reports_dir()
    )
    report_gen.generate_all()
    logger.info("Reports generated successfully.")
```

**Step 5: Run tests to verify they pass**

Run: `pytest tests/test_main.py tests/test_cli_handler.py -v`
Expected: All tests PASS

**Step 6: Commit**

```bash
git add main.py tests/test_main.py
git commit -m "feat: integrate SignalHandler and KeyListener into orchestrator"
```

---

### Task 5: Replace `input()` with `cli_input()` in scope builder

**Files:**
- Modify: `wstg_orchestrator/scope_builder.py`
- Test: `tests/test_scope_builder.py`

**Step 1: Run existing scope builder tests to confirm baseline**

Run: `pytest tests/test_scope_builder.py -v`
Expected: All 3 tests PASS (baseline)

**Step 2: Modify `scope_builder.py`**

Add import at the top of `wstg_orchestrator/scope_builder.py`:

```python
from wstg_orchestrator.utils.cli_handler import cli_input
```

Replace every `input(` call in `scope_builder.py` with `cli_input(`. There are 14 calls total (lines 9-49). Each follows the pattern:

- `input("Company name: ")` → `cli_input("Company name: ")`
- `input("Base domain (e.g., example.com): ")` → `cli_input("Base domain (e.g., example.com): ")`
- And so on for all 14 `input()` calls

**Step 3: Run tests to verify they still pass**

Run: `pytest tests/test_scope_builder.py -v`
Expected: All 3 tests PASS — because `cli_input` calls `input()` internally and the tests mock `builtins.input`. However, the test mocking pattern `patch("builtins.input", lambda prompt="": next(inputs))` will still work because `cli_input` calls `input()` under the hood.

**Step 4: Commit**

```bash
git add wstg_orchestrator/scope_builder.py
git commit -m "feat: replace input() with cli_input() in scope builder"
```

---

### Task 6: Run full test suite and verify no regressions

**Files:**
- No modifications

**Step 1: Run the full test suite**

Run: `pytest tests/ -v`
Expected: The same 5 pre-existing failures (test_config_loader, test_http_utils, test_scope_checker). No new failures.

**Step 2: Verify the 5 failures are pre-existing**

The known pre-existing failures are:
- `tests/test_config_loader.py::test_enumeration_domains`
- `tests/test_config_loader.py::test_enumeration_domains_deduplicates`
- `tests/test_config_loader.py::test_enumeration_domains_with_full_urls`
- `tests/test_http_utils.py::test_out_of_scope_raises`
- `tests/test_scope_checker.py::test_out_of_scope_no_base_domain`

If any NEW failures appear, fix them before proceeding.

**Step 3: Commit (only if any fixes were needed)**

```bash
git add -A
git commit -m "fix: resolve test regressions from CLI integration"
```

---

### Task 7: Update CLAUDE.md documentation

**Files:**
- Modify: `CLAUDE.md`

**Step 1: Add CLI handler documentation to CLAUDE.md**

In the **Architecture** section, after the **Entry point** paragraph, add:

```markdown
**CLI handler:** `wstg_orchestrator/utils/cli_handler.py` provides three components: `SignalHandler` (Ctrl+C pause/resume/abort with state persistence), `KeyListener` (daemon thread reading keypresses for `?` hotkey menu overlay during scans), and `cli_input()` (readline-enhanced `input()` replacement with arrow key support). The `KeyListener` uses `tty`/`termios` for raw mode and restores terminal settings via triple redundancy (stop method, finally block, atexit).
```

In the **Key patterns** section, add a new bullet:

```markdown
- **Graceful interrupts:** Ctrl+C pauses the scan between phases, saves state immediately, and prompts to abort or resume. Aborting prints the exact `python main.py -c ... -s ... -e ...` command to resume. A `?` hotkey opens a menu overlay during scans with: view status, skip phase, pause/resume, abort.
```

**Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: document CLI handler in CLAUDE.md"
```
