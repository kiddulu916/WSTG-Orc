# wstg_orchestrator/utils/cli_handler.py
import atexit
import os
import select
import signal
import sys
import threading
import time

try:
    import readline
except ImportError:
    readline = None

try:
    import termios
    import tty
    HAS_TERMIOS = True
except ImportError:
    HAS_TERMIOS = False


def cli_input(prompt: str, history_file: str = None) -> str:
    """readline-enhanced input() replacement with arrow key support."""
    if readline is not None:
        readline.parse_and_bind("tab: complete")
        readline.parse_and_bind(r'"\e[A": previous-history')
        readline.parse_and_bind(r'"\e[B": next-history')
        readline.parse_and_bind(r'"\e[C": forward-char')
        readline.parse_and_bind(r'"\e[D": backward-char')
        readline.parse_and_bind(r'"\e[H": beginning-of-line')
        readline.parse_and_bind(r'"\e[F": end-of-line')
        if history_file:
            try:
                readline.read_history_file(history_file)
            except OSError:
                pass
    result = input(prompt).strip()
    if readline is not None and history_file:
        try:
            readline.write_history_file(history_file)
        except OSError:
            pass
    return result


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
        with self._lock:
            return self._paused

    def set_paused(self, value: bool):
        with self._lock:
            self._paused = value

    def handle_sigint(self, signum, frame):
        with self._lock:
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
            with self._lock:
                self._paused = False
                self._force_exit = False
            print("Resuming scan...\n")

    def _print_resume_instructions(self):
        print(f"\nState saved. To resume, run:")
        print(f"  python main.py -c {self._config_path} -s {self._state_path} -e {self._evidence_dir}\n")


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
            print(f"\033[2J\033[H{menu}", end="", flush=True)
            try:
                tty.setraw(sys.stdin.fileno())
                ch = sys.stdin.read(1)
                self._restore_terminal()
            except (termios.error, ValueError, OSError):
                self._restore_terminal()
                return

            if ch == "\x1b":
                try:
                    tty.setraw(sys.stdin.fileno())
                    if select.select([sys.stdin], [], [], 0.1)[0]:
                        ch2 = sys.stdin.read(1)
                        if ch2 == "[":
                            ch3 = sys.stdin.read(1)
                            if ch3 == "A":
                                selected = (selected - 1) % len(self.MENU_ITEMS)
                            elif ch3 == "B":
                                selected = (selected + 1) % len(self.MENU_ITEMS)
                    else:
                        self._restore_terminal()
                        print("\033[2J\033[H", end="", flush=True)
                        return
                    self._restore_terminal()
                except (termios.error, ValueError, OSError):
                    self._restore_terminal()
                    return
            elif ch == "\r" or ch == "\n":
                print("\033[2J\033[H", end="", flush=True)
                self.handle_selection(selected + 1)
                return
            elif ch in ("1", "2", "3", "4"):
                print("\033[2J\033[H", end="", flush=True)
                self.handle_selection(int(ch))
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
        print("Skipping current phase after it completes its current operation...\n")

    def _toggle_pause(self):
        if self._signal.is_paused():
            self._signal.set_paused(False)
            print("Scan resumed.\n")
        else:
            self._signal.set_paused(True)
            self._orch.state.save()
            print("Scan paused. State saved.\n")

    def _abort(self):
        self._orch.state.save()
        self._signal._print_resume_instructions()
        raise SystemExit(0)
