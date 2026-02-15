# wstg_orchestrator/utils/cli_handler.py
import signal
import sys
import threading

try:
    import readline
except ImportError:
    readline = None


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
