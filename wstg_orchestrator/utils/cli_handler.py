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
