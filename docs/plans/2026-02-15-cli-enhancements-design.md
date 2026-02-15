# CLI Enhancements Design

## Summary

Add interactive CLI capabilities to WSTG-Orc: graceful Ctrl+C handling with pause/resume, a hotkey-triggered action menu during scans, and readline-enhanced input prompts with arrow key support.

## Goals

1. Ctrl+C pauses the scan, saves state, and asks the user whether to abort or resume
2. A `?` hotkey opens an overlay menu during scans with actions: view status, skip phase, pause/resume, abort
3. All input prompts support arrow key cursor movement and line editing

## Constraints

- Stdlib only (no new dependencies) — uses `readline`, `tty`, `termios`, `signal`, `atexit`
- Linux/macOS only (`termios` is not available on Windows)
- Must not interfere with the existing async scan execution
- Terminal settings must always be restored, even on crash

## Architecture

### New file: `wstg_orchestrator/utils/cli_handler.py`

Contains three components:

#### 1. `SignalHandler`

Manages SIGINT (Ctrl+C) with pause/resume semantics.

```
class SignalHandler:
    __init__(state_manager, config_path, state_path, evidence_dir)
    handle_sigint(signum, frame)  # SIGINT handler
    is_paused() -> bool
    wait_for_resume()             # Blocking; prompts user y/n
    _print_resume_instructions()  # Shows exact resume command
```

**Behavior:**
- First Ctrl+C: sets `paused` flag, saves state immediately, prompts "Abort scan? (y/n)"
- User enters `y`: saves state again, prints resume command, raises SystemExit
- User enters `n`: clears `paused` flag, scan continues from where it was
- Second Ctrl+C while paused: immediate forced exit (safety hatch)

**Resume instructions format:**
```
State saved. To resume, run:
  python main.py -c <config_path> -s <state_path> -e <evidence_dir>
```

#### 2. `KeyListener`

Daemon thread that reads keypresses in raw terminal mode during scans.

```
class KeyListener:
    __init__(orchestrator, signal_handler)
    start()              # Starts daemon thread, switches to raw mode
    stop()               # Restores terminal, joins thread
    _listen_loop()       # Reads keys, dispatches actions
    _show_menu()         # Renders overlay
    _handle_selection(n) # Executes menu action
```

**Hotkey trigger:** `?` key opens the menu overlay.

**Menu overlay:**
```
+-- WSTG-Orc --------------------------+
|  [1] View status                      |
|  [2] Skip current phase               |
|  [3] Pause / Resume                   |
|  [4] Abort (save & exit)              |
|  [Esc] Dismiss                        |
+---------------------------------------+
```

Navigation: arrow keys move highlight, Enter selects, 1-4 direct select, Esc dismisses.

**Actions:**
- **View status**: Prints current phase, completed phases, subcategory progress, discovery counts (subdomains, endpoints, vulns). Non-blocking.
- **Skip phase**: Sets a cancellation flag checked by the orchestrator after the current module's `run()` returns. Phase marked as skipped (not complete) in state.
- **Pause/Resume**: Toggles pause state. Same mechanism as Ctrl+C pause but without abort prompt.
- **Abort**: Saves state, prints resume instructions, exits. Identical to confirming Ctrl+C abort.

**Terminal safety:**
- Saves original `termios` settings before switching to raw mode
- Restores in `stop()`, in a `finally` block around the listen loop, and via `atexit.register()`
- Triple redundancy prevents leaving terminal in raw mode

#### 3. `cli_input(prompt, history_file=None)`

Drop-in replacement for `input()` with readline support.

```
def cli_input(prompt: str, history_file: str = None) -> str
```

- Configures `readline` for the call (tab completion off, history loaded if file provided)
- Supports: left/right arrow keys, Home/End, backspace/delete, up/down history navigation
- Optional persistent history file (useful for scope builder to recall previous domains)

### Modified files

#### `main.py`

- Import `SignalHandler`, `KeyListener` from `cli_handler`
- In `main()`: create `SignalHandler` with state/config references, register it before `asyncio.run()`
- Create `KeyListener`, start before scan, stop after scan (in finally block)
- Pass `signal_handler` to `Orchestrator`

#### `Orchestrator.run()` in `main.py`

- Accept `signal_handler` parameter
- After each `await module.run()`, check `if signal_handler.is_paused(): signal_handler.wait_for_resume()`
- This is the natural safe pause point: between phases, never mid-HTTP-request

#### `wstg_orchestrator/scope_builder.py`

- Replace `input()` calls with `cli_input()` from `cli_handler`
- No history file needed (scope building is typically a one-time operation)

### Files NOT modified

- `wstg_orchestrator/modules/base_module.py` — pause points are at orchestrator level, not inside modules
- `wstg_orchestrator/state_manager.py` — already has `save()` method, no changes needed
- Test files — existing tests unchanged; new tests added for `cli_handler`

## Data flow

```
User presses Ctrl+C
  -> SignalHandler.handle_sigint()
    -> state.save()
    -> prompt "Abort? (y/n)"
      -> y: save, print resume cmd, SystemExit
      -> n: clear pause flag, orchestrator continues

User presses ? during scan
  -> KeyListener._listen_loop() detects '?'
    -> _show_menu() renders overlay
    -> user selects action via arrow keys + Enter (or 1-4)
    -> _handle_selection() dispatches action

Orchestrator.run() loop:
  for phase in EXECUTION_ORDER:
    if phase complete: skip
    await module.run()
    if signal_handler.is_paused():
      signal_handler.wait_for_resume()  # blocks until user decides
```

## Testing strategy

- `SignalHandler`: mock `signal.signal`, simulate SIGINT by calling handler directly, mock `input()` for y/n prompt, verify state.save() called, verify SystemExit on confirm
- `KeyListener`: integration test only (requires terminal); unit test the action handlers by calling `_handle_selection()` directly with mocked orchestrator
- `cli_input`: verify readline configuration via mock; functional testing requires interactive terminal
- Menu rendering: test string output of `_show_menu()` against expected format
