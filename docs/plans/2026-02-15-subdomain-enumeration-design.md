# Subdomain Enumeration Expansion — Design

## Overview

Expand the `passive_osint` subcategory to run multiple subdomain enumeration tools in parallel, followed by altdns permutation generation and puredns resolution.

## Architecture

### Two-Phase Execution

**Phase 1 — Parallel Discovery (`asyncio.gather`):**
- `subfinder -d <domain> -silent` (existing)
- `assetfinder --subs-only <domain>`
- `curl -s 'https://crt.sh/?q=%25.<domain>&output=json' | jq -r '.[].name_value'`
- `amass enum -passive -d <domain>` (promoted from fallback to standalone)
- `github-subdomains -d <domain> -t <token>`
- `gitlab-subdomains -d <domain> -t <token>`

All tools run concurrently for each target domain. Results are merged, deduplicated, and scope-filtered.

**Phase 2 — Permutation + Resolution (sequential):**
1. `altdns -i <phase1_subdomains> -o <permutations> -w <wordlist>` — generates permuted subdomains
2. `puredns resolve <permutations> --resolvers <resolvers_file>` — resolves and filters wildcards
3. Valid resolved subdomains added to `discovered_subdomains` state

Phase 2 is skipped entirely if Phase 1 produces no results.

## Tool Details

### assetfinder
- Command: `assetfinder --subs-only <domain>`
- Output: one subdomain per line
- Timeout: 120s

### crt.sh
- Command: `curl -s 'https://crt.sh/?q=%25.<domain>&output=json' | jq -r '.[].name_value'`
- Executed via `CommandRunner.run_pipeline()` (new method, `shell=True`)
- Requires both `curl` and `jq` — check each independently, prompt to install if missing
- Timeout: 120s

### github-subdomains
- Command: `github-subdomains -d <domain> -t <token>`
- Token resolution order:
  1. `tool_configs.github_subdomains.token` in config YAML
  2. `GITHUB_TOKEN` environment variable
  3. Interactive prompt: warn user, ask for token input
     - If token entered: save to `tool_configs.github_subdomains.token` in config YAML, proceed
     - If blank: skip tool with warning

### gitlab-subdomains
- Command: `gitlab-subdomains -d <domain> -t <token>`
- Same token resolution as github-subdomains:
  1. `tool_configs.gitlab_subdomains.token` in config YAML
  2. `GITLAB_TOKEN` environment variable
  3. Interactive prompt with config persistence or skip

### amass
- Command: `amass enum -passive -d <domain>`
- No longer a subfinder fallback — runs as standalone parallel tool
- Timeout: 600s (amass is slow)

### altdns
- Command: `altdns -i <input_file> -o <output_file> -w <wordlist>`
- Input: temp file of Phase 1 deduplicated subdomains
- Wordlist: defaults to bundled `data/altdns-words.txt`, overridable via `tool_configs.altdns.wordlist`
- Timeout: 300s
- Prompt to install if missing

### puredns
- Command: `puredns resolve <permutations_file> --resolvers <resolvers_file>`
- Resolvers: defaults to bundled `data/resolvers.txt`, overridable via `tool_configs.puredns.resolvers`
- Timeout: 300s
- Prompt to install if missing
- If puredns is missing: do NOT add unresolved permutations to discovered_subdomains (too noisy)

## File Changes

### Modified
- **`wstg_orchestrator/modules/reconnaissance.py`**
  - Refactor `_passive_osint` into parallel Phase 1 + sequential Phase 2
  - Add methods: `_run_assetfinder`, `_run_crtsh`, `_run_github_subdomains`, `_run_gitlab_subdomains`, `_run_altdns`, `_run_puredns`
  - Refactor `_run_amass` to be standalone (remove fallback coupling from subfinder)
  - Add `_resolve_tool_token` helper for github/gitlab token resolution
  - Update `TOOL_INSTALL_COMMANDS` dict with all new tools

- **`wstg_orchestrator/utils/command_runner.py`**
  - Add `run_pipeline(description, command, timeout)` method for shell pipelines
  - Returns same `CommandResult` dataclass

- **`wstg_orchestrator/utils/config_loader.py`**
  - Add method to update/persist `tool_configs` entries (for saving API tokens)

### New Files
- **`data/altdns-words.txt`** — Default permutation wordlist
- **`data/resolvers.txt`** — Default DNS resolvers list for puredns

### Unchanged
- `base_module.py`, `main.py`, orchestrator wiring — subcategory name stays `passive_osint`

## Error Handling

- **Tool missing:** Prompt to install via `_prompt_install_tool`. If declined, skip that tool. Others continue.
- **All Phase 1 tools missing/skipped:** Log warning, subcategory completes with empty results. Phase 2 skipped.
- **crt.sh API down:** Non-zero curl exit or empty output — log warning, continue.
- **altdns missing:** Prompt install. If declined, skip Phase 2 entirely.
- **puredns missing:** Prompt install. If declined, do not add unresolved permutations. Phase 2 produces no results.
- **Token tools with no token:** Prompt user for token. If blank, skip tool.

## Timeouts
| Tool | Timeout |
|------|---------|
| subfinder | 300s |
| assetfinder | 120s |
| crt.sh | 120s |
| github-subdomains | 120s |
| gitlab-subdomains | 120s |
| amass | 600s |
| altdns | 300s |
| puredns | 300s |
