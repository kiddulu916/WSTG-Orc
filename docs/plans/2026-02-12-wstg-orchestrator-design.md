# WSTG Orchestrator Framework Design

## Overview

A modular, mostly autonomous Web Application Security Testing Orchestration Framework aligned with OWASP WSTG. Designed from a black-box / bug bounty hunter perspective with strict data chaining between modules.

- **Language:** Python 3.11+
- **Architecture:** Modular with central orchestrator
- **Output:** JSON + human-readable summary
- **Evidence:** Structured `evidence/` directory per company

---

## 1. Config & Scope System

`config.yaml` is the single source of truth. Three top-level sections:

### Program Scope
- `company_name` — evidence directory naming and display
- `base_domain` — primary anchor domain; discovered assets are in scope if their URL contains this substring *or* they are explicitly listed in `in_scope_urls` / `in_scope_ips` (enables subdomains and same-brand assets)
- `wildcard_urls` — patterns like `*.example.com`
- `in_scope_urls` / `in_scope_ips` — explicit targets; use for related companies, acquisitions, sister companies, or third-party domains that do not contain `base_domain`
- `out_of_scope_urls` / `out_of_scope_ips` — blacklist, checked before every action
- `out_of_scope_attack_vectors` — disallowed attack types (e.g., `dos`, `social_engineering`). Modules check this before running specific test categories
- `rate_limit` — requests per second for active target interaction only
- `custom_headers` — injected into every outbound request
- `notes` — free-text for program-specific context

### Scope Enforcement Rules
- **In-scope predicate:** A target is in scope if and only if (1) it is not on the blacklist (`out_of_scope_urls` / `out_of_scope_ips`), and (2) at least one of: the URL contains `base_domain`, the URL matches an `in_scope_urls` entry, or the IP matches `in_scope_ips`. This supports both same-domain discovery (subdomains, wildcards) and explicitly listed related companies, acquisitions, sister companies, and third-party assets.
- `ScopeChecker` utility instantiated at startup, injected into every module
- Every action calls `scope_checker.is_in_scope(target)` before proceeding

### Auth Profiles (optional)
- Named profiles with type (`basic`, `bearer`, `cookie`, `api_key`) and credentials
- Modules that need auth look up profiles by name
- Can be added mid-scan when prompted

### Tool Configs (optional)
- Per-tool overrides keyed by tool name (e.g., `nmap`, `gobuster`, `sqlmap`)
- Custom flags, wordlists, thread counts, etc.
- Checked before every tool execution; merged with defaults

### Interactive Scope Builder
- `main.py` runs an interactive prompt session at startup before any scanning
- Walks user through: company name, base domain, in-scope URLs/IPs (including related or acquired domains that do not contain the base domain), out-of-scope URLs/IPs, out-of-scope attack vectors, rate limits, custom headers, auth profiles, callback server config, notes
- Writes completed `config.yaml` to disk
- If `config.yaml` already exists, asks whether to reuse or reconfigure

---

## 2. State Manager & Data Chain

`state_manager.py` owns `state.json`, persisted to disk. All access is serialized by a single lock so that concurrent threads and async workers update state atomically without lost updates (see Key Behaviors).

### State Structure
```json
{
    "target_domain": "",
    "company_name": "",
    "scan_id": "uuid",
    "scan_start": "timestamp",
    "completed_phases": {},
    "discovered_subdomains": [],
    "live_hosts": [],
    "open_ports": [],
    "technologies": [],
    "server_versions": [],
    "frameworks": [],
    "endpoints": [],
    "parameters": [],
    "forms": [],
    "auth_endpoints": [],
    "api_endpoints": [],
    "cloud_assets": [],
    "potential_idor_candidates": [],
    "valid_usernames": [],
    "inferred_cves": [],
    "exposed_admin_paths": [],
    "pending_callbacks": [],
    "potential_vulnerabilities": [],
    "confirmed_vulnerabilities": [],
    "evidence_index": []
}
```

### Completed Phases Tracking
`completed_phases` tracks both phase-level and sub-category completion:
```json
{
    "reconnaissance": {
        "completed": true,
        "subcategories": {
            "passive_osint": true,
            "live_host_validation": true,
            "parameter_harvesting": true
        }
    },
    "fingerprinting": {
        "completed": false,
        "subcategories": {
            "service_scanning": true,
            "header_analysis": false
        }
    }
}
```

### Key Behaviors
- **Single lock:** All state access is protected by one threading lock. `get(key)`, `enrich(key, values)`, `set(key, value)`, and all `mark_*` operations acquire this lock so that list read–merge–write is atomic and concurrent workers cannot lose data.
- **Atomic enrich:** `enrich(key, values)` appends to list fields with deduplication while holding the lock (single read–merge–write under the lock). No separate “get then set” by callers; all mutations go through StateManager to avoid race conditions.
- **Checkpointing:** `save()` is invoked after every sub-category completion for resume. Modules may call `save()` after significant batch updates within a long-running sub-category so that a crash mid-execution persists partial results; the orchestrator does not rely solely on end-of-module checkpoints.
- `get(key)` reads current values for downstream modules (under the same lock).
- On startup, if `state.json` exists, loads it and checks `completed_phases` to determine resume point.
- `mark_subcategory_complete(phase, subcategory)` and `mark_phase_complete(phase)` for granular tracking (also under the lock).

---

## 3. Rate Limiter & HTTP Utils

### Rate Limiter (`rate_limit_handler.py`)
- Wraps all outbound HTTP requests to URLs containing the base target domain or related IPs
- Configured via `config.yaml` `rate_limit` (requests per second)
- **Passive actions bypass the limiter:** DNS lookups, WHOIS, Wayback queries, local file parsing
- On 429 or WAF block signatures: automatic exponential backoff
- After backoff succeeds, gradually ramps back up to configured ceiling
- Thread-safe, shared across all modules and async workers

### HTTP Utils (`http_utils.py`)
- Central `make_request()` function used by all modules
- Injects `custom_headers` from config automatically
- Passes every URL through `ScopeChecker` before sending — raises `OutOfScopeError` if blocked
- Routes through rate limiter for in-scope active requests
- Returns structured response objects with raw request/response data for evidence logging
- Configurable timeouts, retries with backoff, proxy support

### Command Runner (`command_runner.py`)
- Wraps all subprocess calls (nmap, gobuster, sqlmap, etc.)
- Before execution: checks tool availability, merges custom tool params from config
- Captures stdout/stderr, enforces timeout, handles graceful kill
- Saves raw tool output to appropriate `tool_output/` directory automatically

### Parser Utils (`parser_utils.py`)
- HTML/XML/JSON parsing helpers
- URL normalization and deduplication
- Parameter extraction from URLs, forms, JS files
- Response diffing utilities

---

## 4. Callback Server (`callback_server.py`)

Lightweight HTTP/DNS listener for confirming blind/out-of-band exploits.

### Use Cases
- Blind XSS (stored XSS fires later, hits our server)
- Blind SSRF (target makes outbound request to us)
- Blind command injection (DNS/HTTP exfil)
- Blind SQLi (out-of-band extraction via DNS or HTTP)
- XXE (external entity resolution)

### Design
- Async HTTP server on configurable port
- Optional DNS listener for DNS-based exfil
- Generates unique per-test callback URLs: `http://<host>:<port>/<unique_token>`
- Each token maps to a test case: module, parameter, payload
- On callback hit: logs full incoming request (headers, body, source IP, timestamp)
- Stores evidence in appropriate phase's `confirmed_exploits/` directory
- Notifies orchestrator that a blind exploit was confirmed
- Token-to-test mapping in state: `pending_callbacks[]` → moved to `confirmed_vulnerabilities[]` on hit

### Availability
- **Always available.** If no host/port configured in `config.yaml`, auto-starts on default port and detects machine's external IP (falls back to local)
- **Port conflict handling:** When auto-starting, the server attempts to bind to the default port; if it is already in use (e.g. `AddressAlreadyInUse`), it tries a defined fallback sequence (e.g. default+1, default+2, … up to a small limit). The first successfully bound port is used; callback URLs always reflect the actual bound port. If no port in the sequence is available, the server does not crash: it logs a clear error, does not start the listener, and continues in URL-only mode (callback URLs are still generated for use with an external tunnel; blind tests run but will not receive callbacks until the user frees a port or configures a tunnel in config). This keeps behavior defined and avoids silent failure or runtime crashes
- Supports ngrok/tunnel URL override for testing behind NAT
- No tests are ever skipped for lack of a callback server

---

## 5. Evidence Directory Structure & Logger

### Directory Structure (created at init)
```
evidence/
└── <company_name>/
    ├── reconnaissance/
    │   ├── tool_output/
    │   ├── raw_requests/
    │   ├── raw_responses/
    │   ├── parsed/
    │   ├── evidence/
    │   └── screenshots/
    ├── fingerprinting/
    │   ├── tool_output/
    │   ├── raw_requests/
    │   ├── raw_responses/
    │   ├── parsed/
    │   ├── evidence/
    │   ├── potential_exploits/
    │   ├── confirmed_exploits/
    │   └── screenshots/
    ├── configuration_testing/
    │   ├── tool_output/
    │   ├── raw_requests/
    │   ├── raw_responses/
    │   ├── parsed/
    │   ├── evidence/
    │   ├── potential_exploits/
    │   ├── confirmed_exploits/
    │   └── screenshots/
    ├── auth_testing/
    │   ├── (applicable subdirs)
    ├── authorization_testing/
    │   ├── ...
    ├── session_testing/
    │   ├── ...
    ├── input_validation/
    │   ├── ...
    ├── business_logic/
    │   ├── ...
    ├── api_testing/
    │   ├── ...
    └── reports/
```

Each phase only creates subdirectories that are relevant to it (e.g., recon does not use potential_exploits/ or confirmed_exploits/).

### Evidence Logger (`evidence_logger.py`)
Each module receives a phase-specific logger instance:
- `log_tool_output(tool_name, raw_output)` → `tool_output/`
- `log_request(request_data)` → `raw_requests/`
- `log_response(response_data)` → `raw_responses/`
- `log_parsed(data_name, structured_data)` → `parsed/` (consumed by later phases)
- `log_potential_exploit(finding)` → `potential_exploits/`
- `log_confirmed_exploit(finding)` → `confirmed_exploits/`
- `log_screenshot(name, image_data)` → `screenshots/`
- All files timestamped and cross-referenced in `evidence_index` in state

---

## 6. Orchestrator & Module Execution

### Startup Sequence (`main.py`)
1. Check for existing `config.yaml` — offer to reuse or reconfigure
2. If no config, run interactive scope builder
3. Write `config.yaml`
4. Initialize `StateManager` — load existing `state.json` or create fresh
5. Check `completed_phases` and sub-categories for resume point
6. Initialize shared services: `ScopeChecker`, `RateLimiter`, `CallbackServer`, `EvidenceLogger`
7. Validate external tool availability, log warnings for missing tools
8. Create evidence directory structure for company

### Execution Model (Hybrid Concurrency)
- **Inter-module:** Modules run in threads and can overlap when state dependencies are met
- **Intra-module:** Async workers handle parallel tasks (probing multiple hosts, testing multiple params)
- **State safety:** All concurrent state updates from threads and async workers go through StateManager; the single lock ensures atomic enrich/save and no lost updates (see §2 Key Behaviors)
- Rate limiter sits on top of everything

### Module Dependency Graph
```
recon → fingerprinting + config_testing (parallel)
     → auth_testing
     → authorization + session (parallel)
     → input_validation
     → business_logic
     → api_testing
```

### Decision Gates
- Before destructive/high-risk actions: prompt user
- Before using discovered credentials: prompt user
- Before deep data extraction (SQLi dump): prompt user
- Check `out_of_scope_attack_vectors` before each test category

### Module Interface
Every module implements:
```python
run(state_manager, config, scope_checker, rate_limiter, evidence_logger, callback_server)
```
- Returns enriched state
- Marks sub-categories and phase complete

### External Tool Handling
- Graceful degradation: check if tool is installed at runtime
- If available, use it; if not, skip with warning and fall back to Python-native alternatives
- Framework never crashes due to missing tools

---

## 7. Module Capabilities (Initial Build)

### reconnaissance.py
**Core:**
- Subfinder/amass for subdomain discovery (fallback to DNS brute)
- gau/Wayback URL harvesting
- httpx probing for live hosts with tech detection from headers
- JS file parsing for endpoints and parameters
- Parameter extraction (GET params, form fields, UUID/numeric ID detection)

### fingerprinting.py
**Core:**
- Nmap service version scan with XML parsing
- WhatWeb integration
- Header/cookie analysis
- Forced error triggering for stack disclosure
- CVE API cross-reference on detected versions

### configuration_testing.py
**Core:**
- robots.txt / sitemap.xml parsing
- Directory brute forcing via gobuster (fallback to Python wordlist requests)
- 403 bypass attempts (X-Original-URL, path normalization, case variation)
- HTTP method testing (OPTIONS, PUT, DELETE, TRACE)
- Cloud storage enumeration (S3, GCS, Azure patterns)

### auth_testing.py
**Core:**
- Username enumeration via response diffing and timing
- Default credential testing
- Lockout policy detection (respects `out_of_scope_attack_vectors`)

### authorization_testing.py
**Core:**
- IDOR fuzzing on numeric IDs (increment/decrement with response diff)
- UUID pattern detection and mutation
- Hidden field / role parameter tampering
- JWT decode, signature validation, algorithm=none test

### session_testing.py
**Core:**
- Cookie flag checks (HttpOnly, Secure, SameSite)
- Session rotation on login/logout
- Session fixation test
- Session reuse after logout

### input_validation.py
**Core:**
- SQLi probes (error, boolean, time-based) with sqlmap handoff
- Reflected XSS with WAF bypass payloads
- Command injection probes with commix handoff
- All tests consume `parameters[]` from state dynamically

### business_logic.py
**Core:**
- Multi-step workflow skip detection
- Price/quantity/negative value tampering
- Race condition via threaded concurrent requests (skipped if `dos` in out-of-scope vectors)

### api_testing.py
**Core:**
- Swagger/OpenAPI detection
- BOLA testing (ID swap, role swap)
- GraphQL introspection and field enumeration if detected

---

## 8. Reporting Engine

Generated in `evidence/<company_name>/reports/`:

### Structured JSON Reports
- `attack_surface.json` — subdomains, live hosts, open ports, technologies, endpoints, parameters, API endpoints, cloud assets
- `potential_findings.json` — potential vulnerabilities with severity, affected URL, parameter, test type, evidence file links
- `confirmed_findings.json` — confirmed exploits with full reproduction steps
- `evidence_index.json` — maps every finding to its evidence files

### Executive Summary (`executive_summary.txt`)
- Company name, scan date, scope summary
- Statistics: total assets discovered, tests run, findings by severity
- Each finding includes:
  - CVSS-like severity score (Critical/High/Medium/Low/Info)
  - Affected asset and parameter
  - Vulnerability description
  - Step-by-step reproduction instructions
  - Impact explanation
  - Mitigation guidance
  - References to evidence files and tool output
- Findings sorted by severity (critical first)

---

## 9. Project Structure

```
wstg_orchestrator/
├── main.py
├── state_manager.py
├── config.yaml
├── modules/
│   ├── reconnaissance.py
│   ├── fingerprinting.py
│   ├── configuration_testing.py
│   ├── auth_testing.py
│   ├── authorization_testing.py
│   ├── session_testing.py
│   ├── input_validation.py
│   ├── business_logic.py
│   └── api_testing.py
├── utils/
│   ├── http_utils.py
│   ├── parser_utils.py
│   ├── command_runner.py
│   ├── evidence_logger.py
│   ├── rate_limit_handler.py
│   └── callback_server.py
└── evidence/
```

---

## 10. Future Enhancements (TODOs)
- Plugin architecture for custom modules
- Delta scan mode (only test new assets)
- Headless browser support (Playwright) for DOM-based testing
- AI-based anomaly detection in responses
- Wordlist mutation engine
- Smart payload selection based on detected stack
- Notification webhooks (Slack/Discord) for confirmed findings
