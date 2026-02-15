# URL & Domain Handling Redesign

## Problem

Current implementation has inconsistent URL storage (some with schemes, some without), `enumeration_domains` includes `in_scope_urls` unnecessarily, `ScopeChecker` ignores `in_scope_urls` and `wildcard_urls` for positive scope validation, and no scheme stripping is applied to user input or tool outputs.

## Design

### URL Stripping Rules

All stored URLs strip `http://` and `https://` schemes. A shared `strip_scheme(url)` utility handles this everywhere: ScopeBuilder input, tool output parsing, state storage.

**User input (ScopeBuilder):**
- `base_domain`: strip scheme -> `example.com`
- `wildcard_urls`: strip scheme AND `*.` prefix -> `example.com`, `api.example.com`
- `in_scope_urls`: strip scheme, keep paths -> `app.example.com/dashboard`, `partner.com`
- `out_of_scope_urls`: strip scheme, keep paths -> `example.com/admin`, `*.internal.example.com`

**Tool/discovery outputs (state):**
- `discovered_subdomains`: bare hostnames only
- `endpoints`: hostname + path, no query strings
- `parameters`: hostname + path + query string
- `discovered_directory_paths`: hostname + path (non-API, HTML response)
- `live_hosts`: bare hostnames that responded to probing

### enumeration_domains

Derived property in ConfigLoader. Combines `base_domain` + `wildcard_urls` only. `in_scope_urls` are excluded. Deduplicated, order preserved. `wildcard_urls` are already stored as bare domains (no `*.` prefix), so no further stripping needed.

### Recon Pipeline Flow

1. **Subdomain enumeration** (subfinder/amass) - uses `enumeration_domains` -> populates `state.discovered_subdomains`
2. **URL harvesting** (gau/wayback) - uses `enumeration_domains` -> parses output into three buckets:
   - Hostname extracted -> `state.discovered_subdomains`
   - Path without query string -> `state.endpoints` (if later probed and returns JSON) or `state.discovered_directory_paths` (if HTML)
   - Full URL with query string -> `state.parameters` (only when `?key=value` present), and base path -> `state.endpoints`
3. **Live host validation** (httpx) - probes `state.discovered_subdomains` + `in_scope_urls` (merged, deduplicated) -> populates `state.live_hosts`

### URL Harvesting Parsing Rules

For any tool output that produces a URL:

| URL has... | Response type | Stored in |
|---|---|---|
| Query string | Any | `parameters` (full) + `endpoints` (base path) |
| Path, no query | JSON body | `endpoints` |
| Path, no query | HTML/other | `discovered_directory_paths` |
| No path | N/A | `discovered_subdomains` only |

### ScopeChecker Updates

Constructor now accepts `wildcard_urls` and `in_scope_urls` in addition to existing params.

**`is_in_scope(target)` logic:**

1. Strip scheme from target, lowercase
2. Extract hostname
3. Check out-of-scope first (deny takes priority):
   - Match against `out_of_scope_urls` using three pattern types (see below)
   - Match against `out_of_scope_ips`
   - If matched -> return False
4. Check positive scope:
   - Hostname == `base_domain` or ends with `.{base_domain}` -> True
   - Hostname == any `wildcard_urls` entry or ends with `.{entry}` -> True
   - Hostname matches any hostname extracted from `in_scope_urls` -> True
   - Otherwise -> False

Out-of-scope always wins over in-scope.

### Out-of-Scope Pattern Types

Three pattern types recognized:

1. **Domain wildcards** - `*.something.com` -> matches any subdomain of something.com
2. **Domain + path prefix** - `example.com/path` -> matches exact domain with path starting with `/path`
3. **Path component wildcards** - `*/segment/*` -> matches any URL on any domain where `/segment/` appears anywhere in the path

The `*/segment/*` pattern uses the structure `*/xxxxx/*` where `xxxxx` is any user-submitted path name. The engine extracts the segment and checks if it appears as a path component anywhere in the URL.

### Out-of-Scope Filtering on State Ingest

Whenever data is added to state via `enrich()`, each entry is checked against `out_of_scope_urls`:

- `state.discovered_subdomains` - hostname matched -> discard
- `state.endpoints` - hostname + path matched -> discard
- `state.parameters` - hostname + path matched -> discard
- `state.discovered_directory_paths` - hostname + path matched -> discard
- `state.live_hosts` - hostname matched -> discard

Two layers of enforcement:
1. **On ingest** - when data enters state, strip anything matching out_of_scope
2. **On request** - ScopeChecker validates before any HTTP request

### Scheme-Aware HTTP Requests

New `try_request(url, ...)` utility:
1. Prepend `https://` and attempt request
2. If connection fails (SSL error, refused, timeout), retry with `http://`
3. Return response with working scheme noted

All modules use this instead of manually prepending schemes.

### State Key Definitions

| Key | Format | Content |
|---|---|---|
| `discovered_subdomains` | `hostname` | Bare hostnames only |
| `discovered_directory_paths` | `hostname/path` | Non-API paths (HTML response) |
| `endpoints` | `hostname/path` | API endpoints (JSON response or has query params) |
| `parameters` | `hostname/path?key=value` | Full URLs with query strings |
| `live_hosts` | `hostname` | Hostnames that responded to probing |

### Files Changed

- **New utility**: `strip_scheme(url)` in parser_utils.py or new url_utils.py
- **New utility**: `try_request(url, ...)` in shared HTTP utility
- **Modified**: `wstg_orchestrator/scope_builder.py` - strip schemes on input, strip `*.` from wildcards
- **Modified**: `wstg_orchestrator/utils/config_loader.py` - `enumeration_domains` excludes `in_scope_urls`
- **Modified**: `wstg_orchestrator/utils/scope_checker.py` - accept `wildcard_urls` + `in_scope_urls`, three out-of-scope pattern types
- **Modified**: `wstg_orchestrator/utils/state_manager.py` - out-of-scope filtering on `enrich()`
- **Modified**: `wstg_orchestrator/modules/reconnaissance.py` - reordered pipeline, URL parsing into three buckets, seed `in_scope_urls` into live host validation
- **Modified**: All modules making HTTP requests - use `try_request()` instead of direct requests
