# Acquisition Discovery Subcategory Design

## Overview

Add a `acquisition_discovery` subcategory to the reconnaissance module that discovers companies acquired by the target organization. Extracted domains are added to scope and state, expanding the attack surface for downstream modules.

## Subcategory Position & Data Flow

Slots into `SUBCATEGORIES` after `asn_enumeration`, before `passive_osint`:

```python
SUBCATEGORIES = [
    "asn_enumeration",
    "acquisition_discovery",   # NEW
    "passive_osint",
    "url_harvesting",
    "live_host_validation",
    "parameter_harvesting"
]
```

**Why this position:** Acquisition domains must be in scope before passive OSINT runs subfinder, otherwise they won't be enumerated. Only needs `company_name` from config — no upstream state dependencies beyond what ASN enumeration also uses.

**Data flow:**
1. Read `config.company_name`
2. Query Wikipedia API -> parse acquisitions (company names + domains)
3. If Wikipedia yields nothing -> Playwright scrapes Crunchbase search -> acquisitions tab
4. Extracted domains get:
   - Added to `ScopeChecker._in_scope_hostnames` (in-memory, immediate effect)
   - Appended to `in_scope_urls` in config YAML on disk (persistence for resume)
   - Enriched into `state.discovered_subdomains` (available to downstream modules)
   - Logged to evidence as parsed JSON

## Source 1: Wikipedia API (Primary)

No browser or external tools needed. Pure HTTP via `aiohttp`.

**Strategy:**
1. Query `https://en.wikipedia.org/w/api.php?action=parse&page={company_name}&prop=wikitext&format=json`
2. Parse wikitext for acquisition-related sections (headings: "Acquisitions", "Mergers and acquisitions", "Corporate acquisitions")
3. Extract company names and associated URLs/domains from wiki tables and infoboxes
4. Also check `List of mergers and acquisitions by {company_name}` disambiguation pattern for large companies

**What we extract:**
- Acquired company name (for evidence/logging)
- Domain/website URL (actionable data)
- Acquisition year (context for evidence, not functionally used)

**Fallback triggers** (move to Crunchbase):
- Wikipedia page doesn't exist for the company
- Page exists but has no acquisitions section
- Acquisitions section exists but contains zero extractable domains

## Source 2: Crunchbase via Playwright (Fallback)

Browser automation using the Playwright MCP server when Wikipedia yields nothing.

**Flow:**
1. Navigate to `https://www.crunchbase.com/textsearch?q={company_name}`
2. Wait for search results, click best-matching organization
3. Navigate to acquisitions tab (append `/acquisitions` to org URL)
4. Extract acquisitions table: company name, domain/website link, date

**Playwright MCP tools used:**
- `browser_navigate` -> search page
- `browser_snapshot` -> read search results
- `browser_click` -> select best match
- `browser_snapshot` -> verify org page loaded
- `browser_navigate` -> acquisitions tab URL
- `browser_snapshot` -> read acquisitions table
- `browser_close` -> clean up

**Error handling:**
- Crunchbase blocks/CAPTCHAs -> log warning, return empty (graceful degradation)
- No acquisitions tab -> log info, return empty
- Playwright MCP server not available -> log warning, skip entirely
- Network timeouts -> standard retry with backoff

## Runtime Scope Modification

Two new methods to support dynamic scope expansion.

**ScopeChecker.add_in_scope_hostnames(hostnames):**
- Appends to existing `_in_scope_hostnames` set
- Immediate effect for all subsequent `is_in_scope()` calls

**ConfigLoader.append_in_scope_urls(urls, config_path):**
- Appends URLs to `in_scope_urls` in both memory and YAML on disk
- Deduplicates against existing entries
- Re-writes YAML file for resume persistence

**ConfigLoader.config_path:**
- Store config file path as attribute during `__init__` for access by modules

**Console logging:**
```
[SCOPE EXPANSION] Added 3 acquisition domains to scope:
  + instagram.com
  + whatsapp.com
  + oculus.com
```

**Config toggle:** New optional key `auto_expand_scope: true` under `program_scope`. Defaults to `true`. When `false`, domains go to state and evidence only — not added to scope or config.

## State & Evidence

**New state key:**
- `acquired_companies` — list of dicts: `{"company": str, "domain": str, "year": str, "source": "wikipedia"|"crunchbase"}`

**Enrichment flow:**
```
acquisition_discovery
  +-- state.enrich("acquired_companies", [{company, domain, year, source}, ...])
  +-- state.enrich("discovered_subdomains", [domain1, domain2, ...])
  +-- scope_checker.add_in_scope_hostnames([domain1, domain2, ...])
  +-- config.append_in_scope_urls([domain1, domain2, ...], config_path)
  +-- evidence.log_parsed("reconnaissance", "acquired_companies", results)
```

**Resume behavior:** On resume, if `acquisition_discovery` is already complete in state, it skips. Domains persist in both state and config YAML.

## Testing Strategy

1. **Wikipedia parsing** — Mock API response, verify extraction of company names, domains, years
2. **Wikipedia fallback triggers** — 404, no section, zero domains all trigger Crunchbase fallback
3. **Crunchbase Playwright flow** — Mock MCP tools, verify navigate/snapshot/click sequence and domain extraction
4. **Playwright unavailable** — Graceful degradation when MCP server not configured
5. **Scope expansion** — Verify `add_in_scope_hostnames()` and `append_in_scope_urls()` work correctly
6. **State enrichment** — Both `acquired_companies` (dicts) and `discovered_subdomains` (strings) enriched
7. **Auto-expand toggle** — `false` skips scope/config modification
8. **Execution ordering** — Runs after `asn_enumeration`, before `passive_osint`
9. **Deduplication** — Domains already in scope aren't duplicated
