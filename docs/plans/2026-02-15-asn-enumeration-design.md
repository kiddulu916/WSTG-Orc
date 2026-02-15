# ASN Enumeration Design

## Overview

Expand passive OSINT capabilities in `reconnaissance.py` by adding ASN enumeration before subdomain enumeration. Uses target company name to discover ASNs via amass, then looks up IP ranges for each ASN. IP ranges feed downstream into port/service enumeration.

## Data Flow

```
company_name (from config)
  │
  ▼
amass intel -org "<company_name>"
  │
  ▼
Parse output: case-insensitive substring match on company_name
  │
  ├──► state.asns  (e.g. ["AS394161", "AS12345"])
  │
  ▼
For each ASN:
  try:  amass intel -asn <ASN>
  fall: whois -h whois.radb.net -- '-i origin <ASN>'
  │
  ▼
state.ip_ranges  (e.g. ["12.0.0.0/8", "10.0.0.0/16"])
  │
  ▼
Available for port/service enumeration downstream
```

## Pipeline Order (updated)

1. `asn_enumeration` — NEW, runs first
2. `passive_osint` — subdomain enumeration (unchanged)
3. `url_harvesting` (unchanged)
4. `live_host_validation` (unchanged)
5. `parameter_harvesting` (unchanged)

## State Keys (new)

- `asns` — list of ASN strings (e.g. `"AS394161"`), deduplicated
- `ip_ranges` — list of CIDR strings (e.g. `"12.0.0.0/8"`), deduplicated

Added to both `STATE_KEYS` and `LIST_KEYS` in `StateManager`.

## Implementation: ReconModule

### New subcategory: `asn_enumeration`

Added to `SUBCATEGORIES` list before `passive_osint`. Gets its own resume checkpoint via `mark_subcategory_complete`.

### Method structure

```
_asn_enumeration()
  ├── _run_amass_intel_org(company_name) → CommandResult
  ├── _parse_amass_org_output(stdout, company_name) → list[dict{asn, cidr, org}]
  ├── Deduplicate ASNs, enrich state.asns
  ├── Collect any CIDRs found on the same lines → ip_ranges
  ├── _lookup_asn_ip_ranges(asn_list) → list[str] CIDRs
  │     ├── try: _run_amass_intel_asn(asn) per ASN
  │     └── fallback: _run_whois_radb(asn) per ASN
  └── Deduplicate CIDRs, enrich state.ip_ranges
```

### Parsing: amass intel -org output

Each line typically: `AS12345, 192.168.0.0/16, OrgName`

- Split on comma, strip whitespace each field
- Check if any field contains `company_name` (case-insensitive substring)
- Extract `AS\d+` token as the ASN
- If a CIDR (`\d+\.\d+\.\d+\.\d+/\d+` or IPv6) is present, collect it too

### Parsing: whois RADB fallback

Output contains `route:` / `route6:` lines:

- Match lines with `^route6?:\s+(.+)`
- Strip and collect the CIDR value

### Parsing: amass intel -asn output

Lines are CIDR ranges, one per line. Validate with CIDR regex before collecting.

## Tool Installation

When a required tool (amass, whois) is missing:

1. Detect tool is unavailable via `CommandRunner.is_tool_available()`
2. Prompt user with the exact install command via `cli_input()`
3. On confirmation: run install command, retry the tool invocation
4. On decline: log warning, skip that step gracefully

Install commands:
- amass: `go install -v github.com/owasp-amass/amass/v4/...@master` or `apt install amass`
- whois: `apt install whois`

## Error Handling

- Empty/malformed lines skipped silently during parsing
- ASN regex `AS\d+` — no match on a line means skip it
- CIDR validation regex before adding to ip_ranges
- If amass intel -asn fails for a specific ASN, fall back to whois for THAT ASN only
- If both tools fail for an ASN, log warning, continue with remaining ASNs
- Deduplication before tool invocations (avoid querying same ASN twice)
- `state.enrich()` handles final dedup

## Timeouts

- `amass intel -org`: 300s
- `amass intel -asn`: 120s per ASN
- `whois`: 30s per ASN

## Evidence Logging

- `self.evidence.log_tool_output("reconnaissance", "amass_intel_org", stdout)`
- `self.evidence.log_tool_output("reconnaissance", "amass_intel_asn", stdout)` per ASN
- `self.evidence.log_tool_output("reconnaissance", "whois_radb", stdout)` per ASN
- `self.evidence.log_parsed("reconnaissance", "asns", asn_list)`
- `self.evidence.log_parsed("reconnaissance", "ip_ranges", ip_range_list)`

## Files Modified

1. `wstg_orchestrator/modules/reconnaissance.py` — new subcategory + methods
2. `wstg_orchestrator/state_manager.py` — add `asns` and `ip_ranges` to STATE_KEYS/LIST_KEYS
3. `tests/test_reconnaissance.py` — tests for new functionality
