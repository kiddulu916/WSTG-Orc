# ASN Enumeration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add ASN enumeration to the reconnaissance module, discovering ASNs by company name via amass and resolving them to IP ranges for downstream port scanning.

**Architecture:** New `asn_enumeration` subcategory runs before `passive_osint` in the recon pipeline. Uses `amass intel -org` for ASN discovery, then `amass intel -asn` (with whois RADB fallback) for IP range resolution. Missing tools prompt the user for installation.

**Tech Stack:** Python 3.11+, amass CLI, whois CLI, CommandRunner, StateManager, pytest + unittest.mock

**Design doc:** `docs/plans/2026-02-15-asn-enumeration-design.md`

---

### Task 1: Add state keys `asns` and `ip_ranges` to StateManager

**Files:**
- Modify: `wstg_orchestrator/state_manager.py:10-31`
- Test: `tests/test_state_manager.py`

**Step 1: Write the failing test**

Add to `tests/test_state_manager.py`:

```python
def test_asns_and_ip_ranges_initialized(tmp_state_file):
    sm = StateManager(tmp_state_file, target_domain="example.com", company_name="ExCorp")
    assert sm.get("asns") == []
    assert sm.get("ip_ranges") == []
```

Note: `tmp_state_file` fixture already exists in the test file.

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_state_manager.py::test_asns_and_ip_ranges_initialized -v`
Expected: FAIL — `assert None == []` because the keys don't exist yet.

**Step 3: Write minimal implementation**

In `wstg_orchestrator/state_manager.py`, add `"asns"` and `"ip_ranges"` to both `STATE_KEYS` (line 11) and `LIST_KEYS` (line 21):

```python
STATE_KEYS = [
    "target_domain", "company_name", "scan_id", "scan_start",
    "completed_phases", "discovered_subdomains", "live_hosts",
    "open_ports", "technologies", "server_versions", "frameworks",
    "endpoints", "parameters", "forms", "auth_endpoints",
    "api_endpoints", "cloud_assets", "potential_idor_candidates", "discovered_directory_paths",
    "valid_usernames", "inferred_cves", "exposed_admin_paths",
    "pending_callbacks", "potential_vulnerabilities",
    "confirmed_vulnerabilities", "evidence_index",
    "asns", "ip_ranges",
]

LIST_KEYS = [
    "discovered_subdomains", "live_hosts", "open_ports",
    "technologies", "server_versions", "frameworks", "endpoints",
    "parameters", "forms", "auth_endpoints", "api_endpoints",
    "cloud_assets", "potential_idor_candidates", "discovered_directory_paths",
    "valid_usernames",
    "inferred_cves", "exposed_admin_paths", "pending_callbacks",
    "potential_vulnerabilities", "confirmed_vulnerabilities",
    "evidence_index",
    "asns", "ip_ranges",
]
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_state_manager.py -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/state_manager.py tests/test_state_manager.py
git commit -m "feat: add asns and ip_ranges state keys"
```

---

### Task 2: Add `_parse_amass_org_output` parser method

**Files:**
- Modify: `wstg_orchestrator/modules/reconnaissance.py`
- Test: `tests/test_reconnaissance.py`

**Step 1: Write the failing tests**

Add to `tests/test_reconnaissance.py`:

```python
def test_parse_amass_org_output_matches_company(recon_module):
    """Lines containing the company name (case-insensitive substring) are matched."""
    stdout = (
        "AS394161, 12.0.0.0/8, Tesla, Inc.\n"
        "AS12345, 10.0.0.0/16, Tesla Motors\n"
        "AS99999, 172.16.0.0/12, Unrelated Corp\n"
    )
    results = recon_module._parse_amass_org_output(stdout, "Tesla")
    asns = [r["asn"] for r in results]
    assert "AS394161" in asns
    assert "AS12345" in asns
    assert "AS99999" not in asns


def test_parse_amass_org_output_collects_cidrs(recon_module):
    """CIDRs present on matching lines are collected."""
    stdout = "AS394161, 12.0.0.0/8, Tesla, Inc.\n"
    results = recon_module._parse_amass_org_output(stdout, "Tesla")
    assert results[0]["cidr"] == "12.0.0.0/8"


def test_parse_amass_org_output_missing_cidr(recon_module):
    """Lines without a CIDR still return the ASN with cidr=None."""
    stdout = "AS394161 -- Tesla, Inc.\n"
    results = recon_module._parse_amass_org_output(stdout, "Tesla")
    assert results[0]["asn"] == "AS394161"
    assert results[0]["cidr"] is None


def test_parse_amass_org_output_empty_input(recon_module):
    """Empty or whitespace-only input returns empty list."""
    assert recon_module._parse_amass_org_output("", "Tesla") == []
    assert recon_module._parse_amass_org_output("  \n\n  ", "Tesla") == []


def test_parse_amass_org_output_no_asn_token(recon_module):
    """Lines without an AS\\d+ token are skipped."""
    stdout = "Some random line, Tesla\n"
    assert recon_module._parse_amass_org_output(stdout, "Tesla") == []
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_reconnaissance.py::test_parse_amass_org_output_matches_company tests/test_reconnaissance.py::test_parse_amass_org_output_collects_cidrs tests/test_reconnaissance.py::test_parse_amass_org_output_missing_cidr tests/test_reconnaissance.py::test_parse_amass_org_output_empty_input tests/test_reconnaissance.py::test_parse_amass_org_output_no_asn_token -v`
Expected: FAIL — `AttributeError: 'ReconModule' object has no attribute '_parse_amass_org_output'`

**Step 3: Write minimal implementation**

Add to `wstg_orchestrator/modules/reconnaissance.py` in the `ReconModule` class:

```python
def _parse_amass_org_output(self, stdout: str, company_name: str) -> list[dict]:
    """Parse amass intel -org output. Return list of {asn, cidr, org} dicts
    for lines where org field contains company_name (case-insensitive)."""
    results = []
    company_lower = company_name.lower()
    asn_re = re.compile(r'(AS\d+)')
    cidr_re = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})')

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if company_lower not in line.lower():
            continue
        asn_match = asn_re.search(line)
        if not asn_match:
            continue
        cidr_match = cidr_re.search(line)
        results.append({
            "asn": asn_match.group(1),
            "cidr": cidr_match.group(1) if cidr_match else None,
            "org": line,
        })
    return results
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_reconnaissance.py -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/modules/reconnaissance.py tests/test_reconnaissance.py
git commit -m "feat: add amass intel -org output parser with company name matching"
```

---

### Task 3: Add `_parse_whois_radb_output` parser method

**Files:**
- Modify: `wstg_orchestrator/modules/reconnaissance.py`
- Test: `tests/test_reconnaissance.py`

**Step 1: Write the failing tests**

Add to `tests/test_reconnaissance.py`:

```python
def test_parse_whois_radb_output_extracts_routes(recon_module):
    """Extracts CIDR from route: and route6: lines."""
    stdout = (
        "route:          12.0.0.0/8\n"
        "descr:          Tesla\n"
        "origin:         AS394161\n"
        "route6:         2001:db8::/32\n"
        "descr:          Tesla IPv6\n"
    )
    cidrs = recon_module._parse_whois_radb_output(stdout)
    assert "12.0.0.0/8" in cidrs
    assert "2001:db8::/32" in cidrs


def test_parse_whois_radb_output_empty(recon_module):
    assert recon_module._parse_whois_radb_output("") == []


def test_parse_whois_radb_output_no_routes(recon_module):
    stdout = "descr: Some description\norigin: AS12345\n"
    assert recon_module._parse_whois_radb_output(stdout) == []
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_reconnaissance.py::test_parse_whois_radb_output_extracts_routes tests/test_reconnaissance.py::test_parse_whois_radb_output_empty tests/test_reconnaissance.py::test_parse_whois_radb_output_no_routes -v`
Expected: FAIL — `AttributeError`

**Step 3: Write minimal implementation**

Add to `ReconModule`:

```python
def _parse_whois_radb_output(self, stdout: str) -> list[str]:
    """Parse whois RADB output for route:/route6: lines, return list of CIDRs."""
    cidrs = []
    route_re = re.compile(r'^route6?:\s+(.+)', re.MULTILINE)
    for match in route_re.finditer(stdout):
        cidr = match.group(1).strip()
        if cidr:
            cidrs.append(cidr)
    return cidrs
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_reconnaissance.py -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/modules/reconnaissance.py tests/test_reconnaissance.py
git commit -m "feat: add whois RADB output parser for IP range extraction"
```

---

### Task 4: Add tool installation prompt helper

**Files:**
- Modify: `wstg_orchestrator/modules/reconnaissance.py`
- Test: `tests/test_reconnaissance.py`

**Step 1: Write the failing tests**

Add to `tests/test_reconnaissance.py`:

```python
@patch("wstg_orchestrator.modules.reconnaissance.cli_input", return_value="y")
@patch("subprocess.run")
def test_prompt_install_tool_accepted(mock_run, mock_input, recon_module):
    """When user accepts, install command runs and returns True."""
    mock_run.return_value = MagicMock(returncode=0)
    result = recon_module._prompt_install_tool("amass", "go install -v github.com/owasp-amass/amass/v4/...@master")
    assert result is True
    mock_run.assert_called_once()


@patch("wstg_orchestrator.modules.reconnaissance.cli_input", return_value="n")
def test_prompt_install_tool_declined(mock_input, recon_module):
    """When user declines, returns False without running install."""
    result = recon_module._prompt_install_tool("amass", "go install -v github.com/owasp-amass/amass/v4/...@master")
    assert result is False
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_reconnaissance.py::test_prompt_install_tool_accepted tests/test_reconnaissance.py::test_prompt_install_tool_declined -v`
Expected: FAIL — `AttributeError`

**Step 3: Write minimal implementation**

Add import at top of `reconnaissance.py`:

```python
import subprocess as _subprocess
from wstg_orchestrator.utils.cli_handler import cli_input
```

Add method to `ReconModule`:

```python
def _prompt_install_tool(self, tool_name: str, install_cmd: str) -> bool:
    """Prompt user to install a missing tool. Returns True if installed successfully."""
    self.logger.warning(f"{tool_name} not found.")
    answer = cli_input(f"Install {tool_name} with `{install_cmd}`? [y/N]: ").strip().lower()
    if answer != "y":
        self.logger.info(f"User declined to install {tool_name}, skipping")
        return False
    try:
        result = _subprocess.run(install_cmd.split(), capture_output=True, text=True, timeout=300)
        if result.returncode == 0:
            self.logger.info(f"{tool_name} installed successfully")
            return True
        self.logger.error(f"Failed to install {tool_name}: {result.stderr}")
    except Exception as e:
        self.logger.error(f"Error installing {tool_name}: {e}")
    return False
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_reconnaissance.py -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/modules/reconnaissance.py tests/test_reconnaissance.py
git commit -m "feat: add tool installation prompt helper"
```

---

### Task 5: Add `_run_amass_intel_org` and `_run_amass_intel_asn` tool methods

**Files:**
- Modify: `wstg_orchestrator/modules/reconnaissance.py`
- Test: `tests/test_reconnaissance.py`

**Step 1: Write the failing tests**

Add to `tests/test_reconnaissance.py`:

```python
@pytest.mark.asyncio
async def test_run_amass_intel_org_success(recon_module):
    """Successful amass intel -org returns parsed results."""
    mock_result = MagicMock()
    mock_result.tool_missing = False
    mock_result.returncode = 0
    mock_result.stdout = "AS394161, 12.0.0.0/8, Tesla, Inc.\n"

    recon_module.config.company_name = "Tesla"
    with patch.object(recon_module._cmd, 'run', return_value=mock_result):
        result = await recon_module._run_amass_intel_org("Tesla")
    assert result.stdout == mock_result.stdout


@pytest.mark.asyncio
async def test_run_amass_intel_org_missing_prompts_install(recon_module):
    """When amass is missing, prompts to install."""
    missing = MagicMock(tool_missing=True, returncode=1, stdout="", stderr="")
    success = MagicMock(tool_missing=False, returncode=0, stdout="AS1, 10.0.0.0/8, Tesla\n", stderr="")

    recon_module.config.company_name = "Tesla"
    with patch.object(recon_module._cmd, 'run', side_effect=[missing, success]):
        with patch.object(recon_module, '_prompt_install_tool', return_value=True):
            result = await recon_module._run_amass_intel_org("Tesla")
    assert result.returncode == 0


@pytest.mark.asyncio
async def test_run_amass_intel_asn_success(recon_module):
    """Successful amass intel -asn returns CommandResult."""
    mock_result = MagicMock()
    mock_result.tool_missing = False
    mock_result.returncode = 0
    mock_result.stdout = "12.0.0.0/8\n10.0.0.0/16\n"

    with patch.object(recon_module._cmd, 'run', return_value=mock_result):
        result = await recon_module._run_amass_intel_asn("AS394161")
    assert result.stdout == mock_result.stdout
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_reconnaissance.py::test_run_amass_intel_org_success tests/test_reconnaissance.py::test_run_amass_intel_org_missing_prompts_install tests/test_reconnaissance.py::test_run_amass_intel_asn_success -v`
Expected: FAIL — `AttributeError`

**Step 3: Write minimal implementation**

Add to `ReconModule`:

```python
TOOL_INSTALL_COMMANDS = {
    "amass": "go install -v github.com/owasp-amass/amass/v4/...@master",
    "whois": "apt install whois",
}

async def _run_amass_intel_org(self, company_name: str):
    """Run amass intel -org to discover ASNs for a company."""
    self.logger.info(f"Running amass intel -org for: {company_name}")
    result = self._cmd.run("amass", ["intel", "-org", company_name], timeout=300)
    if result.tool_missing:
        if self._prompt_install_tool("amass", self.TOOL_INSTALL_COMMANDS["amass"]):
            result = self._cmd.run("amass", ["intel", "-org", company_name], timeout=300)
        else:
            return result
    if result.returncode == 0 and result.stdout.strip():
        self.evidence.log_tool_output("reconnaissance", "amass_intel_org", result.stdout)
    return result

async def _run_amass_intel_asn(self, asn: str):
    """Run amass intel -asn to get IP ranges for an ASN."""
    self.logger.info(f"Running amass intel -asn for: {asn}")
    result = self._cmd.run("amass", ["intel", "-asn", asn], timeout=120)
    if result.returncode == 0 and result.stdout.strip():
        self.evidence.log_tool_output("reconnaissance", f"amass_intel_asn_{asn}", result.stdout)
    return result
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_reconnaissance.py -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/modules/reconnaissance.py tests/test_reconnaissance.py
git commit -m "feat: add amass intel -org and -asn tool runner methods"
```

---

### Task 6: Add `_run_whois_radb` fallback method

**Files:**
- Modify: `wstg_orchestrator/modules/reconnaissance.py`
- Test: `tests/test_reconnaissance.py`

**Step 1: Write the failing tests**

Add to `tests/test_reconnaissance.py`:

```python
@pytest.mark.asyncio
async def test_run_whois_radb_success(recon_module):
    """whois RADB returns route lines."""
    mock_result = MagicMock()
    mock_result.tool_missing = False
    mock_result.returncode = 0
    mock_result.stdout = "route:          12.0.0.0/8\norigin:         AS394161\n"

    with patch.object(recon_module._cmd, 'run', return_value=mock_result):
        result = await recon_module._run_whois_radb("AS394161")
    assert result.returncode == 0


@pytest.mark.asyncio
async def test_run_whois_radb_missing_prompts_install(recon_module):
    """When whois is missing, prompts to install."""
    missing = MagicMock(tool_missing=True, returncode=1, stdout="", stderr="")
    success = MagicMock(tool_missing=False, returncode=0, stdout="route: 10.0.0.0/8\n", stderr="")

    with patch.object(recon_module._cmd, 'run', side_effect=[missing, success]):
        with patch.object(recon_module, '_prompt_install_tool', return_value=True):
            result = await recon_module._run_whois_radb("AS12345")
    assert result.returncode == 0
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_reconnaissance.py::test_run_whois_radb_success tests/test_reconnaissance.py::test_run_whois_radb_missing_prompts_install -v`
Expected: FAIL — `AttributeError`

**Step 3: Write minimal implementation**

Add `"whois"` to the `CommandRunner` init in `__init__`:

```python
def __init__(self, *args, **kwargs):
    super().__init__(*args, **kwargs)
    self._cmd = CommandRunner(
        tool_configs={
            name: self.config.get_tool_config(name)
            for name in ["subfinder", "amass", "gau", "httpx", "whois"]
        }
    )
```

Add method to `ReconModule`:

```python
async def _run_whois_radb(self, asn: str):
    """Run whois against RADB to look up IP ranges for an ASN."""
    self.logger.info(f"Running whois RADB lookup for: {asn}")
    result = self._cmd.run("whois", ["-h", "whois.radb.net", "--", f"-i origin {asn}"], timeout=30)
    if result.tool_missing:
        if self._prompt_install_tool("whois", self.TOOL_INSTALL_COMMANDS["whois"]):
            result = self._cmd.run("whois", ["-h", "whois.radb.net", "--", f"-i origin {asn}"], timeout=30)
        else:
            return result
    if result.returncode == 0 and result.stdout.strip():
        self.evidence.log_tool_output("reconnaissance", f"whois_radb_{asn}", result.stdout)
    return result
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_reconnaissance.py -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/modules/reconnaissance.py tests/test_reconnaissance.py
git commit -m "feat: add whois RADB fallback for ASN IP range lookup"
```

---

### Task 7: Add `_lookup_asn_ip_ranges` orchestration method

**Files:**
- Modify: `wstg_orchestrator/modules/reconnaissance.py`
- Test: `tests/test_reconnaissance.py`

**Step 1: Write the failing tests**

Add to `tests/test_reconnaissance.py`:

```python
@pytest.mark.asyncio
async def test_lookup_asn_ip_ranges_uses_amass_first(recon_module):
    """Uses amass intel -asn for IP ranges when available."""
    amass_result = MagicMock(returncode=0, stdout="12.0.0.0/8\n10.0.0.0/16\n", tool_missing=False)

    with patch.object(recon_module, '_run_amass_intel_asn', new_callable=AsyncMock, return_value=amass_result):
        with patch.object(recon_module, '_run_whois_radb', new_callable=AsyncMock) as mock_whois:
            ranges = await recon_module._lookup_asn_ip_ranges(["AS394161"])
    assert "12.0.0.0/8" in ranges
    assert "10.0.0.0/16" in ranges
    mock_whois.assert_not_called()


@pytest.mark.asyncio
async def test_lookup_asn_ip_ranges_falls_back_to_whois(recon_module):
    """Falls back to whois when amass returns nothing."""
    amass_result = MagicMock(returncode=1, stdout="", tool_missing=False)
    whois_result = MagicMock(returncode=0, stdout="route:          10.0.0.0/16\n", tool_missing=False)

    with patch.object(recon_module, '_run_amass_intel_asn', new_callable=AsyncMock, return_value=amass_result):
        with patch.object(recon_module, '_run_whois_radb', new_callable=AsyncMock, return_value=whois_result):
            ranges = await recon_module._lookup_asn_ip_ranges(["AS12345"])
    assert "10.0.0.0/16" in ranges


@pytest.mark.asyncio
async def test_lookup_asn_ip_ranges_deduplicates(recon_module):
    """Duplicate CIDRs across ASNs are deduplicated."""
    result1 = MagicMock(returncode=0, stdout="10.0.0.0/16\n12.0.0.0/8\n", tool_missing=False)
    result2 = MagicMock(returncode=0, stdout="10.0.0.0/16\n", tool_missing=False)

    with patch.object(recon_module, '_run_amass_intel_asn', new_callable=AsyncMock, side_effect=[result1, result2]):
        ranges = await recon_module._lookup_asn_ip_ranges(["AS1", "AS2"])
    assert ranges.count("10.0.0.0/16") == 1
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_reconnaissance.py::test_lookup_asn_ip_ranges_uses_amass_first tests/test_reconnaissance.py::test_lookup_asn_ip_ranges_falls_back_to_whois tests/test_reconnaissance.py::test_lookup_asn_ip_ranges_deduplicates -v`
Expected: FAIL — `AttributeError`

**Step 3: Write minimal implementation**

Add to `ReconModule`:

```python
async def _lookup_asn_ip_ranges(self, asn_list: list[str]) -> list[str]:
    """Look up IP ranges for each ASN. Try amass first, fall back to whois RADB."""
    all_cidrs = []
    cidr_re = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})')

    for asn in asn_list:
        cidrs_for_asn = []

        # Try amass intel -asn first
        result = await self._run_amass_intel_asn(asn)
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.splitlines():
                line = line.strip()
                match = cidr_re.search(line)
                if match:
                    cidrs_for_asn.append(match.group(1))

        # Fall back to whois RADB if amass returned nothing
        if not cidrs_for_asn:
            self.logger.info(f"amass returned no ranges for {asn}, trying whois RADB")
            result = await self._run_whois_radb(asn)
            if result.returncode == 0 and result.stdout.strip():
                cidrs_for_asn = self._parse_whois_radb_output(result.stdout)

        if not cidrs_for_asn:
            self.logger.warning(f"No IP ranges found for {asn}")

        all_cidrs.extend(cidrs_for_asn)

    return list(dict.fromkeys(all_cidrs))
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_reconnaissance.py -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/modules/reconnaissance.py tests/test_reconnaissance.py
git commit -m "feat: add ASN-to-IP-range lookup with amass/whois fallback"
```

---

### Task 8: Wire up `_asn_enumeration` orchestrator and update `execute()`

**Files:**
- Modify: `wstg_orchestrator/modules/reconnaissance.py`
- Test: `tests/test_reconnaissance.py`

**Step 1: Write the failing tests**

Add to `tests/test_reconnaissance.py`:

```python
def test_subcategories_includes_asn_enumeration(recon_module):
    """asn_enumeration is the first subcategory."""
    assert recon_module.SUBCATEGORIES[0] == "asn_enumeration"


@pytest.mark.asyncio
async def test_asn_enumeration_full_flow(recon_module):
    """Full ASN enumeration: amass org -> parse -> lookup ranges -> enrich state."""
    org_result = MagicMock(
        returncode=0, tool_missing=False,
        stdout="AS394161, 12.0.0.0/8, Tesla, Inc.\nAS99999, 172.16.0.0/12, Unrelated Corp\n",
    )
    recon_module.config.company_name = "Tesla"

    with patch.object(recon_module, '_run_amass_intel_org', new_callable=AsyncMock, return_value=org_result):
        with patch.object(recon_module, '_lookup_asn_ip_ranges', new_callable=AsyncMock, return_value=["12.0.0.0/8", "10.0.0.0/16"]):
            await recon_module._asn_enumeration()

    # Check state.enrich was called with ASNs and IP ranges
    enrich_calls = {call.args[0]: call.args[1] for call in recon_module.state.enrich.call_args_list}
    assert "AS394161" in enrich_calls["asns"]
    assert "AS99999" not in enrich_calls["asns"]
    assert "12.0.0.0/8" in enrich_calls["ip_ranges"]
    assert "10.0.0.0/16" in enrich_calls["ip_ranges"]


@pytest.mark.asyncio
async def test_asn_enumeration_includes_inline_cidrs(recon_module):
    """CIDRs found inline in amass org output are included in ip_ranges."""
    org_result = MagicMock(
        returncode=0, tool_missing=False,
        stdout="AS394161, 12.0.0.0/8, Tesla, Inc.\n",
    )
    recon_module.config.company_name = "Tesla"

    with patch.object(recon_module, '_run_amass_intel_org', new_callable=AsyncMock, return_value=org_result):
        with patch.object(recon_module, '_lookup_asn_ip_ranges', new_callable=AsyncMock, return_value=["10.0.0.0/16"]):
            await recon_module._asn_enumeration()

    enrich_calls = {}
    for call in recon_module.state.enrich.call_args_list:
        key = call.args[0]
        enrich_calls.setdefault(key, []).extend(call.args[1])
    # Both inline CIDR and looked-up CIDR should be present
    assert "12.0.0.0/8" in enrich_calls["ip_ranges"]
    assert "10.0.0.0/16" in enrich_calls["ip_ranges"]


@pytest.mark.asyncio
async def test_execute_runs_asn_enumeration_first(recon_module):
    """asn_enumeration runs before passive_osint in execute()."""
    call_order = []

    async def mock_asn():
        call_order.append("asn_enumeration")

    async def mock_passive():
        call_order.append("passive_osint")

    async def mock_harvest():
        call_order.append("url_harvesting")

    async def mock_live():
        call_order.append("live_host_validation")

    async def mock_params():
        call_order.append("parameter_harvesting")

    with patch.object(recon_module, '_asn_enumeration', side_effect=mock_asn):
        with patch.object(recon_module, '_passive_osint', side_effect=mock_passive):
            with patch.object(recon_module, '_url_harvesting', side_effect=mock_harvest):
                with patch.object(recon_module, '_live_host_validation', side_effect=mock_live):
                    with patch.object(recon_module, '_parameter_harvesting', side_effect=mock_params):
                        await recon_module.execute()

    assert call_order[0] == "asn_enumeration"
    assert call_order[1] == "passive_osint"


@pytest.mark.asyncio
async def test_asn_enumeration_skipped_when_amass_missing_and_declined(recon_module):
    """When amass is missing and user declines install, no ASNs are enriched."""
    missing_result = MagicMock(returncode=1, tool_missing=True, stdout="", stderr="")
    recon_module.config.company_name = "Tesla"

    with patch.object(recon_module, '_run_amass_intel_org', new_callable=AsyncMock, return_value=missing_result):
        await recon_module._asn_enumeration()

    # enrich should not have been called for asns
    asn_calls = [c for c in recon_module.state.enrich.call_args_list if c.args[0] == "asns"]
    assert len(asn_calls) == 0 or asn_calls[0].args[1] == []
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_reconnaissance.py::test_subcategories_includes_asn_enumeration tests/test_reconnaissance.py::test_asn_enumeration_full_flow tests/test_reconnaissance.py::test_execute_runs_asn_enumeration_first tests/test_reconnaissance.py::test_asn_enumeration_skipped_when_amass_missing_and_declined -v`
Expected: FAIL

**Step 3: Write minimal implementation**

Update `SUBCATEGORIES` in `ReconModule`:

```python
SUBCATEGORIES = ["asn_enumeration", "passive_osint", "url_harvesting", "live_host_validation", "parameter_harvesting"]
```

Update `execute()` to call `_asn_enumeration` first:

```python
async def execute(self):
    if not self.should_skip_subcategory("asn_enumeration"):
        await self._asn_enumeration()
        self.mark_subcategory_complete("asn_enumeration")

    if not self.should_skip_subcategory("passive_osint"):
        await self._passive_osint()
        self.mark_subcategory_complete("passive_osint")

    if not self.should_skip_subcategory("url_harvesting"):
        await self._url_harvesting()
        self.mark_subcategory_complete("url_harvesting")

    if not self.should_skip_subcategory("live_host_validation"):
        await self._live_host_validation()
        self.mark_subcategory_complete("live_host_validation")

    if not self.should_skip_subcategory("parameter_harvesting"):
        await self._parameter_harvesting()
        self.mark_subcategory_complete("parameter_harvesting")
```

Add `_asn_enumeration` method:

```python
async def _asn_enumeration(self):
    """Discover ASNs for the target company and resolve their IP ranges."""
    company_name = self.config.company_name
    if not company_name:
        self.logger.warning("No company_name configured, skipping ASN enumeration")
        return

    self.logger.info(f"Starting ASN enumeration for: {company_name}")

    # Step 1: Discover ASNs via amass intel -org
    result = await self._run_amass_intel_org(company_name)
    if result.tool_missing or result.returncode != 0:
        self.logger.warning("amass intel -org failed, skipping ASN enumeration")
        return

    parsed = self._parse_amass_org_output(result.stdout, company_name)
    if not parsed:
        self.logger.info("No ASNs found matching company name")
        return

    # Collect ASNs and any inline CIDRs
    asns = list(dict.fromkeys(entry["asn"] for entry in parsed))
    inline_cidrs = [entry["cidr"] for entry in parsed if entry["cidr"]]

    self.state.enrich("asns", asns)
    self.evidence.log_parsed("reconnaissance", "asns", asns)
    self.logger.info(f"Found {len(asns)} ASNs: {', '.join(asns)}")

    # Step 2: Look up IP ranges for each ASN
    looked_up_cidrs = await self._lookup_asn_ip_ranges(asns)

    # Merge inline + looked-up CIDRs, deduplicate
    all_cidrs = list(dict.fromkeys(inline_cidrs + looked_up_cidrs))

    self.state.enrich("ip_ranges", all_cidrs)
    self.evidence.log_parsed("reconnaissance", "ip_ranges", all_cidrs)
    self.logger.info(f"Found {len(all_cidrs)} IP ranges")
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_reconnaissance.py -v`
Expected: ALL PASS

**Step 5: Run full test suite**

Run: `pytest tests/ -v`
Expected: ALL PASS

**Step 6: Commit**

```bash
git add wstg_orchestrator/modules/reconnaissance.py wstg_orchestrator/state_manager.py tests/test_reconnaissance.py tests/test_state_manager.py
git commit -m "feat: wire up ASN enumeration subcategory in recon pipeline"
```

---

### Task 9: Final verification

**Step 1: Run full test suite**

Run: `pytest tests/ -v`
Expected: ALL PASS — no regressions

**Step 2: Verify the existing execute order test still passes**

Run: `pytest tests/test_reconnaissance.py::test_execute_runs_url_harvesting_before_live_hosts -v`
Expected: PASS — existing order tests must account for the new asn_enumeration step

**Step 3: Commit plan doc**

```bash
git add docs/plans/2026-02-15-asn-enumeration-implementation.md
git commit -m "docs: add ASN enumeration implementation plan"
```
