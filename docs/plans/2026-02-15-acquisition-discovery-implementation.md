# Acquisition Discovery Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add an `acquisition_discovery` subcategory to the recon module that discovers acquired company domains via Wikipedia API (primary) and Crunchbase/Playwright (fallback), dynamically expanding scope and enriching state.

**Architecture:** Multi-source cascade: Wikipedia MediaWiki API first (pure HTTP, no tools), Crunchbase via Playwright MCP fallback. Discovered domains are added to ScopeChecker in-memory, persisted to config YAML, and enriched into state for downstream modules. Runs after ASN enumeration, before passive OSINT.

**Tech Stack:** Python 3.11+, aiohttp (existing dep), Playwright MCP server (optional), pytest + unittest.mock

---

### Task 1: ScopeChecker.add_in_scope_hostnames()

**Files:**
- Test: `tests/test_scope_checker.py`
- Modify: `wstg_orchestrator/utils/scope_checker.py:10-37`

**Step 1: Write the failing test**

Add to `tests/test_scope_checker.py`:

```python
def test_add_in_scope_hostnames_makes_domain_pass(expanded_checker):
    """Dynamically added hostnames pass is_in_scope()."""
    assert expanded_checker.is_in_scope("newdomain.com") is False
    expanded_checker.add_in_scope_hostnames(["newdomain.com"])
    assert expanded_checker.is_in_scope("newdomain.com") is True


def test_add_in_scope_hostnames_case_insensitive(expanded_checker):
    """Added hostnames are lowercased for consistent matching."""
    expanded_checker.add_in_scope_hostnames(["NewDomain.COM"])
    assert expanded_checker.is_in_scope("newdomain.com") is True


def test_add_in_scope_hostnames_no_duplicates(expanded_checker):
    """Adding an already in-scope hostname doesn't break anything."""
    expanded_checker.add_in_scope_hostnames(["partner.com"])
    assert expanded_checker.is_in_scope("partner.com") is True
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_scope_checker.py::test_add_in_scope_hostnames_makes_domain_pass -v`
Expected: FAIL with `AttributeError: 'ScopeChecker' object has no attribute 'add_in_scope_hostnames'`

**Step 3: Write minimal implementation**

Add to `wstg_orchestrator/utils/scope_checker.py` after the `__init__` method (after line 37):

```python
def add_in_scope_hostnames(self, hostnames: list[str]):
    """Dynamically add hostnames to the in-scope set at runtime."""
    for h in hostnames:
        self._in_scope_hostnames.add(h.lower())
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_scope_checker.py -v`
Expected: All PASS including three new tests

**Step 5: Commit**

```bash
git add tests/test_scope_checker.py wstg_orchestrator/utils/scope_checker.py
git commit -m "feat: add dynamic scope expansion to ScopeChecker"
```

---

### Task 2: ConfigLoader.config_path and append_in_scope_urls()

**Files:**
- Test: `tests/test_config_loader.py`
- Modify: `wstg_orchestrator/utils/config_loader.py:6-14` (init) and add method after line 97

**Step 1: Write the failing tests**

Add to `tests/test_config_loader.py`:

```python
def test_config_path_stored(config_file):
    """ConfigLoader stores the config file path."""
    config = ConfigLoader(config_file)
    assert config.config_path == config_file


def test_append_in_scope_urls_adds_to_memory(config_file):
    """append_in_scope_urls updates in-memory in_scope_urls."""
    config = ConfigLoader(config_file)
    config.append_in_scope_urls(["newdomain.com", "another.com"])
    assert "newdomain.com" in config.in_scope_urls
    assert "another.com" in config.in_scope_urls


def test_append_in_scope_urls_persists_to_yaml(config_file):
    """append_in_scope_urls writes changes to the YAML file on disk."""
    config = ConfigLoader(config_file)
    original_count = len(config.in_scope_urls)
    config.append_in_scope_urls(["persisted.com"])

    # Reload from disk
    reloaded = ConfigLoader(config_file)
    assert "persisted.com" in reloaded.in_scope_urls
    assert len(reloaded.in_scope_urls) == original_count + 1


def test_append_in_scope_urls_deduplicates(config_file):
    """Already present URLs are not duplicated."""
    config = ConfigLoader(config_file)
    existing = list(config.in_scope_urls)
    config.append_in_scope_urls([existing[0], "brand-new.com"])
    assert config.in_scope_urls.count(existing[0]) == 1
    assert "brand-new.com" in config.in_scope_urls


def test_append_in_scope_urls_empty_list(config_file):
    """Appending empty list is a no-op."""
    config = ConfigLoader(config_file)
    before = list(config.in_scope_urls)
    config.append_in_scope_urls([])
    assert config.in_scope_urls == before
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_config_loader.py::test_config_path_stored -v`
Expected: FAIL with `AttributeError: 'ConfigLoader' object has no attribute 'config_path'`

**Step 3: Write minimal implementation**

Modify `wstg_orchestrator/utils/config_loader.py`:

In `__init__` (line 7), store the config path:

```python
def __init__(self, config_path: str):
    self.config_path = config_path
    with open(config_path, "r") as f:
        self._raw = yaml.safe_load(f)
    self._scope = self._raw.get("program_scope", {})
    self._auth = self._raw.get("auth_profiles", {})
    self._tools = self._raw.get("tool_configs", {})
    self._callback = self._raw.get("callback_server", {})
```

Add new method after the `save` method (after line 98):

```python
def append_in_scope_urls(self, urls: list[str]):
    """Append URLs to in_scope_urls in both memory and YAML on disk.

    Deduplicates against existing entries. Writes to self.config_path.
    """
    if not urls:
        return
    current = self._scope.get("in_scope_urls", [])
    new_urls = [u for u in urls if u not in current]
    if not new_urls:
        return
    current.extend(new_urls)
    self._scope["in_scope_urls"] = current
    self._raw.setdefault("program_scope", {})["in_scope_urls"] = current
    self.save(self.config_path)
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_config_loader.py -v`
Expected: All PASS

**Step 5: Commit**

```bash
git add tests/test_config_loader.py wstg_orchestrator/utils/config_loader.py
git commit -m "feat: add config_path storage and append_in_scope_urls to ConfigLoader"
```

---

### Task 3: auto_expand_scope config property

**Files:**
- Test: `tests/test_config_loader.py`
- Modify: `wstg_orchestrator/utils/config_loader.py`

**Step 1: Write the failing tests**

Add to `tests/test_config_loader.py`:

```python
def test_auto_expand_scope_defaults_true(config_file):
    """auto_expand_scope defaults to True when not set in config."""
    config = ConfigLoader(config_file)
    assert config.auto_expand_scope is True


def test_auto_expand_scope_reads_from_config():
    """auto_expand_scope reads from program_scope when explicitly set."""
    cfg = {
        "program_scope": {
            "base_domain": "test.com",
            "auto_expand_scope": False,
        },
    }
    fd, path = tempfile.mkstemp(suffix=".yaml")
    os.close(fd)
    with open(path, "w") as f:
        yaml.dump(cfg, f)
    try:
        config = ConfigLoader(path)
        assert config.auto_expand_scope is False
    finally:
        os.remove(path)
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_config_loader.py::test_auto_expand_scope_defaults_true -v`
Expected: FAIL with `AttributeError`

**Step 3: Write minimal implementation**

Add property to `wstg_orchestrator/utils/config_loader.py` (after the `notes` property):

```python
@property
def auto_expand_scope(self) -> bool:
    return self._scope.get("auto_expand_scope", True)
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_config_loader.py -v`
Expected: All PASS

**Step 5: Commit**

```bash
git add tests/test_config_loader.py wstg_orchestrator/utils/config_loader.py
git commit -m "feat: add auto_expand_scope config property"
```

---

### Task 4: Add acquired_companies state key

**Files:**
- Test: `tests/test_state_manager.py`
- Modify: `wstg_orchestrator/state_manager.py:10-32`

**Step 1: Write the failing test**

Add to `tests/test_state_manager.py`:

```python
def test_acquired_companies_state_key(tmp_path):
    """acquired_companies is a valid state key initialized as empty list."""
    state_file = str(tmp_path / "state.json")
    sm = StateManager(state_file, "example.com", "TestCorp")
    assert sm.get("acquired_companies") == []
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_state_manager.py::test_acquired_companies_state_key -v`
Expected: FAIL — `assert None == []` (key doesn't exist in STATE_KEYS/LIST_KEYS)

**Step 3: Write minimal implementation**

In `wstg_orchestrator/state_manager.py`, add `"acquired_companies"` to both `STATE_KEYS` (line 19, before the closing bracket) and `LIST_KEYS` (line 31, before the closing bracket):

STATE_KEYS line 19: add `"acquired_companies"` after `"ip_ranges"`:
```python
"asns", "ip_ranges", "acquired_companies",
```

LIST_KEYS line 31: add `"acquired_companies"` after `"ip_ranges"`:
```python
"asns", "ip_ranges", "acquired_companies",
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_state_manager.py -v`
Expected: All PASS

**Step 5: Commit**

```bash
git add tests/test_state_manager.py wstg_orchestrator/state_manager.py
git commit -m "feat: add acquired_companies state key"
```

---

### Task 5: Wikipedia acquisition parsing

**Files:**
- Test: `tests/test_reconnaissance.py`
- Modify: `wstg_orchestrator/modules/reconnaissance.py`

This task adds two methods:
- `_fetch_wikipedia_acquisitions(company_name)` — async, fetches + parses Wikipedia API
- `_parse_wikipedia_acquisitions(wikitext)` — pure parser, extracts acquisitions from wikitext

**Step 1: Write the failing tests**

Add to `tests/test_reconnaissance.py`:

```python
def test_parse_wikipedia_acquisitions_extracts_table_rows(recon_module):
    """Parses wiki table rows containing company name, domain, and year."""
    wikitext = (
        "== Acquisitions ==\n"
        "{| class=\"wikitable\"\n"
        "|-\n"
        "! Company !! Date !! Notes\n"
        "|-\n"
        "| [https://instagram.com Instagram] || October 2012 || Photo sharing\n"
        "|-\n"
        "| [https://whatsapp.com WhatsApp] || February 2014 || Messaging\n"
        "|-\n"
        "| Onavo || 2013 || VPN app\n"
        "|}\n"
    )
    results = recon_module._parse_wikipedia_acquisitions(wikitext)
    domains = [r["domain"] for r in results]
    companies = [r["company"] for r in results]
    assert "instagram.com" in domains
    assert "whatsapp.com" in domains
    assert "Instagram" in companies
    assert "WhatsApp" in companies
    # Onavo has no URL in the wikitext, so no domain extracted
    assert all(d != "" for d in domains)


def test_parse_wikipedia_acquisitions_no_section(recon_module):
    """Returns empty list when no acquisitions section exists."""
    wikitext = "== History ==\nFounded in 2004.\n== Products ==\nSome products.\n"
    results = recon_module._parse_wikipedia_acquisitions(wikitext)
    assert results == []


def test_parse_wikipedia_acquisitions_empty_table(recon_module):
    """Returns empty list when acquisitions section has no table rows with URLs."""
    wikitext = (
        "== Acquisitions ==\n"
        "The company has made several acquisitions.\n"
    )
    results = recon_module._parse_wikipedia_acquisitions(wikitext)
    assert results == []


def test_parse_wikipedia_acquisitions_list_page_format(recon_module):
    """Handles 'List of mergers and acquisitions by X' page format with external links."""
    wikitext = (
        "== List ==\n"
        "{| class=\"wikitable\"\n"
        "|-\n"
        "| [https://youtube.com YouTube] || October 2006 || $1.65B\n"
        "|}\n"
    )
    results = recon_module._parse_wikipedia_acquisitions(wikitext)
    assert len(results) >= 1
    assert results[0]["domain"] == "youtube.com"
    assert results[0]["company"] == "YouTube"


@pytest.mark.asyncio
async def test_fetch_wikipedia_acquisitions_success(recon_module):
    """Successful Wikipedia API call returns parsed acquisitions."""
    mock_response = {
        "parse": {
            "wikitext": {
                "*": (
                    "== Acquisitions ==\n"
                    "{| class=\"wikitable\"\n"
                    "|-\n"
                    "| [https://instagram.com Instagram] || 2012 || Photo sharing\n"
                    "|}\n"
                )
            }
        }
    }
    with patch("aiohttp.ClientSession") as mock_session_cls:
        mock_session = AsyncMock()
        mock_session_cls.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.json = AsyncMock(return_value=mock_response)
        mock_session.get = AsyncMock(return_value=mock_resp)
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        results = await recon_module._fetch_wikipedia_acquisitions("Meta")
    assert len(results) >= 1
    assert results[0]["source"] == "wikipedia"


@pytest.mark.asyncio
async def test_fetch_wikipedia_acquisitions_no_page(recon_module):
    """Returns empty list when Wikipedia page doesn't exist."""
    mock_response = {"error": {"code": "missingtitle"}}
    with patch("aiohttp.ClientSession") as mock_session_cls:
        mock_session = AsyncMock()
        mock_session_cls.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.json = AsyncMock(return_value=mock_response)
        mock_session.get = AsyncMock(return_value=mock_resp)
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        results = await recon_module._fetch_wikipedia_acquisitions("NonexistentCorp12345")
    assert results == []


@pytest.mark.asyncio
async def test_fetch_wikipedia_acquisitions_tries_list_page(recon_module):
    """Falls back to 'List of mergers and acquisitions by X' page."""
    # First call (company page) returns no acquisitions section
    no_acq_response = {
        "parse": {"wikitext": {"*": "== History ==\nFounded in 2004.\n"}}
    }
    # Second call (list page) returns acquisitions
    list_response = {
        "parse": {
            "wikitext": {
                "*": (
                    "{| class=\"wikitable\"\n"
                    "|-\n"
                    "| [https://youtube.com YouTube] || 2006 || $1.65B\n"
                    "|}\n"
                )
            }
        }
    }

    call_count = 0

    async def mock_get(url, **kwargs):
        nonlocal call_count
        resp = AsyncMock()
        resp.status = 200
        if call_count == 0:
            resp.json = AsyncMock(return_value=no_acq_response)
        else:
            resp.json = AsyncMock(return_value=list_response)
        resp.__aenter__ = AsyncMock(return_value=resp)
        resp.__aexit__ = AsyncMock(return_value=False)
        call_count += 1
        return resp

    with patch("aiohttp.ClientSession") as mock_session_cls:
        mock_session = AsyncMock()
        mock_session_cls.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_session.get = mock_get

        results = await recon_module._fetch_wikipedia_acquisitions("Alphabet")
    assert len(results) >= 1
    assert results[0]["domain"] == "youtube.com"
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_reconnaissance.py::test_parse_wikipedia_acquisitions_extracts_table_rows -v`
Expected: FAIL with `AttributeError: 'ReconModule' object has no attribute '_parse_wikipedia_acquisitions'`

**Step 3: Write minimal implementation**

Add to `wstg_orchestrator/modules/reconnaissance.py`, after the `_CIDR_RE` class constant (line 27), add a new regex:

```python
_WIKI_LINK_RE = re.compile(
    r'\[https?://([^\s/\]]+)(?:/[^\s\]]*)?\s+([^\]]+)\]'
)
```

Add these two methods after `_asn_enumeration` (after line 226):

```python
def _parse_wikipedia_acquisitions(self, wikitext: str) -> list[dict]:
    """Parse Wikipedia wikitext for acquisition entries.

    Looks for wiki table rows containing external links [https://domain.com Name].
    Extracts domain and company name. Searches within acquisition-related sections
    first, falls back to scanning the entire wikitext for table rows with links.
    """
    results = []
    seen_domains = set()

    # Check for acquisition-related sections
    acq_headings = re.compile(
        r'={2,}\s*(?:acquisitions|mergers and acquisitions|'
        r'list of (?:mergers and )?acquisitions|acquired companies)\s*={2,}',
        re.IGNORECASE,
    )
    sections = acq_headings.split(wikitext)

    # If we found an acquisitions section, only parse content after the heading
    if len(sections) > 1:
        # Take everything after the first matching heading until the next same-level heading
        content = sections[1]
        # Truncate at the next == heading of same or higher level
        next_heading = re.search(r'\n={2}\s*[^=]', content)
        if next_heading:
            content = content[:next_heading.start()]
    else:
        # No acquisitions section found — return empty
        return []

    # Extract [https://domain.com CompanyName] patterns from table rows
    for match in self._WIKI_LINK_RE.finditer(content):
        domain = match.group(1).lower()
        company = match.group(2).strip()
        if domain not in seen_domains:
            seen_domains.add(domain)
            # Try to extract year from the same table row
            row_start = content.rfind("|-", 0, match.start())
            row_text = content[row_start:match.start() + 200] if row_start != -1 else ""
            year_match = re.search(r'((?:19|20)\d{2})', row_text)
            year = year_match.group(1) if year_match else ""

            results.append({
                "company": company,
                "domain": domain,
                "year": year,
                "source": "wikipedia",
            })

    return results

async def _fetch_wikipedia_acquisitions(self, company_name: str) -> list[dict]:
    """Fetch and parse acquisition data from Wikipedia.

    Tries the company page first, then 'List of mergers and acquisitions by X'.
    Returns list of dicts: {company, domain, year, source}.
    """
    import aiohttp

    pages_to_try = [
        company_name,
        f"List of mergers and acquisitions by {company_name}",
    ]
    base_url = "https://en.wikipedia.org/w/api.php"

    async with aiohttp.ClientSession() as session:
        for page_title in pages_to_try:
            params = {
                "action": "parse",
                "page": page_title,
                "prop": "wikitext",
                "format": "json",
            }
            try:
                async with session.get(base_url, params=params, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    data = await resp.json()

                if "error" in data:
                    self.logger.debug(f"Wikipedia page not found: {page_title}")
                    continue

                wikitext = data.get("parse", {}).get("wikitext", {}).get("*", "")
                if not wikitext:
                    continue

                self.evidence.log_tool_output("reconnaissance", f"wikipedia_{page_title.replace(' ', '_')}", wikitext)
                results = self._parse_wikipedia_acquisitions(wikitext)
                if results:
                    return results

            except Exception as e:
                self.logger.warning(f"Wikipedia API error for '{page_title}': {e}")
                continue

    return []
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_reconnaissance.py -k "wikipedia" -v`
Expected: All PASS

**Step 5: Commit**

```bash
git add tests/test_reconnaissance.py wstg_orchestrator/modules/reconnaissance.py
git commit -m "feat: add Wikipedia acquisition parsing to recon module"
```

---

### Task 6: Crunchbase/Playwright fallback

**Files:**
- Test: `tests/test_reconnaissance.py`
- Modify: `wstg_orchestrator/modules/reconnaissance.py`

This task adds `_fetch_crunchbase_acquisitions(company_name)` which uses Playwright MCP tools.

**Step 1: Write the failing tests**

Add to `tests/test_reconnaissance.py`:

```python
@pytest.mark.asyncio
async def test_fetch_crunchbase_acquisitions_success(recon_module):
    """Extracts acquisitions from Crunchbase via Playwright MCP tools."""
    search_snapshot = (
        "- link: Organization result\n"
        "  url: /organization/meta-platforms\n"
        "  text: Meta Platforms\n"
    )
    acq_snapshot = (
        "- row: Instagram | instagram.com | October 2012\n"
        "- row: WhatsApp | whatsapp.com | February 2014\n"
        "- row: Oculus VR | oculus.com | March 2014\n"
    )

    async def mock_mcp_call(tool_name, **kwargs):
        if tool_name == "browser_navigate":
            return {"success": True}
        if tool_name == "browser_snapshot":
            if not hasattr(mock_mcp_call, '_snapshot_count'):
                mock_mcp_call._snapshot_count = 0
            mock_mcp_call._snapshot_count += 1
            if mock_mcp_call._snapshot_count <= 2:
                return {"content": search_snapshot}
            return {"content": acq_snapshot}
        if tool_name == "browser_click":
            return {"success": True}
        if tool_name == "browser_close":
            return {"success": True}
        return {}

    with patch.object(recon_module, '_call_playwright_mcp', side_effect=mock_mcp_call):
        results = await recon_module._fetch_crunchbase_acquisitions("Meta")

    domains = [r["domain"] for r in results]
    assert "instagram.com" in domains
    assert "whatsapp.com" in domains
    assert all(r["source"] == "crunchbase" for r in results)


@pytest.mark.asyncio
async def test_fetch_crunchbase_acquisitions_playwright_unavailable(recon_module):
    """Returns empty list when Playwright MCP is not available."""
    async def mock_mcp_call(tool_name, **kwargs):
        raise RuntimeError("MCP server not configured")

    with patch.object(recon_module, '_call_playwright_mcp', side_effect=mock_mcp_call):
        results = await recon_module._fetch_crunchbase_acquisitions("Meta")

    assert results == []


@pytest.mark.asyncio
async def test_fetch_crunchbase_acquisitions_no_results(recon_module):
    """Returns empty list when Crunchbase has no acquisition data."""
    async def mock_mcp_call(tool_name, **kwargs):
        if tool_name == "browser_navigate":
            return {"success": True}
        if tool_name == "browser_snapshot":
            return {"content": "No acquisitions found."}
        if tool_name == "browser_click":
            return {"success": True}
        if tool_name == "browser_close":
            return {"success": True}
        return {}

    with patch.object(recon_module, '_call_playwright_mcp', side_effect=mock_mcp_call):
        results = await recon_module._fetch_crunchbase_acquisitions("TinyStartup")

    assert results == []
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_reconnaissance.py::test_fetch_crunchbase_acquisitions_success -v`
Expected: FAIL with `AttributeError`

**Step 3: Write minimal implementation**

Add two methods to `wstg_orchestrator/modules/reconnaissance.py` after `_fetch_wikipedia_acquisitions`:

```python
async def _call_playwright_mcp(self, tool_name: str, **kwargs) -> dict:
    """Call a Playwright MCP tool. Raises RuntimeError if unavailable.

    This is a thin wrapper that subclasses or test mocks can override.
    In production, the orchestrator injects MCP tool access via the
    callback_server or a dedicated MCP client. For now, we attempt
    to use the globally available MCP tool functions.
    """
    try:
        from wstg_orchestrator.utils.mcp_client import call_mcp_tool
        return await call_mcp_tool("playwright", tool_name, **kwargs)
    except (ImportError, Exception) as e:
        raise RuntimeError(f"Playwright MCP unavailable: {e}")

async def _fetch_crunchbase_acquisitions(self, company_name: str) -> list[dict]:
    """Fetch acquisition data from Crunchbase using Playwright browser automation.

    Flow: search for company -> click best match -> navigate to acquisitions tab
    -> extract table data. Returns list of {company, domain, year, source} dicts.
    """
    results = []
    try:
        # Step 1: Navigate to Crunchbase search
        search_url = f"https://www.crunchbase.com/textsearch?q={company_name}"
        await self._call_playwright_mcp("browser_navigate", url=search_url)

        # Step 2: Wait and get search results
        snapshot = await self._call_playwright_mcp("browser_snapshot")
        search_content = snapshot.get("content", "")

        if not search_content or "organization" not in search_content.lower():
            self.logger.info("No Crunchbase results found")
            await self._call_playwright_mcp("browser_close")
            return []

        # Step 3: Click the first organization result
        await self._call_playwright_mcp("browser_click", ref="Organization result")

        # Step 4: Get the org page snapshot to find the URL
        snapshot = await self._call_playwright_mcp("browser_snapshot")
        org_content = snapshot.get("content", "")

        # Step 5: Navigate to acquisitions tab
        # Extract current URL path from snapshot or construct it
        org_path = ""
        for line in org_content.splitlines():
            if "/organization/" in line:
                match = re.search(r'(/organization/[^\s\]"]+)', line)
                if match:
                    org_path = match.group(1)
                    break

        if org_path:
            acq_url = f"https://www.crunchbase.com{org_path}/acquisitions"
        else:
            # Fall back to constructing URL from company name
            slug = company_name.lower().replace(" ", "-")
            acq_url = f"https://www.crunchbase.com/organization/{slug}/acquisitions"

        await self._call_playwright_mcp("browser_navigate", url=acq_url)

        # Step 6: Get acquisitions table
        snapshot = await self._call_playwright_mcp("browser_snapshot")
        acq_content = snapshot.get("content", "")

        self.evidence.log_tool_output(
            "reconnaissance", "crunchbase_acquisitions", acq_content,
        )

        # Step 7: Parse acquisitions from snapshot content
        # Crunchbase table rows typically contain: Company | domain | date
        seen_domains = set()
        domain_re = re.compile(r'([a-zA-Z0-9][-a-zA-Z0-9]*\.(?:com|org|net|io|co|ai|app|dev|xyz|me|tv|us|uk|de))')
        year_re = re.compile(r'((?:19|20)\d{2})')

        for line in acq_content.splitlines():
            line = line.strip()
            if not line or line.startswith("!") or line.startswith("-"):
                # Parse structured snapshot lines like "- row: Company | domain | date"
                if line.startswith("- row:"):
                    line = line[6:].strip()
                else:
                    continue

            parts = [p.strip() for p in line.split("|")]
            if len(parts) < 2:
                continue

            company = parts[0].strip()
            domain_match = domain_re.search(line)
            year_match = year_re.search(line)

            if domain_match:
                domain = domain_match.group(1).lower()
                if domain not in seen_domains:
                    seen_domains.add(domain)
                    results.append({
                        "company": company,
                        "domain": domain,
                        "year": year_match.group(1) if year_match else "",
                        "source": "crunchbase",
                    })

        # Step 8: Clean up browser
        await self._call_playwright_mcp("browser_close")

    except RuntimeError as e:
        self.logger.warning(f"Playwright MCP unavailable, skipping Crunchbase: {e}")
    except Exception as e:
        self.logger.warning(f"Crunchbase scraping failed: {e}")
        try:
            await self._call_playwright_mcp("browser_close")
        except Exception:
            pass

    return results
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_reconnaissance.py -k "crunchbase" -v`
Expected: All PASS

**Step 5: Commit**

```bash
git add tests/test_reconnaissance.py wstg_orchestrator/modules/reconnaissance.py
git commit -m "feat: add Crunchbase/Playwright fallback for acquisition discovery"
```

---

### Task 7: Wire acquisition_discovery into execute()

**Files:**
- Test: `tests/test_reconnaissance.py`
- Modify: `wstg_orchestrator/modules/reconnaissance.py:22` (SUBCATEGORIES) and `execute()` method

This task adds the `_acquisition_discovery()` orchestration method and wires it into `execute()`.

**Step 1: Write the failing tests**

Add to `tests/test_reconnaissance.py`:

```python
def test_subcategories_includes_acquisition_discovery(recon_module):
    """acquisition_discovery is the second subcategory (after asn_enumeration)."""
    assert "acquisition_discovery" in recon_module.SUBCATEGORIES
    assert recon_module.SUBCATEGORIES.index("acquisition_discovery") == 1
    assert recon_module.SUBCATEGORIES.index("acquisition_discovery") < recon_module.SUBCATEGORIES.index("passive_osint")


@pytest.mark.asyncio
async def test_acquisition_discovery_enriches_state(recon_module):
    """Full flow: Wikipedia returns acquisitions, state and scope are updated."""
    recon_module.config.company_name = "Meta"
    recon_module.config.auto_expand_scope = True
    recon_module.config.config_path = "/tmp/test_config.yaml"

    wiki_results = [
        {"company": "Instagram", "domain": "instagram.com", "year": "2012", "source": "wikipedia"},
        {"company": "WhatsApp", "domain": "whatsapp.com", "year": "2014", "source": "wikipedia"},
    ]
    with patch.object(recon_module, '_fetch_wikipedia_acquisitions', new_callable=AsyncMock, return_value=wiki_results):
        await recon_module._acquisition_discovery()

    # Check state enrichment
    enrich_calls = {}
    for call in recon_module.state.enrich.call_args_list:
        key = call.args[0]
        enrich_calls.setdefault(key, []).extend(call.args[1])

    assert "instagram.com" in enrich_calls.get("discovered_subdomains", [])
    assert "whatsapp.com" in enrich_calls.get("discovered_subdomains", [])
    assert any(a["company"] == "Instagram" for a in enrich_calls.get("acquired_companies", []))

    # Check scope expansion
    recon_module.scope.add_in_scope_hostnames.assert_called_once_with(["instagram.com", "whatsapp.com"])
    recon_module.config.append_in_scope_urls.assert_called_once_with(["instagram.com", "whatsapp.com"])


@pytest.mark.asyncio
async def test_acquisition_discovery_falls_back_to_crunchbase(recon_module):
    """When Wikipedia returns nothing, Crunchbase fallback is tried."""
    recon_module.config.company_name = "SmallCorp"
    recon_module.config.auto_expand_scope = True
    recon_module.config.config_path = "/tmp/test_config.yaml"

    cb_results = [
        {"company": "AcquiredCo", "domain": "acquiredco.com", "year": "2023", "source": "crunchbase"},
    ]
    with patch.object(recon_module, '_fetch_wikipedia_acquisitions', new_callable=AsyncMock, return_value=[]):
        with patch.object(recon_module, '_fetch_crunchbase_acquisitions', new_callable=AsyncMock, return_value=cb_results):
            await recon_module._acquisition_discovery()

    enrich_calls = {}
    for call in recon_module.state.enrich.call_args_list:
        key = call.args[0]
        enrich_calls.setdefault(key, []).extend(call.args[1])
    assert "acquiredco.com" in enrich_calls.get("discovered_subdomains", [])


@pytest.mark.asyncio
async def test_acquisition_discovery_skips_without_company_name(recon_module):
    """Skips when company_name is empty."""
    recon_module.config.company_name = ""
    await recon_module._acquisition_discovery()
    assert recon_module.state.enrich.call_count == 0


@pytest.mark.asyncio
async def test_acquisition_discovery_respects_auto_expand_false(recon_module):
    """When auto_expand_scope is False, domains go to state but not scope."""
    recon_module.config.company_name = "Meta"
    recon_module.config.auto_expand_scope = False
    recon_module.config.config_path = "/tmp/test_config.yaml"

    wiki_results = [
        {"company": "Instagram", "domain": "instagram.com", "year": "2012", "source": "wikipedia"},
    ]
    with patch.object(recon_module, '_fetch_wikipedia_acquisitions', new_callable=AsyncMock, return_value=wiki_results):
        await recon_module._acquisition_discovery()

    # State should still be enriched
    enrich_calls = {}
    for call in recon_module.state.enrich.call_args_list:
        key = call.args[0]
        enrich_calls.setdefault(key, []).extend(call.args[1])
    assert "instagram.com" in enrich_calls.get("discovered_subdomains", [])

    # But scope should NOT be expanded
    recon_module.scope.add_in_scope_hostnames.assert_not_called()
    recon_module.config.append_in_scope_urls.assert_not_called()


@pytest.mark.asyncio
async def test_execute_runs_acquisition_discovery_after_asn(recon_module):
    """acquisition_discovery runs after asn_enumeration, before passive_osint."""
    call_order = []

    async def mock_asn():
        call_order.append("asn_enumeration")

    async def mock_acq():
        call_order.append("acquisition_discovery")

    async def mock_passive():
        call_order.append("passive_osint")

    async def mock_harvest():
        call_order.append("url_harvesting")

    async def mock_live():
        call_order.append("live_host_validation")

    async def mock_params():
        call_order.append("parameter_harvesting")

    with patch.object(recon_module, '_asn_enumeration', side_effect=mock_asn):
        with patch.object(recon_module, '_acquisition_discovery', side_effect=mock_acq):
            with patch.object(recon_module, '_passive_osint', side_effect=mock_passive):
                with patch.object(recon_module, '_url_harvesting', side_effect=mock_harvest):
                    with patch.object(recon_module, '_live_host_validation', side_effect=mock_live):
                        with patch.object(recon_module, '_parameter_harvesting', side_effect=mock_params):
                            await recon_module.execute()

    assert call_order[0] == "asn_enumeration"
    assert call_order[1] == "acquisition_discovery"
    assert call_order[2] == "passive_osint"
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_reconnaissance.py::test_subcategories_includes_acquisition_discovery -v`
Expected: FAIL — `"acquisition_discovery"` not in SUBCATEGORIES

**Step 3: Write minimal implementation**

3a. Update `SUBCATEGORIES` on line 22 of `reconnaissance.py`:

```python
SUBCATEGORIES = ["asn_enumeration", "acquisition_discovery", "passive_osint", "url_harvesting", "live_host_validation", "parameter_harvesting"]
```

3b. Add the `_acquisition_discovery` method after `_fetch_crunchbase_acquisitions`:

```python
async def _acquisition_discovery(self):
    """Discover companies acquired by the target and add their domains to scope."""
    company_name = self.config.company_name
    if not company_name:
        self.logger.warning("No company_name configured, skipping acquisition discovery")
        return

    self.logger.info(f"Starting acquisition discovery for: {company_name}")

    # Try Wikipedia first (lightweight, no browser needed)
    acquisitions = await self._fetch_wikipedia_acquisitions(company_name)

    # Fall back to Crunchbase via Playwright if Wikipedia yielded nothing
    if not acquisitions:
        self.logger.info("Wikipedia returned no acquisitions, trying Crunchbase")
        acquisitions = await self._fetch_crunchbase_acquisitions(company_name)

    if not acquisitions:
        self.logger.info("No acquisitions found from any source")
        return

    # Extract domains
    domains = [a["domain"] for a in acquisitions if a.get("domain")]
    domains = list(dict.fromkeys(domains))  # deduplicate, preserve order

    # Enrich state
    self.state.enrich("acquired_companies", acquisitions)
    self.state.enrich("discovered_subdomains", domains)
    self.evidence.log_parsed("reconnaissance", "acquired_companies", acquisitions)

    self.logger.info(
        f"Found {len(acquisitions)} acquisitions with {len(domains)} domains"
    )

    # Expand scope if enabled
    auto_expand = getattr(self.config, "auto_expand_scope", True)
    if auto_expand and domains:
        self.scope.add_in_scope_hostnames(domains)
        self.config.append_in_scope_urls(domains)
        self.logger.info(
            f"[SCOPE EXPANSION] Added {len(domains)} acquisition domains to scope:\n"
            + "\n".join(f"  + {d}" for d in domains)
        )
    elif domains:
        self.logger.info(
            f"auto_expand_scope disabled — {len(domains)} acquisition domains logged but not added to scope"
        )
```

3c. Update `execute()` to wire in the new subcategory (insert after line 45):

```python
async def execute(self):
    if not self.should_skip_subcategory("asn_enumeration"):
        await self._asn_enumeration()
        self.mark_subcategory_complete("asn_enumeration")

    if not self.should_skip_subcategory("acquisition_discovery"):
        await self._acquisition_discovery()
        self.mark_subcategory_complete("acquisition_discovery")

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

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_reconnaissance.py -v`
Expected: All PASS (including all prior tests — execution order tests will need updating, see step 4b)

4b. Update the existing execution order test `test_execute_runs_url_harvesting_before_live_hosts` (line 81) and `test_execute_runs_asn_enumeration_first` (line 393) to include the new `_acquisition_discovery` mock. These tests patch all subcategory methods — they'll fail without the new mock.

In `test_execute_runs_url_harvesting_before_live_hosts`, add a mock for `_acquisition_discovery`:

```python
async def mock_acq():
    call_order.append("acquisition_discovery")
```

And add a `patch.object(recon_module, '_acquisition_discovery', side_effect=mock_acq)` to the `with` block.

Similarly update `test_execute_runs_asn_enumeration_first`.

**Step 5: Run full test suite**

Run: `pytest tests/ -v`
Expected: All PASS

**Step 6: Commit**

```bash
git add tests/test_reconnaissance.py wstg_orchestrator/modules/reconnaissance.py
git commit -m "feat: wire acquisition_discovery subcategory into recon pipeline"
```

---

### Task 8: Update existing execution order tests

**Files:**
- Modify: `tests/test_reconnaissance.py:81-108` and `tests/test_reconnaissance.py:393-420`

The two existing tests that mock all subcategory methods need an `_acquisition_discovery` mock added.

**Step 1: Update test_execute_runs_url_harvesting_before_live_hosts (line 81)**

Replace the test body to include the new mock:

```python
@pytest.mark.asyncio
async def test_execute_runs_url_harvesting_before_live_hosts(recon_module):
    """URL harvesting must run before live host validation."""
    call_order = []

    async def mock_asn():
        call_order.append("asn_enumeration")

    async def mock_acq():
        call_order.append("acquisition_discovery")

    async def mock_passive():
        call_order.append("passive_osint")

    async def mock_harvest():
        call_order.append("url_harvesting")

    async def mock_live():
        call_order.append("live_host_validation")

    async def mock_params():
        call_order.append("parameter_harvesting")

    with patch.object(recon_module, '_asn_enumeration', side_effect=mock_asn):
        with patch.object(recon_module, '_acquisition_discovery', side_effect=mock_acq):
            with patch.object(recon_module, '_passive_osint', side_effect=mock_passive):
                with patch.object(recon_module, '_url_harvesting', side_effect=mock_harvest):
                    with patch.object(recon_module, '_live_host_validation', side_effect=mock_live):
                        with patch.object(recon_module, '_parameter_harvesting', side_effect=mock_params):
                            await recon_module.execute()

    assert call_order.index("url_harvesting") < call_order.index("live_host_validation")
```

**Step 2: Update test_execute_runs_asn_enumeration_first (line 393)**

Replace the test body similarly:

```python
@pytest.mark.asyncio
async def test_execute_runs_asn_enumeration_first(recon_module):
    """asn_enumeration runs before passive_osint in execute()."""
    call_order = []

    async def mock_asn():
        call_order.append("asn_enumeration")

    async def mock_acq():
        call_order.append("acquisition_discovery")

    async def mock_passive():
        call_order.append("passive_osint")

    async def mock_harvest():
        call_order.append("url_harvesting")

    async def mock_live():
        call_order.append("live_host_validation")

    async def mock_params():
        call_order.append("parameter_harvesting")

    with patch.object(recon_module, '_asn_enumeration', side_effect=mock_asn):
        with patch.object(recon_module, '_acquisition_discovery', side_effect=mock_acq):
            with patch.object(recon_module, '_passive_osint', side_effect=mock_passive):
                with patch.object(recon_module, '_url_harvesting', side_effect=mock_harvest):
                    with patch.object(recon_module, '_live_host_validation', side_effect=mock_live):
                        with patch.object(recon_module, '_parameter_harvesting', side_effect=mock_params):
                            await recon_module.execute()

    assert call_order[0] == "asn_enumeration"
    assert call_order[1] == "acquisition_discovery"
    assert call_order[2] == "passive_osint"
```

**Step 3: Run full test suite**

Run: `pytest tests/ -v`
Expected: All PASS

**Step 4: Commit**

```bash
git add tests/test_reconnaissance.py
git commit -m "fix: update execution order tests for acquisition_discovery subcategory"
```

---

### Task 9: Final verification

**Step 1: Run the full test suite**

Run: `pytest tests/ -v`
Expected: All tests pass, no regressions

**Step 2: Verify no import errors**

Run: `python -c "from wstg_orchestrator.modules.reconnaissance import ReconModule; print('OK')"`
Expected: `OK`

**Step 3: Verify SUBCATEGORIES order**

Run: `python -c "from wstg_orchestrator.modules.reconnaissance import ReconModule; print(ReconModule.SUBCATEGORIES)"`
Expected: `['asn_enumeration', 'acquisition_discovery', 'passive_osint', 'url_harvesting', 'live_host_validation', 'parameter_harvesting']`
