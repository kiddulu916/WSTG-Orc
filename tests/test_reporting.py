import json
import os
import tempfile
import pytest
from wstg_orchestrator.reporting import ReportGenerator


@pytest.fixture
def sample_state():
    return {
        "target_domain": "example.com",
        "company_name": "ExCorp",
        "scan_id": "test-123",
        "scan_start": "2026-02-12T00:00:00Z",
        "discovered_subdomains": ["a.example.com", "b.example.com"],
        "live_hosts": ["https://a.example.com"],
        "open_ports": [{"host": "a.example.com", "port": 443}],
        "technologies": ["nginx", "React"],
        "endpoints": ["https://a.example.com/api/users"],
        "parameters": [{"url": "https://a.example.com/search", "name": "q", "method": "GET"}],
        "potential_vulnerabilities": [
            {"type": "xss", "url": "https://a.example.com/search?q=test", "severity": "high",
             "description": "Reflected XSS", "evidence_file": "/evidence/xss.json"},
        ],
        "confirmed_vulnerabilities": [
            {"type": "sqli", "url": "https://a.example.com/api/users?id=1", "severity": "critical",
             "description": "SQL Injection", "evidence_file": "/evidence/sqli.json",
             "reproduction_steps": "1. Send payload ' OR 1=1-- to id param",
             "impact": "Full database access", "mitigation": "Use parameterized queries"},
        ],
        "evidence_index": [],
    }


@pytest.fixture
def reports_dir():
    with tempfile.TemporaryDirectory() as d:
        yield d


def test_generate_attack_surface(sample_state, reports_dir):
    gen = ReportGenerator(sample_state, reports_dir)
    gen.generate_attack_surface()
    path = os.path.join(reports_dir, "attack_surface.json")
    assert os.path.exists(path)
    with open(path) as f:
        data = json.load(f)
    assert "a.example.com" in data["subdomains"]


def test_generate_findings(sample_state, reports_dir):
    gen = ReportGenerator(sample_state, reports_dir)
    gen.generate_potential_findings()
    gen.generate_confirmed_findings()
    assert os.path.exists(os.path.join(reports_dir, "potential_findings.json"))
    assert os.path.exists(os.path.join(reports_dir, "confirmed_findings.json"))


def test_generate_executive_summary(sample_state, reports_dir):
    gen = ReportGenerator(sample_state, reports_dir)
    gen.generate_executive_summary()
    path = os.path.join(reports_dir, "executive_summary.txt")
    assert os.path.exists(path)
    with open(path) as f:
        content = f.read()
    assert "ExCorp" in content
    assert "CRITICAL" in content.upper() or "SQL Injection" in content
