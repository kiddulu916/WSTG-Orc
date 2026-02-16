import json
import os
import tempfile
import pytest
from wstg_orchestrator.utils.evidence_logger import EvidenceLogger


PHASE_SUBDIRS = {
    "reconnaissance": ["tool_output", "parsed", "evidence", "screenshots"],
    "fingerprinting": [
        "tool_output", "raw_requests", "raw_responses", "parsed",
        "evidence", "potential_exploits", "confirmed_exploits", "screenshots",
    ],
}


@pytest.fixture
def evidence_dir():
    with tempfile.TemporaryDirectory() as d:
        yield d


def test_create_phase_directories(evidence_dir):
    el = EvidenceLogger(evidence_dir, "TestCorp", PHASE_SUBDIRS)
    company_dir = os.path.join(evidence_dir, "TestCorp")
    assert os.path.isdir(company_dir)
    assert os.path.isdir(os.path.join(company_dir, "reconnaissance", "tool_output"))
    assert os.path.isdir(os.path.join(company_dir, "reports"))


def test_log_tool_output(evidence_dir):
    el = EvidenceLogger(evidence_dir, "TestCorp", PHASE_SUBDIRS)
    path = el.log_tool_output("reconnaissance", "subfinder", "sub1.example.com\nsub2.example.com")
    assert os.path.exists(path)
    with open(path) as f:
        assert "sub1.example.com" in f.read()


def test_log_parsed(evidence_dir):
    el = EvidenceLogger(evidence_dir, "TestCorp", PHASE_SUBDIRS)
    data = {"subdomains": ["a.example.com"]}
    path = el.log_parsed("reconnaissance", "subdomains", data)
    assert os.path.exists(path)
    with open(path) as f:
        loaded = json.load(f)
    assert loaded["subdomains"] == ["a.example.com"]


def test_log_request_response(evidence_dir):
    el = EvidenceLogger(evidence_dir, "TestCorp", PHASE_SUBDIRS)
    req_path = el.log_request("fingerprinting", {"method": "GET", "url": "https://example.com"})
    resp_path = el.log_response("fingerprinting", {"status": 200, "body": "OK"})
    assert os.path.exists(req_path)
    assert os.path.exists(resp_path)


def test_log_potential_exploit(evidence_dir):
    el = EvidenceLogger(evidence_dir, "TestCorp", PHASE_SUBDIRS)
    finding = {"type": "sqli", "url": "https://example.com/search?q=test", "payload": "' OR 1=1--"}
    path = el.log_potential_exploit("fingerprinting", finding)
    assert os.path.exists(path)


def test_log_confirmed_exploit(evidence_dir):
    el = EvidenceLogger(evidence_dir, "TestCorp", PHASE_SUBDIRS)
    finding = {"type": "xss", "url": "https://example.com/reflect", "payload": "<script>alert(1)</script>"}
    path = el.log_confirmed_exploit("fingerprinting", finding)
    assert os.path.exists(path)


def test_recon_has_no_raw_requests_dir(evidence_dir):
    el = EvidenceLogger(evidence_dir, "TestCorp", PHASE_SUBDIRS)
    company_dir = os.path.join(evidence_dir, "TestCorp")
    assert not os.path.isdir(os.path.join(company_dir, "reconnaissance", "raw_requests"))
