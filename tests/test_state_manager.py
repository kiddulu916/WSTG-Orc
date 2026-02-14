# tests/test_state_manager.py
import json
import os
import tempfile
import pytest
from wstg_orchestrator.state_manager import StateManager


@pytest.fixture
def tmp_state_file():
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    yield path
    if os.path.exists(path):
        os.remove(path)


def test_init_creates_fresh_state(tmp_state_file):
    sm = StateManager(tmp_state_file, target_domain="example.com", company_name="ExCorp")
    assert sm.get("target_domain") == "example.com"
    assert sm.get("company_name") == "ExCorp"
    assert sm.get("discovered_subdomains") == []
    assert sm.get("scan_id") is not None


def test_enrich_appends_deduplicated(tmp_state_file):
    sm = StateManager(tmp_state_file, target_domain="example.com", company_name="ExCorp")
    sm.enrich("discovered_subdomains", ["a.example.com", "b.example.com"])
    sm.enrich("discovered_subdomains", ["b.example.com", "c.example.com"])
    assert sm.get("discovered_subdomains") == ["a.example.com", "b.example.com", "c.example.com"]


def test_save_and_load(tmp_state_file):
    sm = StateManager(tmp_state_file, target_domain="example.com", company_name="ExCorp")
    sm.enrich("live_hosts", ["h1.example.com"])
    sm.save()
    sm2 = StateManager(tmp_state_file)
    assert sm2.get("live_hosts") == ["h1.example.com"]
    assert sm2.get("target_domain") == "example.com"


def test_mark_subcategory_and_phase_complete(tmp_state_file):
    sm = StateManager(tmp_state_file, target_domain="example.com", company_name="ExCorp")
    sm.mark_subcategory_complete("reconnaissance", "passive_osint")
    phases = sm.get("completed_phases")
    assert phases["reconnaissance"]["subcategories"]["passive_osint"] is True
    assert phases["reconnaissance"]["completed"] is False
    sm.mark_phase_complete("reconnaissance")
    phases = sm.get("completed_phases")
    assert phases["reconnaissance"]["completed"] is True


def test_is_phase_complete(tmp_state_file):
    sm = StateManager(tmp_state_file, target_domain="example.com", company_name="ExCorp")
    assert sm.is_phase_complete("reconnaissance") is False
    sm.mark_phase_complete("reconnaissance")
    assert sm.is_phase_complete("reconnaissance") is True


def test_is_subcategory_complete(tmp_state_file):
    sm = StateManager(tmp_state_file, target_domain="example.com", company_name="ExCorp")
    assert sm.is_subcategory_complete("reconnaissance", "passive_osint") is False
    sm.mark_subcategory_complete("reconnaissance", "passive_osint")
    assert sm.is_subcategory_complete("reconnaissance", "passive_osint") is True


def test_resume_skips_completed(tmp_state_file):
    sm = StateManager(tmp_state_file, target_domain="example.com", company_name="ExCorp")
    sm.mark_phase_complete("reconnaissance")
    sm.mark_subcategory_complete("fingerprinting", "service_scanning")
    sm.save()
    sm2 = StateManager(tmp_state_file)
    assert sm2.is_phase_complete("reconnaissance") is True
    assert sm2.is_subcategory_complete("fingerprinting", "service_scanning") is True
    assert sm2.is_phase_complete("fingerprinting") is False