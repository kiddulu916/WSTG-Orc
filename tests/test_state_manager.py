# tests/test_state_manager.py
import json
import os
import tempfile
import pytest
from wstg_orchestrator.state_manager import StateManager
from wstg_orchestrator.utils.scope_checker import ScopeChecker


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


def test_discovered_directory_paths_key_exists(tmp_state_file):
    sm = StateManager(tmp_state_file, target_domain="example.com")
    assert sm.get("discovered_directory_paths") == []


def test_enrich_filters_out_of_scope(tmp_state_file):
    scope = ScopeChecker(
        base_domain="example.com",
        out_of_scope_urls=["admin.example.com"],
    )
    sm = StateManager(tmp_state_file, target_domain="example.com", scope_checker=scope)
    sm.enrich("discovered_subdomains", ["app.example.com", "admin.example.com", "api.example.com"])
    result = sm.get("discovered_subdomains")
    assert "app.example.com" in result
    assert "api.example.com" in result
    assert "admin.example.com" not in result


def test_enrich_filters_path_component_out_of_scope(tmp_state_file):
    scope = ScopeChecker(
        base_domain="example.com",
        out_of_scope_urls=["*/admin/*"],
    )
    sm = StateManager(tmp_state_file, target_domain="example.com", scope_checker=scope)
    sm.enrich("endpoints", ["example.com/api/users", "example.com/admin/settings"])
    result = sm.get("endpoints")
    assert "example.com/api/users" in result
    assert "example.com/admin/settings" not in result


def test_enrich_without_scope_checker_no_filtering(tmp_state_file):
    sm = StateManager(tmp_state_file, target_domain="example.com")
    sm.enrich("discovered_subdomains", ["anything.com"])
    assert "anything.com" in sm.get("discovered_subdomains")


def test_enrich_filters_dict_values_by_url_key(tmp_state_file):
    scope = ScopeChecker(
        base_domain="example.com",
        out_of_scope_urls=["admin.example.com"],
    )
    sm = StateManager(tmp_state_file, target_domain="example.com", scope_checker=scope)
    sm.enrich("parameters", [
        {"url": "app.example.com/search?q=test", "name": "q", "value": "test"},
        {"url": "admin.example.com/login?user=admin", "name": "user", "value": "admin"},
    ])
    result = sm.get("parameters")
    assert len(result) == 1
    assert result[0]["url"] == "app.example.com/search?q=test"