import json
import os
import tempfile
import threading
import time
from pathlib import Path

import pytest

from wstg_orchestrator.state_manager import StateManager


class TestStateManager:
    def test_init_fresh_state(self):
        """Test initializing a fresh state file"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            state_file = f.name

        try:
            # Remove the file so we create fresh
            os.unlink(state_file)

            sm = StateManager(state_file, target_domain="example.com", company_name="TestCorp")

            # Check basic fields
            assert sm.get("target_domain") == "example.com"
            assert sm.get("company_name") == "TestCorp"
            assert sm.get("scan_id") is not None
            assert sm.get("scan_start") is not None

            # Check list fields exist
            list_fields = [
                "discovered_subdomains", "live_hosts", "open_ports",
                "technologies", "server_versions", "frameworks",
                "endpoints", "parameters", "forms", "auth_endpoints",
                "api_endpoints", "cloud_assets", "potential_idor_candidates",
                "valid_usernames", "inferred_cves", "exposed_admin_paths",
                "pending_callbacks", "potential_vulnerabilities",
                "confirmed_vulnerabilities", "evidence_index"
            ]
            for field in list_fields:
                assert isinstance(sm.get(field), list)

            # Check completed_phases
            assert isinstance(sm.get("completed_phases"), dict)
        finally:
            if os.path.exists(state_file):
                os.unlink(state_file)

    def test_get_set(self):
        """Test get and set operations"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            state_file = f.name

        try:
            os.unlink(state_file)
            sm = StateManager(state_file, target_domain="example.com")

            sm.set("custom_key", "custom_value")
            assert sm.get("custom_key") == "custom_value"

            sm.set("custom_list", [1, 2, 3])
            assert sm.get("custom_list") == [1, 2, 3]
        finally:
            if os.path.exists(state_file):
                os.unlink(state_file)

    def test_enrich_with_dedup(self):
        """Test enrich method with deduplication"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            state_file = f.name

        try:
            os.unlink(state_file)
            sm = StateManager(state_file, target_domain="example.com")

            # Add items
            sm.enrich("discovered_subdomains", ["sub1.example.com", "sub2.example.com"])
            assert len(sm.get("discovered_subdomains")) == 2

            # Add with duplicates
            sm.enrich("discovered_subdomains", ["sub2.example.com", "sub3.example.com"])
            subs = sm.get("discovered_subdomains")
            assert len(subs) == 3
            assert "sub1.example.com" in subs
            assert "sub2.example.com" in subs
            assert "sub3.example.com" in subs
        finally:
            if os.path.exists(state_file):
                os.unlink(state_file)

    def test_save_and_load(self):
        """Test save and load round-trip"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            state_file = f.name

        try:
            os.unlink(state_file)

            # Create and populate
            sm1 = StateManager(state_file, target_domain="example.com", company_name="TestCorp")
            sm1.enrich("discovered_subdomains", ["sub1.example.com"])
            sm1.set("custom_field", "test_value")
            sm1.save()

            # Load in new instance
            sm2 = StateManager(state_file)
            assert sm2.get("target_domain") == "example.com"
            assert sm2.get("company_name") == "TestCorp"
            assert "sub1.example.com" in sm2.get("discovered_subdomains")
            assert sm2.get("custom_field") == "test_value"
            assert sm2.get("scan_id") == sm1.get("scan_id")
        finally:
            if os.path.exists(state_file):
                os.unlink(state_file)

    def test_mark_subcategory_complete(self):
        """Test marking subcategories as complete"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            state_file = f.name

        try:
            os.unlink(state_file)
            sm = StateManager(state_file, target_domain="example.com")

            # Mark subcategory complete
            sm.mark_subcategory_complete("recon", "subdomain_enum")
            assert sm.is_subcategory_complete("recon", "subdomain_enum") is True
            assert sm.is_subcategory_complete("recon", "port_scan") is False

            # Verify saved to disk
            sm2 = StateManager(state_file)
            assert sm2.is_subcategory_complete("recon", "subdomain_enum") is True
        finally:
            if os.path.exists(state_file):
                os.unlink(state_file)

    def test_mark_phase_complete(self):
        """Test marking phases as complete"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            state_file = f.name

        try:
            os.unlink(state_file)
            sm = StateManager(state_file, target_domain="example.com")

            # Mark phase complete
            sm.mark_phase_complete("recon")
            assert sm.is_phase_complete("recon") is True
            assert sm.is_phase_complete("mapping") is False

            # Verify saved to disk
            sm2 = StateManager(state_file)
            assert sm2.is_phase_complete("recon") is True
        finally:
            if os.path.exists(state_file):
                os.unlink(state_file)

    def test_thread_safety(self):
        """Test thread-safe operations"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            state_file = f.name

        try:
            os.unlink(state_file)
            sm = StateManager(state_file, target_domain="example.com")

            def add_subdomains(prefix, count):
                for i in range(count):
                    sm.enrich("discovered_subdomains", [f"{prefix}{i}.example.com"])
                    time.sleep(0.001)

            # Create multiple threads
            threads = []
            for prefix in ['a', 'b', 'c']:
                t = threading.Thread(target=add_subdomains, args=(prefix, 10))
                threads.append(t)
                t.start()

            for t in threads:
                t.join()

            # Should have 30 unique subdomains
            subs = sm.get("discovered_subdomains")
            assert len(subs) == 30
        finally:
            if os.path.exists(state_file):
                os.unlink(state_file)

    def test_resume_from_disk(self):
        """Test resuming scan from existing state file"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            state_file = f.name

        try:
            # Create initial state
            os.unlink(state_file)
            sm1 = StateManager(state_file, target_domain="example.com", company_name="TestCorp")
            original_scan_id = sm1.get("scan_id")
            sm1.enrich("discovered_subdomains", ["sub1.example.com", "sub2.example.com"])
            sm1.mark_subcategory_complete("recon", "subdomain_enum")
            sm1.save()

            # Resume without providing domain/company
            sm2 = StateManager(state_file)
            assert sm2.get("scan_id") == original_scan_id
            assert sm2.get("target_domain") == "example.com"
            assert sm2.get("company_name") == "TestCorp"
            assert len(sm2.get("discovered_subdomains")) == 2
            assert sm2.is_subcategory_complete("recon", "subdomain_enum") is True
        finally:
            if os.path.exists(state_file):
                os.unlink(state_file)
