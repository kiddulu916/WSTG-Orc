import pytest
from unittest.mock import MagicMock
from wstg_orchestrator.modules.base_module import BaseModule


class DummyModule(BaseModule):
    PHASE_NAME = "test_phase"
    SUBCATEGORIES = ["sub_a", "sub_b"]
    EVIDENCE_SUBDIRS = ["tool_output", "parsed"]

    async def execute(self):
        self.state.enrich("endpoints", ["https://example.com/test"])
        self.mark_subcategory_complete("sub_a")
        self.mark_subcategory_complete("sub_b")


def test_module_has_required_attrs():
    assert hasattr(BaseModule, "PHASE_NAME")
    assert hasattr(BaseModule, "SUBCATEGORIES")


def test_module_interface():
    state = MagicMock()
    config = MagicMock()
    scope = MagicMock()
    limiter = MagicMock()
    evidence = MagicMock()
    callback = MagicMock()

    mod = DummyModule(state, config, scope, limiter, evidence, callback)
    assert mod.PHASE_NAME == "test_phase"


def test_skip_completed_subcategory():
    state = MagicMock()
    state.is_subcategory_complete.return_value = True
    config = MagicMock()
    scope = MagicMock()
    limiter = MagicMock()
    evidence = MagicMock()
    callback = MagicMock()

    mod = DummyModule(state, config, scope, limiter, evidence, callback)
    assert mod.should_skip_subcategory("sub_a") is True


def test_attack_vector_check():
    state = MagicMock()
    config = MagicMock()
    scope = MagicMock()
    scope.is_attack_vector_allowed.return_value = False
    limiter = MagicMock()
    evidence = MagicMock()
    callback = MagicMock()

    mod = DummyModule(state, config, scope, limiter, evidence, callback)
    assert mod.is_attack_allowed("dos") is False
