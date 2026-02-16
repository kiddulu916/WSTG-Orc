import time
import pytest
import requests
from wstg_orchestrator.utils.callback_server import CallbackServer


@pytest.fixture
def server():
    srv = CallbackServer(host="127.0.0.1", port=0)
    srv.start()
    time.sleep(0.3)
    yield srv
    srv.stop()


def test_generate_callback_url(server):
    url, token = server.generate_callback(
        module="input_validation",
        parameter="q",
        payload="<script>fetch(CALLBACK)</script>",
    )
    assert token in url
    assert "127.0.0.1" in url


def test_callback_hit_recorded(server):
    url, token = server.generate_callback(
        module="input_validation",
        parameter="q",
        payload="test_payload",
    )
    requests.get(url, timeout=5)
    time.sleep(0.3)
    hits = server.get_hits()
    assert len(hits) >= 1
    assert hits[0]["token"] == token
    assert hits[0]["module"] == "input_validation"


def test_pending_callbacks_tracked(server):
    _, token = server.generate_callback(
        module="recon", parameter="x", payload="p",
    )
    pending = server.get_pending()
    assert any(p["token"] == token for p in pending)


def test_hit_moves_from_pending(server):
    url, token = server.generate_callback(
        module="recon", parameter="x", payload="p",
    )
    requests.get(url, timeout=5)
    time.sleep(0.3)
    pending = server.get_pending()
    assert not any(p["token"] == token for p in pending)
