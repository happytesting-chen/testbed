import pytest

from tests.conftest import ANALYST, EVAL, TOKENS


def test_config_fails_closed_without_tokens(monkeypatch, tmp_path):
    from app.config import ConfigError, load_settings
    for k in ("ANALYST_TOKEN", "EVALUATOR_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(ConfigError):
        load_settings()


def test_config_rejects_shared_tokens(monkeypatch):
    from app.config import ConfigError, load_settings
    monkeypatch.setenv("ANALYST_TOKEN", "same-token-for-both-roles")
    monkeypatch.setenv("EVALUATOR_TOKEN", "same-token-for-both-roles")
    with pytest.raises(ConfigError):
        load_settings()


def test_public_app_has_no_evaluator_routes(make_clients):
    pub, _, _ = make_clients()
    for path in ("/api/runs", "/api/ground-truth", "/api/evaluator/ground-truth", "/api/config", "/docs", "/openapi.json"):
        assert pub.get(path, headers={**ANALYST, **EVAL}).status_code == 404


def test_authentication_required(make_clients):
    pub, _, _ = make_clients()
    assert pub.get("/api/reports").status_code == 401
    assert pub.get("/api/reports", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert pub.post("/api/agent/chat", json={"message": "hi"}).status_code == 401


def test_chat_unavailable_without_provider(make_clients):
    pub, _, _ = make_clients(with_provider=False)
    assert pub.post("/api/agent/chat", json={"message": "hi"}, headers=ANALYST).status_code == 503


def test_evaluator_requires_token(make_clients):
    _, ev, _ = make_clients()
    for path in ("/api/runs", "/api/ground-truth", "/api/config", "/api/validations"):
        assert ev.get(path).status_code == 403
        assert ev.get(path, headers={"X-Evaluator-Token": TOKENS["ANALYST_TOKEN"]}).status_code == 403
        assert ev.get(path, headers=EVAL).status_code == 200
    assert ev.post("/api/reset").status_code == 403


def test_config_validation(make_clients):
    _, ev, _ = make_clients()
    assert ev.put("/api/config", headers=EVAL, json={"unknown": True}).status_code == 400
    assert ev.put("/api/config", headers=EVAL, json={"spotlight_untrusted": "yes"}).status_code == 400
