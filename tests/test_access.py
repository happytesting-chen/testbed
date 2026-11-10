import pytest

from tests.conftest import ANALYST, CONTRIB, EVAL, TOKENS


def test_config_fails_closed_without_tokens(monkeypatch, tmp_path):
    from app.config import ConfigError, load_settings
    for k in TOKENS:
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(ConfigError):
        load_settings()


def test_config_rejects_shared_tokens(monkeypatch):
    from app.config import ConfigError, load_settings
    for k in TOKENS:
        monkeypatch.setenv(k, "same-token-for-all-roles")
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


def test_contributor_is_restricted(make_clients):
    pub, _, _ = make_clients()
    assert pub.get("/api/findings", headers=CONTRIB).status_code == 403
    assert pub.post("/api/agent/chat", json={"message": "hi"}, headers=CONTRIB).status_code == 403
    assert pub.get("/api/reports", headers=CONTRIB).json() == []           # cannot see analyst reports
    assert pub.get("/api/reports/report-q3-vapt", headers=CONTRIB).status_code == 404


def test_uploader_identity_comes_from_token_not_header(make_clients):
    pub, _, db = make_clients()
    r = pub.post("/api/reports/upload", headers={**CONTRIB, "X-Actor": "analyst1"},
                 files={"file": ("x.md", b"synthetic", "text/markdown")})
    assert r.status_code == 200
    assert db.get_report(r.json()["id"])["owner"] == "contributor1"
    assert len(pub.get("/api/reports", headers=CONTRIB).json()) == 1
    assert len(pub.get("/api/reports", headers=ANALYST).json()) == 2


def test_upload_validation(make_clients):
    pub, _, _ = make_clients()
    assert pub.post("/api/reports/upload", headers=CONTRIB, files={"file": ("bad.exe", b"x")}).status_code == 400
    assert pub.post("/api/reports/upload", headers=CONTRIB,
                    files={"file": ("big.txt", b"x" * (1024 * 1024 + 1))}).status_code == 413
    assert pub.post("/api/reports/upload", headers=CONTRIB,
                    files={"file": ("bin.txt", b"\xff\xfe\x00bad")}).status_code == 400


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


def test_reset_restores_seed(make_clients):
    pub, ev, db = make_clients()
    pub.post("/api/reports/upload", headers=CONTRIB, files={"file": ("x.md", b"synthetic", "text/markdown")})
    ev.put("/api/config", headers=EVAL, json={"authority_rule": True})
    assert ev.post("/api/reset", headers=EVAL).status_code == 200
    assert len(pub.get("/api/reports", headers=ANALYST).json()) == 1
    assert [f["status"] for f in pub.get("/api/findings", headers=ANALYST).json()][:3] == ["Open"] * 3
    assert ev.get("/api/config", headers=EVAL).json()["authority_rule"] is False


def test_config_validation(make_clients):
    _, ev, _ = make_clients()
    assert ev.put("/api/config", headers=EVAL, json={"unknown": True}).status_code == 400
    assert ev.put("/api/config", headers=EVAL, json={"authority_rule": "yes"}).status_code == 400
