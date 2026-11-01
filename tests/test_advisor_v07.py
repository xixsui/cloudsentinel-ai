"""v0.7 local opt-in AI API, redaction, cache, error-handling contract tests."""
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from tests.preview_client import PreviewClient as TestClient

from ai_module.database import Database
from ai_module.models import Finding, FindingType, Severity
from ai_module import advisor_v07
from backend_api.app import app

OUTPUT = '''{"explanation":"Public access could expose data that was not intended to be accessible.",
"attack_scenario":"If objects are accessible externally, an unauthorized party could retrieve them.",
"risk_priority":"High","risk_justification":"Public exposure is conditional on effective permissions.",
"mitigation_steps":["Inspect bucket policy and intended access.","Remove unintended public read access."],
"verification_steps":["Rerun the matching Prowler check."],"cautions":["Review legitimate application access before changing permissions."]}'''


@pytest.fixture
def local_client(tmp_path, monkeypatch):
    monkeypatch.setenv("CLOUDSENTINEL_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("CLOUDSENTINEL_WRITE_TOKEN", "local-test-secret")
    monkeypatch.delenv("CLOUDSENTINEL_DEMO", raising=False)
    monkeypatch.setenv("CLOUDSENTINEL_AI_PROVIDER", "openai")
    monkeypatch.setenv("CLOUDSENTINEL_AI_API_KEY", "unit-test-not-a-real-key")
    monkeypatch.setenv("CLOUDSENTINEL_AI_MODEL", "mock-model")
    db = Database(tmp_path / "test.db")
    db.upsert_finding(Finding(
        finding_id="test-s3", finding_type=FindingType.MISCONFIG, source="prowler",
        severity=Severity.HIGH, title="Public bucket in account 123456789012",
        description="arn:aws:s3:::private-bucket should not expose objects; suspicious AWS key AKIAABCDEFGHIJKLMNOP",
        resource="arn:aws:s3:::private-bucket", account_id="123456789012",region="us-east-1",
        check_id="s3_bucket_public_access", timestamp=datetime.now(timezone.utc),
        raw_evidence={"secret": "NOT_ALLOWED_IN_AI_PROMPT"}
    ))
    return TestClient(app)


def test_disabled_provider_displays_local_fallback(local_client, monkeypatch):
    monkeypatch.delenv("CLOUDSENTINEL_AI_API_KEY")
    response = local_client.get("/api/v1/ai/status")
    assert response.status_code == 200 and not response.json()["configured"]
    post = local_client.post("/api/v1/findings/test-s3/ai/analyze", json={"consent_to_external_processing": True},
                             headers={"X-Local-Token": "local-test-secret"})
    assert post.status_code == 409


def test_consent_and_write_token_enforced(local_client):
    url = "/api/v1/findings/test-s3/ai/analyze"
    assert local_client.post(url, json={"consent_to_external_processing": True}).status_code == 403
    assert local_client.post(url, json={"consent_to_external_processing": False},
                              headers={"X-Local-Token": "local-test-secret"}).status_code == 422
    assert local_client.post(url, json={},headers={"X-Local-Token": "local-test-secret"}).status_code == 422
    assert local_client.get("/api/v1/findings/missing/ai/history").status_code == 404


def test_generate_cache_history_and_evidence_redaction(local_client, monkeypatch):
    captured = []
    class FakeProvider:
        def complete(self, prompt, max_tokens=1024):
            captured.append(prompt)
            return SimpleNamespace(text=OUTPUT, error=None, input_tokens=10, output_tokens=20)
    monkeypatch.setattr(advisor_v07, "get_provider", lambda *a, **kw: FakeProvider())
    url = "/api/v1/findings/test-s3/ai/analyze"
    args = {"consent_to_external_processing": True}
    headers = {"X-Local-Token": "local-test-secret"}
    first = local_client.post(url, json=args, headers=headers)
    assert first.status_code == 200, first.text
    assert first.json()["cached"] is False
    assert first.json()["analysis"]["mitigation_steps"]
    assert "123456789012" not in captured[0]
    assert "private-bucket" not in captured[0]
    assert "AKIAABCDEFGHIJKLMNOP" not in captured[0]
    assert "NOT_ALLOWED_IN_AI_PROMPT" not in captured[0]
    assert "unit-test-not-a-real-key" not in captured[0]
    cached = local_client.post(url, json=args, headers=headers)
    assert cached.status_code == 200 and cached.json()["cached"] is True
    assert len(captured) == 1
    forced = local_client.post(url, json={**args, "force_refresh":True}, headers=headers)
    assert forced.status_code == 200 and forced.json()["cached"] is False
    assert len(captured) == 2
    runs = local_client.get("/api/v1/findings/test-s3/ai/history").json()["items"]
    assert len(runs) == 2
    assert runs[0]["analysis"]["explanation"]
    detail = local_client.get("/api/v1/findings/test-s3").json()
    assert detail["ai_analysis"]["mitigation_steps"]


def test_provider_errors_not_persisted(local_client, monkeypatch):
    class BrokenProvider:
        def complete(self, prompt, max_tokens=1024):
            return SimpleNamespace(text="", error="sensitive provider debug info", input_tokens=0, output_tokens=0)
    monkeypatch.setattr(advisor_v07, "get_provider", lambda *a, **kw: BrokenProvider())
    response = local_client.post("/api/v1/findings/test-s3/ai/analyze",
        json={"consent_to_external_processing":True},headers={"X-Local-Token":"local-test-secret"})
    assert response.status_code == 502
    assert "sensitive provider debug info" not in response.text
    assert local_client.get("/api/v1/findings/test-s3/ai/history").json()["items"] == []


def test_demo_mode_never_calls_provider(local_client, monkeypatch):
    monkeypatch.setenv("CLOUDSENTINEL_DEMO", "1")
    monkeypatch.setattr(advisor_v07, "get_provider", lambda *a, **kw: pytest.fail("Network attempted in demo mode"))
    assert not local_client.get("/api/v1/ai/status").json()["configured"]
    response = local_client.post("/api/v1/findings/test-s3/ai/analyze",
        json={"consent_to_external_processing":True},headers={"X-Local-Token":"local-test-secret"})
    assert response.status_code == 409
