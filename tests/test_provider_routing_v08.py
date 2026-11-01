"""v0.8 provider selection / private serving. No live requests in these tests."""
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from tests.preview_client import PreviewClient as TestClient

from ai_module import advisor_v07
from ai_module.database import Database
from ai_module.models import Finding, FindingType, Severity
from ai_module.providers.private_provider import (
    PrivateProvider,
    PrivateEndpointConfigurationError,
    validate_private_base_url,
)
from backend_api.app import app

VALID = '''{"explanation":"The config may permit unintended access if the resource is reachable.",
"attack_scenario":"Access may be attempted if network controls permit it.",
"risk_priority":"High", "risk_justification":"Exposure should be investigated.",
"mitigation_steps":["Review and narrow access controls."],
"verification_steps":["Rescan using Prowler."],"cautions":["Review service impact."]}'''


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("CLOUDSENTINEL_DB_PATH", str(tmp_path / "findings.db"))
    monkeypatch.setenv("CLOUDSENTINEL_WRITE_TOKEN", "local-v08-test")
    monkeypatch.setenv("CLOUDSENTINEL_AI_PROVIDER", "groq")
    monkeypatch.setenv("CLOUDSENTINEL_AI_MODEL", "openai/gpt-oss-120b")
    monkeypatch.setenv("CLOUDSENTINEL_AI_API_KEY", "fake-groq")
    monkeypatch.setenv("CLOUDSENTINEL_AI_OPENAI_API_KEY", "fake-openai")
    monkeypatch.setenv("CLOUDSENTINEL_PRIVATE_AI_BASE_URL", "http://127.0.0.1:11434/v1")
    monkeypatch.setenv("CLOUDSENTINEL_PRIVATE_AI_MODEL", "qwen2.5:7b")
    monkeypatch.delenv("CLOUDSENTINEL_DEMO", raising=False)
    db = Database(tmp_path / "findings.db")
    db.upsert_finding(Finding(
        finding_id="f-v08", finding_type=FindingType.MISCONFIG,
        source="prowler", severity=Severity.HIGH, title="S3 public access",
        description="Potentially exposed objects", resource="s3-bucket", account_id="123456789012",
        region="us-east-1", check_id="s3_bucket_public_access", timestamp=datetime.now(timezone.utc)
    ))
    return TestClient(app)


def test_status_lists_only_configured_providers_without_credentials_or_endpoint(client):
    data = client.get("/api/v1/ai/status").json()
    assert data["configured"] is True
    assert data["provider"] == "groq"
    selected = {p["id"]: p for p in data["providers"]}
    assert {"groq", "openai", "private"}.issubset(selected)
    assert "qwen2.5:7b" in selected["private"]["models"]
    text = str(data)
    assert "fake-groq" not in text
    assert "fake-openai" not in text
    assert "11434" not in text


def test_switching_providers_keeps_cache_separate(client, monkeypatch):
    calls = []
    class FakeProvider:
        def complete(self, prompt, max_tokens=1024):
            calls.append("complete")
            return SimpleNamespace(text=VALID, error=None, input_tokens=1, output_tokens=2)
        def complete_structured(self, prompt, schema, max_tokens=4096):
            calls.append("structured")
            return SimpleNamespace(text=VALID, error=None, input_tokens=1, output_tokens=2)
    monkeypatch.setattr(advisor_v07, "get_provider", lambda *args, **kwargs: FakeProvider())
    path = "/api/v1/findings/f-v08/ai/analyze"
    header = {"X-Local-Token": "local-v08-test"}
    groq = {"consent_to_external_processing": True, "provider_id": "groq", "model": "openai/gpt-oss-120b"}
    private = {"consent_to_external_processing": True, "provider_id": "private", "model": "qwen2.5:7b"}
    first = client.post(path, headers=header, json=groq)
    second = client.post(path, headers=header, json=private)
    again = client.post(path, headers=header, json=groq)
    assert first.status_code == second.status_code == again.status_code == 200
    assert (first.json()["cached"], second.json()["cached"], again.json()["cached"]) == (False, False, True)
    assert len(calls) == 2
    assert len(client.get("/api/v1/findings/f-v08/ai/history").json()["items"]) == 2


def test_unlisted_model_and_unconfigured_provider_rejected_before_network(client, monkeypatch):
    monkeypatch.setattr(advisor_v07, "get_provider", lambda *args, **kwargs: pytest.fail("Network not permitted"))
    path = "/api/v1/findings/f-v08/ai/analyze"
    headers = {"X-Local-Token": "local-v08-test"}
    for provider, model in [("private", "unapproved-model"), ("evil", "test-model")]:
        response = client.post(path, json={"consent_to_external_processing": True,
                                           "provider_id": provider, "model": model}, headers=headers)
        assert response.status_code == 409
    assert client.post(path, json={"consent_to_external_processing": True}, headers={}).status_code == 403


def test_private_endpoint_url_validation(monkeypatch):
    monkeypatch.delenv("CLOUDSENTINEL_PRIVATE_ALLOW_HTTP", raising=False)
    assert validate_private_base_url("http://127.0.0.1:11434/v1") == "http://127.0.0.1:11434/v1"
    assert validate_private_base_url("http://localhost:8001/v1/") == "http://localhost:8001/v1"
    assert validate_private_base_url("https://model.internal.example/v1") == "https://model.internal.example/v1"
    for url in ["http://169.254.169.254/v1", "http://8.8.8.8/v1",
                "http://192.168.1.20/v1", "file:///tmp/v1", "https://user:pass@example.com/v1",
                "https://example.com/v1?token=secret", "http://localhost:11434/evil"]:
        with pytest.raises(PrivateEndpointConfigurationError):
            validate_private_base_url(url)
    monkeypatch.setenv("CLOUDSENTINEL_PRIVATE_ALLOW_HTTP", "true")
    assert validate_private_base_url("http://192.168.1.20:8000/v1")


def test_private_provider_uses_operator_url_and_never_displays_provider_error():
    p = PrivateProvider(base_url="http://127.0.0.1:11434/v1", model="qwen2.5:7b", rate_limit_seconds=0)
    recorded = []
    def fake_create(**kw):
        recorded.append(kw)
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=VALID),finish_reason="stop")], usage=None)
    p._client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=fake_create)))
    assert p.complete("redacted prompt", max_tokens=1024).text == VALID
    assert recorded[0]["model"] == "qwen2.5:7b"


def test_demo_mode_disables_all_providers(client, monkeypatch):
    monkeypatch.setenv("CLOUDSENTINEL_DEMO", "1")
    assert client.get("/api/v1/ai/status").json()["providers"] == []
    response = client.post("/api/v1/findings/f-v08/ai/analyze", headers={"X-Local-Token": "local-v08-test"},
        json={"consent_to_external_processing": True, "provider_id": "private", "model": "qwen2.5:7b"})
    assert response.status_code == 409
