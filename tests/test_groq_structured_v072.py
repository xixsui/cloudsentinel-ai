"""v0.7.2: Groq strict schema, budget, truncation, persistence regressions.

All provider clients are fake; these tests do not make external requests.
"""
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from ai_module import advisor_v07
from ai_module.database import Database
from ai_module.models import Finding, FindingType, Severity
from ai_module.providers.groq_provider import GroqProvider


VALID_JSON = '''{
  "explanation": "Public RDP access can increase the attack surface if the host is actually reachable.",
  "attack_scenario": "If the network and host are reachable, attackers may try credentials.",
  "risk_priority": "High",
  "risk_justification": "Security group exposure warrants priority review of effective reachability.",
  "mitigation_steps": ["Verify current connectivity before changing inbound rules."],
  "verification_steps": ["Rescan and verify that unrestricted RDP access is no longer allowed."],
  "cautions": ["Ensure an approved alternate management path exists."]
}'''


def make_provider(model="openai/gpt-oss-120b", *, result=VALID_JSON, finish="stop", fail=False):
    provider = GroqProvider(api_key="fake-test-key", model=model, rate_limit_seconds=0)
    recorded = []

    def create(**kwargs):
        recorded.append(kwargs)
        if fail:
            raise RuntimeError("Provider failed: secret or private data must not leak")
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=result), finish_reason=finish)],
            usage=SimpleNamespace(prompt_tokens=20, completion_tokens=50),
        )

    provider._client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    return provider, recorded


def test_groq_structured_schema_is_strict_and_does_not_leak_prompt():
    provider, calls = make_provider()
    result = provider.complete_structured("sanitized finding text", advisor_v07.ADVISOR_JSON_SCHEMA)
    assert result.text == VALID_JSON
    assert (result.input_tokens, result.output_tokens) == (20, 50)
    assert len(calls) == 1
    payload = calls[0]
    assert payload["model"] == "openai/gpt-oss-120b"
    assert payload["max_completion_tokens"] == 4096
    assert payload["reasoning_effort"] == "low"
    assert payload["response_format"]["type"] == "json_schema"
    schema_info = payload["response_format"]["json_schema"]
    assert schema_info["strict"] is True
    schema = schema_info["schema"]
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(schema["properties"])
    assert payload["messages"] == [{"role": "user", "content": "sanitized finding text"}]


def test_groq_truncation_and_provider_failure_fail_closed():
    truncated, _ = make_provider(finish="length", result="{not completed")
    assert truncated.complete_structured("request", advisor_v07.ADVISOR_JSON_SCHEMA).error == "truncated_output"
    failing, _ = make_provider(fail=True)
    err = failing.complete_structured("request", advisor_v07.ADVISOR_JSON_SCHEMA)
    assert err.error == "provider_request_failed"
    assert "secret" not in err.error


def test_other_groq_models_keep_legacy_path(monkeypatch):
    provider, _ = make_provider(model="other-model")
    intercepted = []
    def fake_complete(prompt, max_tokens=1024):
        intercepted.append(max_tokens)
        return SimpleNamespace(text=VALID_JSON, error=None)
    monkeypatch.setattr(provider, "complete", fake_complete)
    assert provider.complete_structured("request", advisor_v07.ADVISOR_JSON_SCHEMA).text == VALID_JSON
    assert intercepted == [4096]


@pytest.fixture
def advisor_db(monkeypatch, tmp_path):
    db = Database(tmp_path / "local.db")
    finding = Finding(
        finding_id="sample", finding_type=FindingType.MISCONFIG,
        source="prowler", severity=Severity.HIGH,
        title="RDP exposed", description="Inbound RDP unrestricted on an EC2 security group",
        resource="arn:aws:ec2:us-east-1:123456789012:security-group/sg-12345678",
        account_id="123456789012", region="us-east-1", check_id="ec2_instance_port_rdp_exposed_to_internet",
        timestamp=datetime.now(timezone.utc),
    )
    db.upsert_finding(finding)
    monkeypatch.setenv("CLOUDSENTINEL_AI_PROVIDER", "groq")
    monkeypatch.setenv("CLOUDSENTINEL_AI_MODEL", "openai/gpt-oss-120b")
    monkeypatch.setenv("CLOUDSENTINEL_AI_API_KEY", "only-a-test-key")
    monkeypatch.delenv("CLOUDSENTINEL_DEMO", raising=False)
    return db, finding


def test_advisor_calls_strict_path_and_reuses_cache(monkeypatch, advisor_db):
    db, finding = advisor_db
    provider, calls = make_provider()
    monkeypatch.setattr(advisor_v07, "get_provider", lambda *a, **kw: provider)
    first = advisor_v07.generate(db, finding)
    assert first["cached"] is False
    assert first["analysis"]["risk_priority"] == "High"
    assert len(calls) == 1
    assert "123456789012" not in calls[0]["messages"][0]["content"]
    second = advisor_v07.generate(db, finding)
    assert second["cached"] is True
    assert len(calls) == 1
    assert len(advisor_v07.history(db, finding.finding_id)) == 1


def test_bad_content_not_saved_even_if_schema_mode(monkeypatch, advisor_db):
    db, finding = advisor_db
    provider, _ = make_provider(result='{"risk_priority":"High"}')
    monkeypatch.setattr(advisor_v07, "get_provider", lambda *a, **kw: provider)
    with pytest.raises(advisor_v07.AdvisorProviderError, match="invalid analysis format"):
        advisor_v07.generate(db, finding)
    assert advisor_v07.history(db, finding.finding_id) == []


def test_truncated_response_not_saved(monkeypatch, advisor_db):
    db, finding = advisor_db
    provider, _ = make_provider(result="{", finish="length")
    monkeypatch.setattr(advisor_v07, "get_provider", lambda *a, **kw: provider)
    with pytest.raises(advisor_v07.AdvisorProviderError, match="AI response was truncated"):
        advisor_v07.generate(db, finding)
    assert advisor_v07.history(db, finding.finding_id) == []
