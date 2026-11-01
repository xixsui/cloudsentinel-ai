"""v0.9 heuristic review and feedback. Network-free; no external model credentials."""
from datetime import datetime, timezone
from types import SimpleNamespace

from tests.preview_client import PreviewClient as TestClient
import pytest

from ai_module import advisor_v07
from ai_module.database import Database
from ai_module.models import Finding, FindingType, Severity
from ai_module.recommendation_review import review_recommendation
from backend_api.app import app


def make_finding(check_id="ec2_instance_port_rdp_exposed_to_internet", finding_id="review-1"):
    return Finding(finding_id=finding_id, finding_type=FindingType.MISCONFIG, source="prowler",
                   severity=Severity.HIGH, title="RDP access is too broad",
                   description="A historical check failed", resource="sg-example",
                   account_id="123456789012", region="us-east-1", check_id=check_id,
                   timestamp=datetime.now(timezone.utc))


def output(steps=None, verify=None):
    return {"explanation":"The static check indicates potentially broad inbound access.",
            "attack_scenario":"A party could attempt access if the host is reachable.",
            "risk_priority":"High", "risk_justification":"Review reachability and intent.",
            "mitigation_steps": steps or ["Review the rule."],
            "verification_steps": verify or ["Rerun Prowler."], "cautions": []}


def test_warns_on_add_only_security_group_fix():
    review = review_recommendation(make_finding(), output(
        ["aws ec2 authorize-security-group-ingress --group-id sg-example --protocol tcp --port 3389 --cidr 10.0.0.0/8"]))
    assert review["assessment"] == "manual_review_required"
    assert "SG_ADD_ONLY" in {a["code"] for a in review["alerts"]}
    assert any("reachab" in s for s in review["unverified_conditions"])
    assert "no attack is confirmed" in review["activity_evidence"]


def test_rule_change_does_not_trigger_add_only_false_alarm():
    result = review_recommendation(make_finding(), output([
        "aws ec2 authorize-security-group-ingress --group-id sg-example --protocol tcp --port 3389 --cidr 10.0.0.0/8",
        "Revoke the old rule with aws ec2 revoke-security-group-ingress after approval."]))
    assert "SG_ADD_ONLY" not in {a["code"] for a in result["alerts"]}


def test_cloudtrail_does_not_prove_rdp_or_ssh_logins():
    review = review_recommendation(make_finding(), output(verify=[
        "Look at CloudTrail for failed RDP login attempts."]))
    assert "CLOUDTRAIL_AUTH_LOG" in {a["code"] for a in review["alerts"]}
    review = review_recommendation(make_finding(), output(verify=[
        "Use CloudTrail to verify security group rule change API calls."]))
    assert "CLOUDTRAIL_AUTH_LOG" not in {a["code"] for a in review["alerts"]}


def test_destructive_command_is_flagged():
    review = review_recommendation(make_finding("s3_bucket_public_access"), output(
        ["aws s3 rb s3://some-bucket --force"]))
    assert "DESTRUCTIVE_OPERATION" in {a["code"] for a in review["alerts"]}


def test_unsubstantiated_compromise_claim_is_flagged():
    review = review_recommendation(make_finding(), {
        **output(), "attack_scenario": "A confirmed breach has occurred."})
    assert "UNSUPPORTED_COMPROMISE" in {a["code"] for a in review["alerts"]}
    benign = review_recommendation(make_finding(), output())
    assert "UNSUPPORTED_COMPROMISE" not in {a["code"] for a in benign["alerts"]}
    assert benign["disclaimer"].startswith("Pattern checks are incomplete")


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("CLOUDSENTINEL_DB_PATH", str(tmp_path / "scan.db"))
    monkeypatch.setenv("CLOUDSENTINEL_WRITE_TOKEN", "review-test-token")
    monkeypatch.setenv("CLOUDSENTINEL_AI_PROVIDER", "openai")
    monkeypatch.setenv("CLOUDSENTINEL_AI_API_KEY", "fake-only")
    monkeypatch.setenv("CLOUDSENTINEL_AI_MODEL", "mock")
    monkeypatch.delenv("CLOUDSENTINEL_DEMO", raising=False)
    Database(tmp_path / "scan.db").upsert_finding(make_finding())
    return TestClient(app)


def _make_run(client, monkeypatch):
    class Dummy:
        def complete(self, prompt, max_tokens):
            import json
            return SimpleNamespace(text=json.dumps(output(["aws ec2 authorize-security-group-ingress --group-id sg-example"])),
                                   error=None, input_tokens=10, output_tokens=25)
    monkeypatch.setattr(advisor_v07, "get_provider", lambda *a, **k: Dummy())
    return client.post("/api/v1/findings/review-1/ai/analyze", headers={"X-Local-Token":"review-test-token"},
                       json={"consent_to_external_processing":True})


def test_review_is_returned_on_generation_cache_and_history(client, monkeypatch):
    run = _make_run(client, monkeypatch)
    assert run.status_code == 200, run.text
    assert run.json()["analysis"]["review"]["alerts"][0]["code"] == "SG_ADD_ONLY"
    cache = client.post("/api/v1/findings/review-1/ai/analyze", headers={"X-Local-Token":"review-test-token"},
                        json={"consent_to_external_processing":True})
    assert cache.status_code == 200 and cache.json()["cached"]
    assert cache.json()["analysis"]["review"]["alerts"]
    hist = client.get("/api/v1/findings/review-1/ai/history").json()["items"]
    assert hist[0]["analysis"]["review"]["version"]
    # Review metadata is computed on read, not added to original AI payload table.
    db = Database(__import__("pathlib").Path(__import__("os").environ["CLOUDSENTINEL_DB_PATH"]))
    with advisor_v07._connect(db.db_path) as conn:
        stored = conn.execute("SELECT payload FROM advisor_runs_v07 LIMIT 1").fetchone()[0]
    assert '"review"' not in stored


def test_feedback_requires_write_token_and_belongs_to_run(client, monkeypatch):
    run = _make_run(client, monkeypatch)
    run_id = run.json()["id"]
    endpoint = f"/api/v1/findings/review-1/ai/runs/{run_id}/feedback"
    assert client.put(endpoint, json={"rating":"helpful"}).status_code == 403
    headers={"X-Local-Token":"review-test-token"}
    assert client.put(endpoint, headers=headers, json={"rating":"invalid"}).status_code == 422
    assert client.put(endpoint, headers=headers, json={"rating":"helpful", "note":"x"*501}).status_code == 422
    saved = client.put(endpoint, headers=headers, json={"rating":"needs_correction",
                                                     "note":"Rule addition alone is insufficient"})
    assert saved.status_code == 200, saved.text
    hist = client.get("/api/v1/findings/review-1/ai/history").json()["items"]
    assert hist[0]["feedback"]["rating"] == "needs_correction"
    assert hist[0]["feedback"]["note"] == "Rule addition alone is insufficient"
    updated = client.put(endpoint, headers=headers, json={"rating":"helpful", "note":"Reviewed"})
    assert updated.status_code == 200
    assert client.get("/api/v1/findings/review-1/ai/history").json()["items"][0]["feedback"]["rating"] == "helpful"
    assert client.put("/api/v1/findings/review-1/ai/runs/999999/feedback", headers=headers,
                      json={"rating":"helpful"}).status_code == 404


def test_feedback_not_available_for_unknown_finding(client):
    res = client.put("/api/v1/findings/unknown/ai/runs/1/feedback",
                     headers={"X-Local-Token":"review-test-token"}, json={"rating":"helpful"})
    assert res.status_code == 404


def test_legacy_run_table_migrates_with_original_analysis_preserved(client):
    import json
    import sqlite3
    from pathlib import Path
    import os
    path = Path(os.environ["CLOUDSENTINEL_DB_PATH"])
    with sqlite3.connect(path) as conn:
        conn.execute("""CREATE TABLE advisor_runs_v07 (
            id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id TEXT NOT NULL,
            fingerprint TEXT NOT NULL, provider TEXT NOT NULL,
            model TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL
        )""")
        conn.execute("INSERT INTO advisor_runs_v07(finding_id,fingerprint,provider,model,payload,created_at) VALUES (?,?,?,?,?,?)",
                     ("review-1", "old-fingerprint", "groq", "old-model",
                      json.dumps(output(["aws ec2 authorize-security-group-ingress --group-id sg-example"])),
                      "2026-01-01T00:00:00"))
        conn.commit()
    response = client.get("/api/v1/findings/review-1/ai/history")
    assert response.status_code == 200, response.text
    record = response.json()["items"][0]
    assert record["prompt_version"] == "unknown-legacy"
    assert record["analysis"]["review"]["alerts"][0]["code"] == "SG_ADD_ONLY"
    assert record["analysis"]["risk_priority"] == "High"
