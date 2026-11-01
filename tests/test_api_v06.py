"""Contract tests against the *real* v0.5 data, classification and tracker layers."""
import pytest
from fastapi.testclient import TestClient
from datetime import datetime, timezone
from ai_module.database import Database
from ai_module.models import Finding, FindingType, Severity
from backend_api.app import app

@pytest.fixture
def client(tmp_path, monkeypatch):
    path = tmp_path / "test.db"
    monkeypatch.setenv("CLOUDSENTINEL_DB_PATH", str(path))
    monkeypatch.setenv("CLOUDSENTINEL_WRITE_TOKEN", "strong-local-test-token")
    db = Database(path)
    db.upsert_finding(Finding(
        finding_id="finding-test-1", finding_type=FindingType.MISCONFIG,
        source="prowler", severity=Severity.HIGH, title="Public S3 access",
        description="Exposed object access check", resource="arn:aws:s3:::demo",
        account_id="123456789012", region="us-east-1", check_id="s3_bucket_public_access",
        timestamp=datetime.now(timezone.utc), raw_evidence={"sensitive": "DO_NOT_EXPOSE"},
    ))
    return TestClient(app)


def test_health(client):
    assert client.get("/api/v1/health").json()["status"] == "ok"


def test_posture_and_filter(client):
    data = client.get("/api/v1/posture/summary").json()
    assert data["total"] == 1
    assert data["severity"]["High"] == 1
    assert client.get("/api/v1/findings?severity=Critical").json()["total"] == 0
    assert client.get("/api/v1/findings?severity=High").json()["items"][0]["finding_id"] == "finding-test-1"


def test_detail_classification_and_evidence_redaction(client):
    data = client.get("/api/v1/findings/finding-test-1").json()
    assert data["assessment"]["technique_id"] == "T1530"
    assert data["assessment"]["weakness_id"] == "CWE-732"
    assert "DO_NOT_EXPOSE" not in str(data)
    assert data["evidence_notice"]
    assert client.get("/api/v1/findings/does-not-exist").status_code == 404


def test_write_requires_token_and_tracker_persists(client):
    url = "/api/v1/remediations/finding-test-1"
    body = {"state":"In Progress","assignee":"Dev A","actor":"local-engineer","note":"reviewed in local test"}
    assert client.patch(url, json=body).status_code == 403
    assert client.patch(url, json=body,headers={"X-Local-Token":"incorrect"}).status_code == 403
    r = client.patch(url, json=body,headers={"X-Local-Token":"strong-local-test-token"})
    assert r.status_code==200, r.text
    assert r.json()["assignee"]=="Dev A"
    assert client.get("/api/v1/remediations").json()["items"][0]["state"]=="In Progress"
    assert client.get(url+"/activity").json()["items"][0]["actor"]=="local-engineer"
    # Manual Verified is forbidden, even with write token.
    assert client.patch(url,json={**body,"state":"Verified"},headers={"X-Local-Token":"strong-local-test-token"}).status_code==422


def test_bad_inputs(client):
    assert client.get("/api/v1/findings?page_size=9999").status_code==422
    assert client.get("/api/v1/findings?severity=Supercritical").status_code==422
