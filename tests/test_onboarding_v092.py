"""Offline boundary checks: preview isolation, content binding and expiry."""
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import sys

import pytest
from fastapi.testclient import TestClient
from backend_api.app import app
from backend_api import aws_workspace
from cloud_connection.aws import AWSConnection
from tests.test_report_import import event


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("CLOUDSENTINEL_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("CLOUDSENTINEL_WRITE_TOKEN", "preview-test")
    return TestClient(app, headers={"X-Local-Token": "preview-test"})


def test_preview_isolated_and_bound_to_import(client):
    payload = {"events": [event(), event("PASS")]}
    preview = client.post("/api/v1/scans/preview", json=payload)
    assert preview.status_code == 200
    checked = preview.json()
    assert checked["counts"]["CONFLICT"] == 1
    assert checked["repeated_observations"] == 1
    assert not checked["duplicate"]
    assert client.get("/api/v1/scans").json()["items"] == []
    assert client.get("/api/v1/findings").json()["total"] == 0
    changed = {"events": [event()], "preview_id": checked["id"]}
    assert client.post("/api/v1/scans/import", json=changed).status_code == 409
    assert client.get("/api/v1/scans").json()["items"] == []
    assert client.post("/api/v1/scans/import", json={**payload, "preview_id": checked["id"]}).status_code == 200
    assert client.post("/api/v1/scans/preview", json=payload).json()["duplicate"]
    assert not client.post("/api/v1/scans/preview", json={**payload, "synthetic": True}).json()["duplicate"]


def test_preview_errors_have_row_and_do_not_write(client):
    for broken in ["not an object", dict(event(), resources="bad"), dict(event(), cloud="bad")]:
        response = client.post("/api/v1/scans/preview", json={"events": [event(), broken]})
        assert response.status_code == 422
        assert "Event 2" in response.json()["detail"]
    assert client.get("/api/v1/findings").json()["total"] == 0
    assert client.get("/api/v1/scans").json()["items"] == []


def test_preview_pass_only_and_missing_time(client):
    response = client.post("/api/v1/scans/preview", json={"events": [dict(event("PASS"), time=None, time_dt=None)]}).json()
    assert response["findings_imported"] == 0
    assert response["scanned_at"] is None
    assert any("No FAIL" in w for w in response["warnings"])


def test_preview_limits_and_auth(client):
    assert client.post("/api/v1/scans/preview", headers={"X-Local-Token": "wrong"}, json={"events": [event()]}).status_code == 403
    assert client.post("/api/v1/scans/preview", json={"events": [{}] * 20001}).status_code == 422
    assert client.post("/api/v1/scans/preview", content=b" " * (10 * 1024 * 1024 + 4097)).status_code == 413


def test_expiry_blocks_cloud_operations_without_sdk_calls(monkeypatch):
    expired = AWSConnection(mode="temporary", access_key_id="ASIA-test", secret_access_key="test", session_token="test", expires_at=(datetime.now(timezone.utc)-timedelta(minutes=1)).isoformat())
    monkeypatch.setattr(AWSConnection, "session", lambda _: pytest.fail("No SDK request expected"))
    with pytest.raises(ValueError, match="expiration"):
        expired.test_identity()
    monkeypatch.setattr(aws_workspace, "_connection", expired)
    monkeypatch.setattr(aws_workspace, "_identity", {"Account": "000000000000"})
    assert aws_workspace.status()["credentials_expired"]
    assert not aws_workspace.status()["connected"]
    with pytest.raises(ValueError):
        aws_workspace.scan_connection()
    with pytest.raises(ValueError):
        aws_workspace.refresh()


def test_expiry_requires_timezone_and_temporary_mode():
    with pytest.raises(ValueError):
        AWSConnection(expires_at="2027-01-01T00:00:00Z")
    with pytest.raises(ValueError):
        AWSConnection(mode="temporary", expires_at="2027-01-01T00:00:00")


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux diagnostics")
def test_doctor_reports_missing_setup_without_touching_credentials(tmp_path, monkeypatch):
    scripts = Path(__file__).parents[1] / "scripts"
    monkeypatch.syspath_prepend(str(scripts))
    spec = importlib.util.spec_from_file_location("doctor", scripts / "doctor.py")
    doctor = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(doctor)
    monkeypatch.setattr(doctor, "run", lambda _: (False, ""))
    checks = doctor.diagnose(tmp_path, startup=True)
    assert any(c["name"] == "Python environment" and c["state"] == "error" for c in checks)
    assert any(c["name"] == "Frontend dependencies" and c["state"] == "error" for c in checks)
    assert all(c["fix"] for c in checks if c["state"] == "error")
