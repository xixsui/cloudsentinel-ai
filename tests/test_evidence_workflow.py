import copy
import sqlite3
from datetime import datetime, timezone
from types import SimpleNamespace
import pytest
from fastapi.testclient import TestClient
from ai_module.database import Database
from ai_module.scan_history import ScanHistory
from ai_module.remediation_tracker import RemediationTracker
from ai_module.scan_snapshots import read
from ai_module import advisor_v07
from backend_api.app import app
from backend_api.recheck import prepare, finish
from prowler_module.report_import import import_report
from tests.test_report_import import event
from tests.test_advisor_v07 import OUTPUT


def sample(status="FAIL", offset=0):
    item = event(status)
    item.pop("time_dt")
    item["time"] += offset
    item["metadata"] = {"product": {"version": "5.46.0"}}
    return item


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    path = tmp_path / "db.sqlite"
    db = Database(path)
    history = ScanHistory(path)
    monkeypatch.setenv("CLOUDSENTINEL_DB_PATH", str(path))
    monkeypatch.setenv("CLOUDSENTINEL_WRITE_TOKEN", "test")
    return db, history, TestClient(app)


def test_snapshot_remains_unchanged_after_new_evidence(workspace):
    db, history, client = workspace
    original = sample()
    first = import_report(history, [original])
    fid = db.get_findings()[0].finding_id
    new = sample(offset=50)
    new["finding_info"]["title"] = "Changed title"
    import_report(history, [new])
    assert db.get_finding(fid).title == "Changed title"
    old = client.get(f"/api/v1/findings/{fid}", params={"scan_id": first["id"]}).json()
    assert old["finding"]["title"] == original["finding_info"]["title"]
    assert old["ai_analysis"] is None
    rows = client.get("/api/v1/findings", params={"scan_id": first["id"]}).json()["items"]
    assert rows[0]["title"] == old["finding"]["title"]
    # Reimporting an identical report never alters the captured snapshot.
    payload = read(db.db_path, first["id"])[0].model_dump_json()
    import_report(history, [original])
    assert read(db.db_path, first["id"])[0].model_dump_json() == payload
    assert db.get_finding(fid).title == "Changed title"


def test_legacy_scan_never_falls_back_to_current(workspace):
    db, history, client = workspace
    run = history.ingest([sample()])
    response = client.get("/api/v1/findings", params={"scan_id": run["id"]})
    assert response.status_code == 404
    assert "Reimport" in response.json()["detail"]


@pytest.mark.parametrize("mode,expected", [("pass","Verified"),("fail","Still failing"),("missing","Unable to confirm"),("conflict","Unable to confirm"),("version","Unable to confirm"),("stale","Unable to confirm"),("manual","Unable to confirm")])
def test_recheck_requires_new_exact_unambiguous_pass(workspace, mode, expected):
    db, history, _ = workspace
    import_report(history, [sample()])
    finding = db.get_findings()[0]
    tracker = RemediationTracker(db.db_path)
    tracker.update(finding.finding_id, state="In Progress", actor="test", assignee="")
    tracker.update(finding.finding_id, state="Pending Verification", actor="test", assignee="")
    pending = datetime.fromtimestamp(sample()["time"]+1, timezone.utc).isoformat()
    with sqlite3.connect(db.db_path) as con:
        con.execute("UPDATE remediation_cases SET pending_at=?", (pending,))
    _, target = prepare(db.db_path, finding)
    newer = sample("FAIL" if mode=="fail" else "MANUAL" if mode=="manual" else "PASS", 0 if mode=="stale" else 10)
    if mode=="missing": newer["resources"][0]["uid"] = "another-resource"
    if mode=="version": newer["metadata"]["product"]["version"] = "different"
    events = [newer]
    if mode=="conflict": events.append(dict(copy.deepcopy(newer), status_code="FAIL"))
    run = import_report(history, events, source="Prowler web scan")
    assert finish(db.db_path, target, run["id"], pending) == expected
    assert (tracker.get(finding.finding_id)["state"]=="Verified") == (expected=="Verified")


def test_preview_exact_payload_and_stale_preview_blocked(workspace, monkeypatch):
    db, history, client = workspace
    import_report(history, [sample()])
    finding = db.get_findings()[0]
    monkeypatch.setenv("CLOUDSENTINEL_AI_PROVIDER", "openai")
    monkeypatch.setenv("CLOUDSENTINEL_AI_API_KEY", "unit-secret")
    monkeypatch.setenv("CLOUDSENTINEL_AI_MODEL", "mock-model")
    sent=[]
    class Provider:
        def complete(self, prompt, **kwargs):
            sent.append(prompt)
            return SimpleNamespace(text=OUTPUT, error=None, input_tokens=1, output_tokens=1)
    monkeypatch.setattr(advisor_v07,"get_provider",lambda *args,**kwargs:Provider())
    base=f"/api/v1/findings/{finding.finding_id}/ai/"
    preview=client.get(base+"preview",params={"privacy":"minimal"}).json()
    assert not sent
    assert "demo-bucket" not in preview["prompt"]
    assert "description_excerpt" not in preview["prompt"]
    body={"consent_to_external_processing":True,"privacy":"minimal","preview_hash":preview["hash"]}
    headers={"X-Local-Token":"test"}
    result=client.post(base+"analyze",json=body,headers=headers)
    assert result.status_code==200,result.text
    assert sent==[preview["prompt"]]
    changed=client.post(base+"analyze",json={**body,"privacy":"standard"},headers=headers)
    assert changed.status_code==409
    assert len(sent)==1
    assert client.post(base+"analyze",json={"consent_to_external_processing":True},headers=headers).status_code==422
