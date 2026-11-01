import pytest
import json
from pathlib import Path
from fastapi.testclient import TestClient

from ai_module.database import Database
from ai_module.scan_history import ScanHistory
from backend_api.app import app


def event(resource="demo-a", status="FAIL", day=1, **changes):
    result = {"time_dt": f"2026-01-{day:02d}T00:00:00Z", "status_code": status,
              "cloud": {"account": {"uid": "000000000000"}},
              "resources": [{"uid": resource, "region": "us-east-1"}],
              "unmapped": {"check_id": "s3_bucket_public_access"},
              "metadata": {"product": {"version": "test-1"}}}
    result.update(changes)
    return result


@pytest.fixture
def history(tmp_path):
    path = tmp_path / "history.db"
    Database(path)
    return ScanHistory(path)


def test_four_outcomes_and_manual(history):
    old = history.ingest([event(r) for r in ("fixed", "still", "gone", "manual")])
    new = history.ingest([event("fixed", "PASS", 2), event("still", day=2),
                          event("new", day=2), event("manual", "MANUAL", 2)])
    result = history.compare(old["id"], new["id"])
    assert result["counts"] == {"New": 1, "Persisting": 1, "Resolved": 1, "Not Rechecked": 2}
    assert all(i["account"] == "…0000" for i in result["items"])


def test_duplicate_order_independent_and_preserves_legacy(history):
    events = [event(), event("demo-b")]
    first = history.ingest(events)
    assert history.ingest(list(reversed(events)))["id"] == first["id"]
    assert len(history.list_runs()) == 1
    with history.connect() as con:
        assert con.execute("SELECT count(*) FROM findings").fetchone()[0] == 0
    assert ScanHistory(history.db_path).get(first["id"])["counts"]["FAIL"] == 2


def test_shipped_fixtures(history):
    folder = Path(__file__).parents[1] / "mock_data" / "scan_history"
    before = history.ingest(json.loads((folder / "before.json").read_text()), synthetic=True)
    after = history.ingest(json.loads((folder / "after.json").read_text()), synthetic=True)
    assert history.compare(before["id"], after["id"])["counts"] == {
        "New": 1, "Persisting": 1, "Resolved": 1, "Not Rechecked": 1}


@pytest.mark.parametrize("new_events", [
    [event(status="MANUAL", day=2)],
    [event(status="PASS", day=2), event(day=2)],
    [event(status="PASS", day=2, resources=[])],
    [event(status="PASS", day=2, cloud={"account": {"uid": "111111111111"}})],
    [event(status="PASS", day=2, metadata={"product": {"version": "test-2"}})],
    [event(status="PASS", day=2, resources=[{"uid": "demo-a", "region": "eu-west-1"}])],
])
def test_unsafe_resolution_is_not_resolved(history, new_events):
    old = history.ingest([event()])
    new = history.ingest(new_events)
    assert history.compare(old["id"], new["id"])["counts"]["Resolved"] == 0


@pytest.mark.parametrize("time", [None, "bad", "2999-01-01T00:00:00Z", "2026-01-02T00:00:00"])
def test_invalid_timestamp_cannot_compare(history, time):
    old = history.ingest([event()])
    new = history.ingest([event(status="PASS", time_dt=time)])
    with pytest.raises(ValueError):
        history.compare(old["id"], new["id"])


def test_out_of_order_and_synthetic_mismatch(history):
    a, b = history.ingest([event()]), history.ingest([event(day=2)])
    c = history.ingest([event(day=3)], synthetic=True)
    for before, after in ((b, a), (a, a), (a, c)):
        with pytest.raises(ValueError):
            history.compare(before["id"], after["id"])


def test_conflicts_are_order_independent(history):
    a = event(status="PASS", day=2)
    b = event(day=2)
    first = history.ingest([a, b])
    assert first["counts"]["CONFLICT"] == 1
    assert history.ingest([b, a])["id"] == first["id"]


def test_stale_observation_inside_new_report(history):
    old = history.ingest([event()])
    new = history.ingest([event(status="PASS"), event("other", day=3)])
    assert history.compare(old["id"], new["id"])["counts"]["Resolved"] == 0


def test_same_upstream_scan_cannot_resolve(history):
    meta = {"check_id": "demo-check", "scan_id": "same-source-scan"}
    old = history.ingest([event(unmapped=meta)])
    new = history.ingest([event(status="PASS", day=2, unmapped=meta)])
    assert history.compare(old["id"], new["id"])["counts"]["Resolved"] == 0


@pytest.mark.parametrize("bad", [[], [None], [event(resources="bad")], [event(cloud="bad")]])
def test_bad_input_is_atomic(history, bad):
    with pytest.raises(ValueError):
        history.ingest(bad)
    assert history.list_runs() == []


def test_api_auth_import_compare_and_existing_state(tmp_path, monkeypatch):
    monkeypatch.setenv("CLOUDSENTINEL_DB_PATH", str(tmp_path / "api.db"))
    monkeypatch.setenv("CLOUDSENTINEL_WRITE_TOKEN", "test-token")
    client = TestClient(app)
    body = {"events": [event()]}
    assert client.post("/api/v1/scans/import", json=body).status_code == 403
    headers = {"X-Local-Token": "test-token"}
    before = client.post("/api/v1/scans/import", json=body, headers=headers)
    assert before.status_code == 200
    assert "observations" not in before.json()
    body["events"] = [event(status="PASS", day=2)]
    after = client.post("/api/v1/scans/import", json=body, headers=headers)
    result = client.get("/api/v1/scans/compare", params={"before": before.json()["id"], "after": after.json()["id"]})
    assert result.json()["counts"]["Resolved"] == 1
    assert client.get("/api/v1/remediations").json()["items"] == []
    assert len(client.get("/api/v1/scans").json()["items"]) == 2
    assert client.get("/api/v1/scans/compare?before=bad&after=bad").status_code == 422
    assert client.get("/api/v1/scans/compare", params={"before": "a" * 64, "after": "b" * 64}).status_code == 404
