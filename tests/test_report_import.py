from datetime import datetime, timezone
import json
import pytest
from ai_module.database import Database
from ai_module.remediation_tracker import RemediationTracker
from ai_module.scan_history import ScanHistory
from prowler_module.report_import import import_report
from prowler_module.event_time import event_time


def event(status="FAIL"):
    return {"time": 1786605086, "time_dt": "2026-08-13T15:11:26.392555",
            "status_code": status, "severity": "High",
            "cloud": {"account": {"uid": "000000000000"}},
            "resources": [{"uid": "demo-bucket", "region": "us-east-1"}],
            "finding_info": {"uid": "demo-finding", "title": "Demo public access",
                             "analytic": {"uid": "s3_bucket_public_access"}}}


@pytest.fixture
def history(tmp_path):
    db = Database(tmp_path / "test.db")
    return ScanHistory(db.db_path)


def test_epoch_seconds_and_milliseconds():
    a = event_time(event())
    assert a == datetime.fromtimestamp(1786605086, timezone.utc)
    assert event_time(dict(event(), time=1786605086000)) == a
    assert event_time({"time_dt": "2026-08-13T15:11:26"}) is None
    assert event_time(dict(event(), time_dt="2020-01-01T00:00:00Z")) is None


def test_import_populates_findings_without_verification(history):
    result = import_report(history, [event(), event("PASS")])
    db = Database(history.db_path)
    findings = db.get_findings()
    assert result["findings_imported"] == 1
    assert len(findings) == 1
    assert findings[0].check_id == "s3_bucket_public_access"
    assert findings[0].raw_evidence["historical_import"]
    assert findings[0].timestamp == event_time(event())
    assert RemediationTracker(history.db_path).list_cases() == []


def test_reimport_preserves_workflow_and_history(history):
    import_report(history, [event()])
    db = Database(history.db_path)
    finding_id = db.get_findings()[0].finding_id
    tracker = RemediationTracker(history.db_path)
    tracker.update(finding_id, state="In Progress", actor="tester", assignee="Alice", note="Keep note")
    tracker.update(finding_id, state="Pending Verification", actor="tester", assignee="Alice")
    import_report(history, [event()])
    import_report(history, [event("PASS")])
    assert len(db.get_findings()) == 1
    assert tracker.get(finding_id)["state"] == "Pending Verification"
    assert tracker.activity(finding_id)[-1]["note"] == "Keep note"


def test_synthetic_does_not_overwrite_real_findings(history):
    import_report(history, [event()])
    import_report(history, [event()], synthetic=True)
    findings = Database(history.db_path).get_findings()
    assert len(findings) == 2
    assert sorted(f.raw_evidence["synthetic_demo"] for f in findings) == [False, True]


def test_failed_finding_parse_rolls_back_scan_and_findings(history, monkeypatch):
    def fail(*args, **kwargs):
        raise ValueError("broken event")
    monkeypatch.setattr("prowler_module.scanner.ProwlerScanner._to_finding", fail)
    with pytest.raises(ValueError):
        import_report(history, [event()])
    assert history.list_runs() == []
    assert Database(history.db_path).get_findings() == []


def test_reimport_repairs_old_derived_timestamp(history):
    first = history.ingest([event()])
    with history.connect() as con:
        con.execute("UPDATE scan_runs SET scanned_at=NULL WHERE id=?", (first["id"],))
    second = import_report(history, [event()])
    assert second["id"] == first["id"]
    assert second["scanned_at"]
    assert len(history.list_runs()) == 1
