import csv
import io
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient
from backend_api.app import app
from backend_api.scan_reports import export_report, summary
from ai_module.database import Database
from ai_module.scan_history import ScanHistory
from ai_module.remediation_tracker import RemediationTracker
from prowler_module.report_import import import_report
from tests.test_scan_history import event


@pytest.fixture
def report(tmp_path):
    db = Database(tmp_path / "report.db")
    history = ScanHistory(db.db_path)
    payload = event(resource="private-resource", cloud={"account":{"uid":"123456789012"}},
                    finding_info={"uid":"private-finding", "title":"<script>alert(1)</script>", "desc":"private-resource 123456789012"})
    scan = import_report(history, [payload])
    return db, history, scan


def test_default_export_omits_identifiers_and_free_text(report):
    db, history, scan = report
    finding = db.get_findings()[0]
    RemediationTracker(db.db_path).update(finding.finding_id, state="In Progress", assignee="private-person", actor="test", note="private-note")
    for format in ("html", "csv"):
        content = export_report(history, scan["id"], format=format)["content"]
        for private in ("123456789012", "private-resource", "private-person", "private-note", "<script>", "private-finding"):
            assert private not in content
        assert "In Progress" in content
        assert "current at export" in content


def test_explicit_fields_escape_html_and_neutralize_csv(report):
    db, history, scan = report
    fid = db.get_findings()[0].finding_id
    RemediationTracker(db.db_path).update(fid, state="In Progress", assignee="", actor="test", note="<img src=x onerror=alert(1)>")
    content = export_report(history, scan["id"], include_identifiers=True, include_notes=True)["content"]
    assert "&lt;script&gt;" in content and "<script>" not in content
    assert "&lt;img" in content and "<img" not in content
    assert "Content-Security-Policy" in content
    from backend_api.scan_reports import csv_cell
    for value in ("=SUM(1,2)", " +cmd", "\t@x", "-2+3", "\n=1"):
        assert csv_cell(value).startswith("'")
    second = import_report(history, [event(resource="=HYPERLINK(1)")])
    csv_text = export_report(history, second["id"], format="csv", include_identifiers=True)["content"]
    rows = list(csv.DictReader(io.StringIO(csv_text.lstrip("\ufeff"))))
    assert rows[0]["resource"].startswith("'")


def test_sensitive_options_require_explicit_identifiers(report):
    _, history, scan = report
    for options in ({"include_notes":True}, {"include_ai":True}):
        with pytest.raises(ValueError, match="sensitive fields"):
            export_report(history, scan["id"], **options)


def test_conflicting_error_status_is_not_lost(report):
    _, history, _ = report
    scan = import_report(history, [event(status="ERROR"), event(status="PASS")])
    info = summary(history, scan["id"])
    assert info["reported_errors"] == 1
    assert info["counts"]["CONFLICT"] == 1


def test_summary_pass_only_and_legacy_unknown(report):
    _, history, _ = report
    scan = import_report(history, [event(status="PASS"), event("skipped", "SKIPPED"), event("error", "ERROR")])
    info = summary(history, scan["id"])
    assert info["counts"]["UNKNOWN"] == 2
    assert info["reported_skipped"] == info["reported_errors"] == 1
    assert info["services"][0]["basis"] == "Inferred from check ID"
    assert "unknown coverage" in info["coverage_notice"]
    content = export_report(history, scan["id"], format="csv")["content"]
    assert len(list(csv.DictReader(io.StringIO(content.lstrip("\ufeff"))))) == 1
    assert "No FAIL findings" in export_report(history, scan["id"])["content"]
    with history.connect() as con:
        values = json.loads(con.execute("SELECT observations FROM scan_runs WHERE id=?", (scan["id"],)).fetchone()[0])
        for value in values:
            value.pop("reported_status")
        con.execute("UPDATE scan_runs SET observations=? WHERE id=?", (json.dumps(values), scan["id"]))
    assert summary(history, scan["id"])["reported_errors"] is None


def test_historical_snapshot_not_current_findings(report):
    db, history, scan = report
    finding = db.get_findings()[0]
    finding.title = "NEWER MUTABLE TITLE"
    db.upsert_finding(finding)
    content = export_report(history, scan["id"], include_identifiers=True)["content"]
    assert "NEWER MUTABLE TITLE" not in content
    with history.connect() as con:
        con.execute("DELETE FROM scan_snapshot_runs WHERE scan_id=?", (scan["id"],))
    with pytest.raises(LookupError, match="snapshot unavailable"):
        export_report(history, scan["id"])


def test_comparison_has_conservative_reasons(report):
    _, history, _ = report
    before = import_report(history, [event("fixed"), event("absent"), event("manual")])
    after = import_report(history, [event("fixed", "PASS", 2), event("manual", "MANUAL", 2)])
    result = history.compare(before["id"], after["id"])
    by_resource = {r["resource"]:r for r in result["items"]}
    assert "absent" in by_resource["absent"]["reason"]
    assert "not remediation" in by_resource["fixed"]["reason"]
    assert "cannot resolve" in by_resource["manual"]["reason"]
    assert all(r["before_time"] for r in result["items"])


def test_api_auth_validation_and_missing_snapshot(report, monkeypatch):
    db, _, scan = report
    monkeypatch.setenv("CLOUDSENTINEL_DB_PATH", str(db.db_path))
    monkeypatch.setenv("CLOUDSENTINEL_WRITE_TOKEN", "report-test")
    client = TestClient(app)
    route = f'/api/v1/scans/{scan["id"]}'
    assert client.get(route+'/summary').status_code == 200
    assert client.post(route+'/export',json={}).status_code == 403
    headers={"X-Local-Token":"report-test"}
    assert client.post(route+'/export',json={"format":"pdf"},headers=headers).status_code == 422
    assert client.post(route+'/export',json={},headers=headers).status_code == 200
    assert client.get('/api/v1/scans/'+'0'*64+'/summary').status_code == 404


def test_ai_export_is_saved_text_only(report):
    db, history, scan = report
    with sqlite3.connect(db.db_path) as con:
        con.execute("CREATE TABLE advisor_runs_v07 (id INTEGER PRIMARY KEY, finding_id TEXT, payload TEXT, created_at TEXT)")
        con.execute("INSERT INTO advisor_runs_v07 VALUES(1,?,?,?)", (db.get_findings()[0].finding_id, '{"advice":"private-ai-text"}', '2026-01-03T00:00:00Z'))
    assert "private-ai-text" not in export_report(history, scan["id"])["content"]
    content = export_report(history, scan["id"], include_identifiers=True, include_ai=True)["content"]
    assert "private-ai-text" in content and "not fresh analysis" in content
