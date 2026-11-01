"""Offline investigation regressions; no AWS, Streamlit or LLM required."""

from datetime import datetime

import pytest

from ai_module.database import Database
from ai_module.investigation import (
    score_finding, score_incident, techniques_for_finding, techniques_for_incident,
)
from ai_module.models import Finding, FindingType, Incident, Severity, Status
from mock_data.generate import build_mock_findings, seed


def test_attack_mapping_requires_evidence_and_supported_detector():
    samples = {f.check_id: f for f in build_mock_findings()}
    assert [m.technique_id for m in techniques_for_finding(samples["5712"])] == ["T1110"]
    assert [m.technique_id for m in techniques_for_finding(samples["2010937"])] == ["T1046"]
    assert [m.technique_id for m in techniques_for_finding(samples["80200"])] == ["T1530"]
    assert techniques_for_finding(samples["s3_bucket_public_access"]) == ()
    assert techniques_for_finding(samples["80201"]) == ()  # Unsupported ambiguous denied API calls
    impostor = samples["5712"].model_copy(deep=True)
    impostor.raw_evidence.pop("failed_attempts")
    assert techniques_for_finding(impostor) == ()
    impostor.raw_evidence["failed_attempts"] = "not-a-number"
    assert techniques_for_finding(impostor) == ()
    assert techniques_for_incident([samples["5712"], samples["5712"]])[0].technique_id == "T1110"
    assert techniques_for_finding(samples["2010937"])[0].url == "https://attack.mitre.org/techniques/T1046/"


def test_risk_is_explainable_bounded_and_not_probabilistic():
    all_findings = build_mock_findings()
    f = next(f for f in all_findings if f.check_id == "5712")
    scored = score_finding(f)
    assert scored.score == sum(factor.points for factor in scored.factors)
    assert scored.score == 74
    case = Incident(incident_id="i", title="candidate", severity=Severity.HIGH)
    assert score_incident(case, []).score == 0  # missing evidence never inherits unverified headline
    composite = score_incident(case, all_findings)
    assert composite.score == 100
    assert composite.score == min(100, sum(f.points for f in composite.factors))
    assert score_incident(case, [f, f]).score == score_incident(case, [f]).score


def test_seed_synthetic_incidents_idempotent_and_flagged(tmp_path):
    db = Database(tmp_path / "d.sqlite")
    assert seed(db) == 9
    cases = db.get_incidents()
    assert len(cases) == 2
    assert all(case.ai_narrative == "" for case in cases)  # no fabricated LLM analysis
    finding_ids = {f.finding_id: f for f in db.get_findings()}
    assert all(all(finding_ids[fid].raw_evidence.get("synthetic_demo") is True
                   for fid in case.finding_ids) for case in cases)
    seed(db)
    assert len(db.get_incidents()) == 2


def test_audit_atomic_and_preserves_manual_status_on_repeat_scan(tmp_path):
    db = Database(tmp_path / "case.sqlite")
    seed(db)
    case = db.get_incidents()[0]
    with pytest.raises(ValueError, match="requires a justification"):
        db.update_incident_workflow(case.incident_id, status=Status.RESOLVED,
                                    assignee="Sam", actor="Sam")
    assert db.get_incident_activity(case.incident_id) == []
    assert db.get_incident(case.incident_id).status == Status.NEW
    db.update_incident_workflow(case.incident_id, status=Status.INVESTIGATING,
                                assignee="Sam", actor="Sam", note="Examining telemetry")
    assert db.get_incident(case.incident_id).assignee == "Sam"
    assert db.get_incident(case.incident_id).status == Status.INVESTIGATING
    records = db.get_incident_activity(case.incident_id)
    assert len(records) == 2
    assert {r["action"] for r in records} == {"assigned", "status_changed"}
    db.update_incident_workflow(case.incident_id, status=Status.RESOLVED,
                                assignee="Sam", actor="Sam", note="Benign test confirmed")
    assert db.get_incident(case.incident_id).resolution_note == "Benign test confirmed"
    seed(db)
    preserved = db.get_incident(case.incident_id)
    assert preserved.status == Status.RESOLVED
    assert preserved.assignee == "Sam"
    assert preserved.resolution_note == "Benign test confirmed"
    assert len(db.get_incident_activity(case.incident_id)) == 3
    with pytest.raises(ValueError, match="Reopen"):
        db.update_incident_workflow(case.incident_id, status=Status.NEW,
                                    assignee="Sam", actor="Sam", note="Unsafe reset")
    db.update_incident_workflow(case.incident_id, status=Status.INVESTIGATING,
                                assignee="Sam", actor="Sam", note="Reopening for review")
    assert db.get_incident(case.incident_id).resolution_note == ""
    assert len(db.get_incident_activity(case.incident_id)) == 4


def test_notes_validation_and_nonexistent_id(tmp_path):
    db = Database(tmp_path / "case.sqlite")
    with pytest.raises(ValueError, match="not found"):
        db.update_incident_workflow("missing", status=Status.NEW, assignee="",
                                    actor="Test", note="hi")
    db.save_incident(Incident(incident_id="a", title="one", timestamp=datetime(2026, 1, 1)))
    with pytest.raises(ValueError, match="analyst label"):
        db.update_incident_workflow("a", status=Status.NEW, assignee="",
                                    actor="", note="test")
    with pytest.raises(ValueError, match="No change"):
        db.update_incident_workflow("a", status=Status.NEW, assignee="", actor="X")
    db.update_incident_workflow("a", status=Status.NEW, assignee="",
                                actor="Analyst", note="Checked original source")
    assert db.get_incident_activity("a")[0]["action"] == "analyst_note"
    assert len(db.get_incident_activity("a")) == 1


def test_existing_schema_migrates_without_data_loss(tmp_path):
    import sqlite3
    p = tmp_path / "legacy.sqlite"
    conn = sqlite3.connect(p)
    conn.execute("CREATE TABLE incidents (incident_id TEXT PRIMARY KEY,title TEXT,severity TEXT,"
                 "summary TEXT,finding_ids TEXT,linked_entity TEXT,ai_narrative TEXT,"
                 "timestamp TEXT,status TEXT)")
    conn.execute("INSERT INTO incidents VALUES (?,?,?,?,?,?,?,?,?)",
                 ("case-1", "Old", "High", "Legacy case", "[]", "", "",
                  "2026-07-01T00:00:00", "Analyzed"))
    conn.commit()
    conn.close()
    db = Database(p)
    assert db.get_incident("case-1").status == Status.ANALYZED
    db.update_incident_workflow("case-1", status=Status.INVESTIGATING,
                                assignee="T", actor="T", note="Imported old case")
    assert db.get_incident("case-1").status == Status.INVESTIGATING


def test_ui_contains_local_timeline_workflow_and_case_export():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    p = (root / "dashboard/pages/3_Correlated_Incidents.py").read_text()
    assert "@st.fragment" in p
    for required in ("Evidence timeline", "ATT&CK & risk", "Activity log",
                     "st.download_button", "update_incident_workflow", "st.dataframe"):
        assert required in p
