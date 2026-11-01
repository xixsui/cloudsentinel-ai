from datetime import datetime
from ai_module.database import Database
from ai_module.models import Finding, FindingType, Severity, Status


def test_reingest_preserves_analyst_resolution(tmp_path):
    db = Database(tmp_path / "test.db")
    f = Finding(finding_id="x", finding_type=FindingType.THREAT, source="wazuh",
                severity=Severity.MEDIUM, title="Old alert", description="old",
                timestamp=datetime(2026, 7, 1))
    db.upsert_finding(f)
    db.update_status("x", Status.RESOLVED)
    f.description = "updated by collector"
    f.title = "Updated alert"
    f.severity = Severity.HIGH
    db.upsert_finding(f)
    got = db.get_findings()[0]
    assert got.status == Status.RESOLVED
    assert got.title == "Updated alert"
    assert got.severity == Severity.HIGH
    assert db.stats()["total"] == 1
