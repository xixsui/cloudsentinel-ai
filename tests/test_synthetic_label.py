from ai_module.database import Database
from mock_data.generate import build_mock_findings


def test_synthetic_data_explicitly_labeled(tmp_path):
    db = Database(tmp_path / "findings.db")
    assert db.has_synthetic_findings() is False
    examples = build_mock_findings()
    assert examples and all(f.raw_evidence.get("synthetic_demo") for f in examples)
    db.upsert_finding(examples[0])
    assert db.has_synthetic_findings() is True
