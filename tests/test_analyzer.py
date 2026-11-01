import json
from types import SimpleNamespace

from ai_module.analyzer import AIAnalyzer
from ai_module.database import Database
from ai_module.models import Finding, FindingType, Severity
from ai_module.providers.base import CompletionResult
from config import user_settings


class FakeProvider:
    model = "fake-model"
    info = SimpleNamespace(id="gemini")

    def __init__(self):
        self.calls = 0

    def complete(self, prompt):
        self.calls += 1
        return CompletionResult(text=json.dumps({
            "is_incident": True, "title": "Potential unauthorized access",
            "severity": "High", "summary": "Correlated suspicious activity",
        }), input_tokens=15, output_tokens=20)


def test_real_analyzer_uses_candidates_and_reuses_cache(monkeypatch, tmp_path):
    monkeypatch.setattr(user_settings, "record_usage", lambda *args: None)
    db = Database(tmp_path / "findings.db")
    from datetime import datetime
    for fid, src, resource, kind in [
        ("m", "prowler", "arn:aws:s3:::test", FindingType.MISCONFIG),
        ("t", "wazuh", "arn:aws:s3:::test", FindingType.THREAT),
        ("unrelated", "wazuh", "arn:aws:s3:::other", FindingType.THREAT),
    ]:
        db.upsert_finding(Finding(
            finding_id=fid, source=src, finding_type=kind,
            title=fid, description=fid, severity=Severity.HIGH,
            resource=resource, account_id="123", region="ap-southeast-1",
            timestamp=datetime(2026, 7, 1, 10),
        ))
    provider = FakeProvider()
    analyzer = AIAnalyzer(db, provider=provider)
    incidents = analyzer.correlate()
    assert provider.calls == 1
    assert len(incidents) == 1
    assert set(incidents[0].finding_ids) == {"m", "t"}
    assert len(analyzer.correlate()) == 1
    assert provider.calls == 1  # cache avoids duplicate API cost
    assert db.stats()["incidents"] == 1
