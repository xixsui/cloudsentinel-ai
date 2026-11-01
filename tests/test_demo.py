from ai_module.database import Database
from orchestrator.pipeline import Orchestrator, PipelineConfig


def test_demo_flag_disables_all_external_calls(monkeypatch, tmp_path):
    monkeypatch.setenv("CLOUDSENTINEL_DEMO", "1")
    # Running default configuration without credentials must never touch AWS,
    # Wazuh, Prowler or LLM while demo is set.
    result = Orchestrator(db=Database(tmp_path / "db.sqlite")).run(PipelineConfig())
    assert all(step.ok and step.message == "Skipped" for step in result.steps)
    assert result.total_findings == 0
