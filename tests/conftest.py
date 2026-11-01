"""Never read an operator's saved AI credentials during automated tests."""
import pytest


@pytest.fixture(autouse=True)
def isolated_ai_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("CLOUDSENTINEL_AI_SETTINGS_DIR", str(tmp_path / "private-settings"))
