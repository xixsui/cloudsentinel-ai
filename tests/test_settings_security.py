import json
import os
import stat
from types import SimpleNamespace

import pytest
from config import user_settings as settings


@pytest.fixture(autouse=True)
def isolated_settings(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(settings, "CONFIG_FILE", tmp_path / "config.json")
    for env in ("GEMINI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
                "GROQ_API_KEY", "WAZUH_INDEXER_PASSWORD"):
        monkeypatch.delenv(env, raising=False)


def test_legacy_secrets_are_never_resaved():
    legacy = {"api_keys": {"openai": "reversibly-obfuscated-secret"},
              "pipeline": {"wazuh_password": "sample-password", "wazuh_enabled": True}}
    settings.save(legacy)
    text = settings.CONFIG_FILE.read_text()
    assert "secret" not in text and "sample-password" not in text
    assert "api_keys" not in text and "wazuh_password" not in text
    assert settings.load()["pipeline"]["wazuh_enabled"]
    if os.name != "nt":
        assert stat.S_IMODE(settings.CONFIG_FILE.stat().st_mode) == 0o600


def test_env_credentials_override_keyring(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "env-only-secret")
    monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "env-wazuh")
    monkeypatch.setattr(settings, "_keyring", lambda: None)
    assert settings.get_api_key("openai") == "env-only-secret"
    assert settings.get_wazuh_password() == "env-wazuh"


def test_keyring_roundtrip_without_secrets_on_disk(monkeypatch):
    storage = {}
    fake_keyring = SimpleNamespace(
        get_password=lambda svc, user: storage.get((svc, user)),
        set_password=lambda svc, user, value: storage.__setitem__((svc, user), value),
        delete_password=lambda svc, user: storage.pop((svc, user)),
        errors=SimpleNamespace(PasswordDeleteError=KeyError),
    )
    monkeypatch.setattr(settings, "_keyring", lambda: fake_keyring)
    settings.set_api_key("gemini", "stored-key")
    settings.set_wazuh_password("stored-wazuh")
    assert settings.get_api_key("gemini") == "stored-key"
    assert settings.get_wazuh_password() == "stored-wazuh"
    settings.set_api_key("gemini", "")
    assert settings.get_api_key("gemini") == ""
    settings.save({"rate_limit_seconds": 2})
    assert "stored-key" not in settings.CONFIG_FILE.read_text()


def test_no_keyring_backend_fails_closed(monkeypatch):
    monkeypatch.setattr(settings, "_keyring", lambda: None)
    with pytest.raises(RuntimeError):
        settings.set_api_key("gemini", "not-persisted")
    with pytest.raises(ValueError):
        settings.get_api_key("invalid-provider")
