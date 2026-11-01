import os
import stat
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from ai_module import advisor_v07
from backend_api.app import app
from config import ai_preferences

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Encrypted Settings saves require Linux/WSL")
TOKEN = {"X-Local-Token": "local-settings-test"}
KEY = "dummy-secret-not-a-real-provider-key-123"


@pytest.fixture
def client(monkeypatch):
    for name in list(os.environ):
        if (name.startswith("CLOUDSENTINEL_AI_") and name != "CLOUDSENTINEL_AI_SETTINGS_DIR") or name.startswith("CLOUDSENTINEL_PRIVATE_"):
            monkeypatch.delenv(name)
    monkeypatch.delenv("CLOUDSENTINEL_DEMO", raising=False)
    monkeypatch.setenv("CLOUDSENTINEL_WRITE_TOKEN", TOKEN["X-Local-Token"])
    monkeypatch.setattr(advisor_v07, "get_provider", lambda *a, **k: pytest.fail("Settings must not call a provider"))
    return TestClient(app)


def save(client, provider="groq", key=KEY):
    return client.put("/api/v1/settings/ai/credential", headers=TOKEN,
                      json={"provider": provider, "action": "save", "api_key": key})


def test_encrypted_key_never_returned_or_saved_in_cleartext(client):
    response = save(client)
    assert response.status_code == 200, response.text
    assert KEY not in response.text
    assert KEY not in client.get("/api/v1/settings/ai").text
    assert KEY not in client.get("/api/v1/ai/status").text
    assert ai_preferences.credential("groq") == KEY
    folder = ai_preferences.directory()
    assert KEY.encode() not in (folder / "settings.enc").read_bytes()
    assert stat.S_IMODE(folder.stat().st_mode) == 0o700
    for name in ("settings.enc", "master.key"):
        assert stat.S_IMODE((folder / name).stat().st_mode) == 0o600


def test_default_persists_and_routes_to_selected_model(client):
    data = save(client).json()
    model = next(p for p in data["providers"] if p["id"] == "groq")["models"][0]
    response = client.put("/api/v1/settings/ai/default", headers=TOKEN, json={"provider": "groq", "model": model})
    assert response.status_code == 200
    assert client.get("/api/v1/ai/status").json()["model"] == model
    assert ai_preferences.load()["default"] == {"provider": "groq", "model": model}
    assert advisor_v07._provider_settings() == ("groq", model, KEY)


def test_auth_and_invalid_requests_do_not_leak_keys(client):
    payload = {"provider": "groq", "action": "save", "api_key": KEY}
    assert client.put("/api/v1/settings/ai/credential", json=payload).status_code == 403
    for bad in ({**payload, "provider": "bad"}, {**payload, "endpoint": KEY}, {**payload, "api_key": {"value": KEY}}, {**payload, "api_key": KEY * 200}):
        response = client.put("/api/v1/settings/ai/credential", headers=TOKEN, json=bad)
        assert response.status_code == 422
        assert KEY not in response.text
    assert not ai_preferences.directory().exists()


def test_environment_credential_cannot_be_overridden(client, monkeypatch):
    monkeypatch.setenv("CLOUDSENTINEL_AI_GROQ_API_KEY", "environment-dummy")
    assert save(client).status_code == 409
    assert ai_preferences.credential("groq") == "environment-dummy"
    assert "environment-dummy" not in client.get("/api/v1/settings/ai").text


def test_remove_disables_provider_without_erasing_other_settings(client):
    save(client)
    save(client, "openai", "other-dummy")
    response = client.put("/api/v1/settings/ai/credential", headers=TOKEN, json={"provider": "groq", "action": "remove"})
    assert response.status_code == 200
    assert ai_preferences.credential("groq") == ""
    assert ai_preferences.credential("openai") == "other-dummy"


def test_unapproved_model_rejected(client):
    save(client)
    response = client.put("/api/v1/settings/ai/default", headers=TOKEN, json={"provider": "groq", "model": "not-approved"})
    assert response.status_code == 409
    assert "default" not in ai_preferences.load()


def test_corruption_fails_closed(client):
    save(client)
    (ai_preferences.directory() / "settings.enc").write_bytes(b"corrupted")
    response = client.get("/api/v1/settings/ai")
    assert response.status_code == 503
    assert KEY not in response.text


def test_concurrent_updates_preserve_both_credentials(client):
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(ai_preferences.save_credential, name, "dummy-" + name) for name in ("groq", "openai")]
        for future in futures:
            future.result()
    assert set(ai_preferences.load()["credentials"]) == {"groq", "openai"}


def test_permissive_permissions_fail_closed(client):
    save(client)
    (ai_preferences.directory() / "master.key").chmod(0o644)
    assert client.get("/api/v1/settings/ai").status_code == 503
