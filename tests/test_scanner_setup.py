import importlib
import os
import sys
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient
from backend_api import scanner_setup as setup, web_scans
from backend_api.app import app


@pytest.fixture
def installer(tmp_path, monkeypatch):
    manager = setup.ScannerSetup()
    monkeypatch.setattr(setup, "managed_dir", lambda: tmp_path / "scanner")
    monkeypatch.setattr(web_scans, "executable", lambda: None)
    monkeypatch.delenv("CLOUDSENTINEL_PROWLER_BIN", raising=False)
    yield manager
    manager.pool.shutdown(wait=True)


def test_credentials_and_pip_overrides_are_not_inherited(monkeypatch):
    for key in ("AWS_SECRET_ACCESS_KEY", "OPENAI_API_KEY", "PIP_EXTRA_INDEX_URL", "PYTHONPATH"):
        monkeypatch.setenv(key, "private")
    env = setup.clean_env()
    assert "private" not in str(env)
    assert env["PIP_CONFIG_FILE"] == os.devnull


def test_success_pins_package_and_only_publishes_verified_install(installer, monkeypatch):
    commands = []
    installer.command = lambda args, timeout: commands.append(args)
    monkeypatch.setattr(setup, "version_of", lambda binary: setup.VERSION)
    handle = Mock()
    installer.run(handle)
    assert installer.state == "completed"
    assert (setup.managed_dir() / ".ready").read_text() == setup.VERSION
    assert f"prowler=={setup.VERSION}" in commands[1]
    assert commands[1][commands[1].index("--index-url") + 1] == "https://pypi.org/simple"
    handle.close.assert_called_once()


def test_failed_install_can_retry_and_has_no_ready_marker(installer, monkeypatch):
    installer.command = Mock(side_effect=RuntimeError("secret detail"))
    installer.run(Mock())
    assert installer.state == "failed"
    assert "secret detail" not in installer.message
    assert not (setup.managed_dir() / ".ready").exists()
    installer.command = Mock()
    monkeypatch.setattr(setup, "version_of", lambda binary: setup.VERSION)
    installer.run(Mock())
    assert installer.state == "completed"


def test_version_mismatch_is_not_published(installer, monkeypatch):
    installer.command = Mock()
    monkeypatch.setattr(setup, "version_of", lambda binary: "0.0.1")
    installer.run(Mock())
    assert installer.state == "failed"
    assert not (setup.managed_dir() / ".ready").exists()


def test_restart_detects_incomplete_environment(installer):
    setup.managed_dir().mkdir()
    assert installer.status()["state"] == "interrupted"


def test_timeout_releases_lock_without_publishing(installer):
    import subprocess
    installer.command = Mock(side_effect=subprocess.TimeoutExpired("hidden", 1))
    handle = Mock()
    installer.run(handle)
    assert installer.state == "failed"
    assert "timed out" in installer.message
    assert not (setup.managed_dir() / ".ready").exists()
    handle.close.assert_called_once()


def test_existing_and_external_scanners_cannot_be_overwritten(installer, monkeypatch, tmp_path):
    binary = tmp_path / "prowler"
    binary.touch()
    monkeypatch.setattr(web_scans, "executable", lambda: str(binary))
    monkeypatch.setattr(setup, "version_of", lambda binary: setup.VERSION)
    assert installer.status()["version"] == setup.VERSION
    with pytest.raises(ValueError):
        installer.start()
    monkeypatch.setattr(web_scans, "executable", lambda: None)
    monkeypatch.setenv("CLOUDSENTINEL_PROWLER_BIN", "/missing/operator/path")
    assert not installer.status()["can_install"]


def test_unsupported_and_busy_states(installer, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    assert not installer.status()["can_install"]
    monkeypatch.setattr(sys, "platform", "linux")
    installer.update("installing", "Installing")
    with pytest.raises(ValueError):
        installer.start()


def test_api_requires_token_consent_and_no_arbitrary_commands(installer, monkeypatch):
    api_module = importlib.import_module("backend_api.app")
    monkeypatch.setattr(api_module, "scanner_setup", installer)
    monkeypatch.setenv("CLOUDSENTINEL_WRITE_TOKEN", "test")
    installer.start = Mock(return_value={"state": "preparing"})
    client = TestClient(app)
    url = "/api/v1/settings/scanner/install"
    headers = {"X-Local-Token": "test"}
    assert client.post(url, json={"consent": True}).status_code == 403
    assert client.post(url, json={"consent": False}, headers=headers).status_code == 422
    assert client.post(url, json={"consent": True, "command": "echo unsafe"}, headers=headers).status_code == 422
    installer.start.assert_not_called()
    assert client.post(url, json={"consent": True}, headers=headers).status_code == 200
    installer.start.assert_called_once()


@pytest.mark.skipif(os.name != "posix", reason="Linux filesystem locks")
def test_cross_instance_install_lock(installer, monkeypatch):
    monkeypatch.setattr(web_scans.manager, "active", lambda: False)
    installer.pool.submit = Mock()  # Keep the lock held without starting a worker.
    installer.start()
    lock_file = installer.pool.submit.call_args.args[1]
    other = setup.ScannerSetup()
    try:
        with pytest.raises(ValueError, match="Another scanner installation"):
            other.start()
    finally:
        lock_file.close()
        other.pool.shutdown()
