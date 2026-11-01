"""Non-secret app settings plus OS keyring / environment-based credentials.

No API key or Wazuh password is ever persisted in config.json. Local GUI
key management uses the system credential store (optional ``keyring`` package).
For containers/headless Linux, use environment variables instead.

Migration: insecure legacy XOR/Base64 credentials are intentionally NOT used.
On the first settings save they are removed; re-enter keys in the keyring or env.
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

CONFIG_DIR = Path.home() / ".fyp-ai-cloud-sec"
CONFIG_FILE = CONFIG_DIR / "config.json"
KEYRING_SERVICE = "cloudsentinel-ai"
PROVIDER_IDS = frozenset({"anthropic", "openai", "gemini", "groq"})

DEFAULTS = {
    "active_provider": "gemini",
    "active_model": "gemini-2.5-flash",
    "preferred_models": {
        "anthropic": "claude-haiku-4-5-20251001",
        "openai": "gpt-4o-mini",
        "gemini": "gemini-2.5-flash",
        "groq": "llama-3.3-70b-versatile",
    },
    "rate_limit_seconds": 1.0,
    "usage": {
        pid: {"input": 0, "output": 0, "calls": 0}
        for pid in ("anthropic", "openai", "gemini", "groq")
    },
}


def _clean(settings: dict) -> dict:
    """Prevent persisted secrets from appearing in runtime settings or saves."""
    clean = copy.deepcopy(settings)
    clean.pop("api_keys", None)  # old insecure XOR/Base64 secrets
    clean.pop(".salt", None)
    pipeline = clean.get("pipeline")
    if isinstance(pipeline, dict):
        pipeline.pop("wazuh_password", None)
    return clean


def load() -> dict:
    merged = copy.deepcopy(DEFAULTS)
    if not CONFIG_FILE.exists():
        return merged
    try:
        on_disk = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        if not isinstance(on_disk, dict):
            return merged
    except (OSError, json.JSONDecodeError):
        return merged
    clean = _clean(on_disk)
    # Best-effort in-place sanitization of insecure legacy fields.
    if clean != on_disk:
        save(clean)
    for key, value in clean.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key].update(value)
        else:
            merged[key] = value
    return merged


def save(settings: dict) -> None:
    """Persist settings atomically with private file permissions."""
    CONFIG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(CONFIG_DIR, 0o700)
    except OSError:
        pass
    # Avoid a temporary window where secrets / config are world-readable.
    tmp = CONFIG_FILE.with_suffix(".json.tmp")
    try:
        fd = os.open(tmp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(_clean(settings), f, indent=2)
        os.replace(tmp, CONFIG_FILE)
        os.chmod(CONFIG_FILE, 0o600)
    finally:
        tmp.unlink(missing_ok=True)


def _keyring():
    try:
        import keyring
        return keyring
    except ImportError:
        return None


def _credential_name(provider_id: str) -> str:
    if provider_id not in PROVIDER_IDS:
        raise ValueError(f"Unsupported AI provider: {provider_id}")
    return f"{provider_id}-api-key"


def _get_secret(name: str, env: str) -> str:
    if os.getenv(env):
        return os.environ[env]
    kr = _keyring()
    if kr is None:
        return ""
    try:
        return kr.get_password(KEYRING_SERVICE, name) or ""
    except Exception:  # unavailable keyring backend, common on headless servers
        return ""


def _set_secret(name: str, value: str) -> None:
    kr = _keyring()
    if kr is None:
        raise RuntimeError("Install keyring and configure an OS keyring, or use environment variables.")
    try:
        if value:
            kr.set_password(KEYRING_SERVICE, name, value)
        else:
            try:
                kr.delete_password(KEYRING_SERVICE, name)
            except kr.errors.PasswordDeleteError:
                pass
    except Exception as exc:
        raise RuntimeError(
            "System credential storage unavailable. Use environment variables instead."
        ) from exc


def get_api_key(provider_id: str) -> str:
    return _get_secret(_credential_name(provider_id), f"{provider_id.upper()}_API_KEY")


def set_api_key(provider_id: str, key: str) -> None:
    _set_secret(_credential_name(provider_id), key)


def get_wazuh_password() -> str:
    return _get_secret("wazuh-indexer-password", "WAZUH_INDEXER_PASSWORD")


def set_wazuh_password(password: str) -> None:
    _set_secret("wazuh-indexer-password", password)


def set_active_provider(provider_id: str, model: Optional[str] = None) -> None:
    if provider_id not in PROVIDER_IDS:
        raise ValueError(f"Unsupported AI provider: {provider_id}")
    settings = load()
    settings["active_provider"] = provider_id
    if model:
        settings["active_model"] = model
        settings.setdefault("preferred_models", {})[provider_id] = model
    else:
        settings["active_model"] = settings.get("preferred_models", {}).get(provider_id, "")
    save(settings)


def record_usage(provider_id: str, input_tokens: int, output_tokens: int) -> None:
    settings = load()
    usage = settings.setdefault("usage", {}).setdefault(
        provider_id, {"input": 0, "output": 0, "calls": 0}
    )
    usage["input"] += input_tokens
    usage["output"] += output_tokens
    usage["calls"] += 1
    save(settings)


def reset_usage(provider_id: Optional[str] = None) -> None:
    settings = load()
    if provider_id:
        settings.setdefault("usage", {})[provider_id] = {"input": 0, "output": 0, "calls": 0}
    else:
        for pid in settings.get("usage", {}):
            settings["usage"][pid] = {"input": 0, "output": 0, "calls": 0}
    save(settings)
