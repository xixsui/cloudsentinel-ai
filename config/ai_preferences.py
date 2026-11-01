"""Local AI settings: encrypted outside the repo, never returned to the browser.

POSIX storage requires owner-only files. This protects against other local users,
not against the same OS user or an administrator who can read the master key.
"""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import stat
import threading

from cryptography.fernet import Fernet, InvalidToken

PROVIDERS = frozenset({"groq", "openai", "gemini", "anthropic", "private"})
_lock = threading.RLock()


class AISettingsError(RuntimeError):
    pass


def directory() -> Path:
    return Path(os.getenv("CLOUDSENTINEL_AI_SETTINGS_DIR", str(Path.home() / ".config" / "cloudsentinel-ai"))).expanduser()


def _private(path: Path) -> None:
    info = path.lstat()
    if path.is_symlink() or (os.name == "posix" and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077)):
        raise AISettingsError("AI settings storage must be owned by the current user with private permissions.")


def load() -> dict:
    root = directory()
    data = root / "settings.enc"
    if not data.exists():
        return {}
    try:
        _private(root)
        _private(data)
        _private(root / "master.key")
        return json.loads(Fernet((root / "master.key").read_bytes()).decrypt(data.read_bytes()))
    except (OSError, ValueError, InvalidToken) as exc:
        raise AISettingsError("Unable to unlock local AI settings. Restore the settings file and its matching master key.") from exc


@contextmanager
def edit():
    if os.name != "posix":
        raise AISettingsError("Encrypted Settings storage currently requires Linux/WSL. On native Windows, use server environment variables.")
    import fcntl
    root = directory()
    try:
        root.mkdir(parents=True, mode=0o700, exist_ok=True)
        _private(root)
        with _lock:
            fd = os.open(root / "settings.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "a+b") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                try:
                    state = load()
                    yield state
                    key_path = root / "master.key"
                    if not key_path.exists():
                        with os.fdopen(os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600), "wb") as key_file:
                            key_file.write(Fernet.generate_key())
                            key_file.flush()
                            os.fsync(key_file.fileno())
                    _private(key_path)
                    encrypted = Fernet(key_path.read_bytes()).encrypt(json.dumps(state).encode())
                    temporary = root / "settings.tmp"
                    with os.fdopen(os.open(temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_NOFOLLOW, 0o600), "wb") as output:
                        os.fchmod(output.fileno(), 0o600)
                        output.write(encrypted)
                        output.flush()
                        os.fsync(output.fileno())
                    os.replace(temporary, root / "settings.enc")
                finally:
                    fcntl.flock(lock, fcntl.LOCK_UN)
    except OSError as exc:
        raise AISettingsError("Could not save AI settings to private local storage.") from exc


def environment_key(provider: str) -> str:
    if provider not in PROVIDERS:
        return ""
    if provider == "private":
        return os.getenv("CLOUDSENTINEL_PRIVATE_AI_API_KEY", "").strip()
    specific = os.getenv(f"CLOUDSENTINEL_AI_{provider.upper()}_API_KEY", "").strip()
    legacy = os.getenv("CLOUDSENTINEL_AI_API_KEY", "").strip() if provider == os.getenv("CLOUDSENTINEL_AI_PROVIDER", "").strip().lower() else ""
    return specific or legacy


def credential(provider: str) -> str:
    return environment_key(provider) or load().get("credentials", {}).get(provider, "")


def save_credential(provider: str, value: str | None) -> None:
    if provider not in PROVIDERS:
        raise ValueError("Unsupported provider")
    if environment_key(provider):
        raise ValueError("This credential is managed by a server environment variable. Change it on the server first.")
    if value is not None:
        value = value.strip()
        if not value or len(value) > 4096 or any(ord(c) < 33 or ord(c) > 126 for c in value):
            raise ValueError("API key must contain 1–4096 printable non-space characters")
    with edit() as state:
        keys = state.setdefault("credentials", {})
        if value is None:
            keys.pop(provider, None)
        else:
            keys[provider] = value


def save_default(provider: str, model: str) -> None:
    with edit() as state:
        state["default"] = {"provider": provider, "model": model}
