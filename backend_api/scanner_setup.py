"""Local, explicit, pinned scanner installation; no cloud credentials or raw logs."""
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

VERSION = "5.46.0"


def managed_dir():
    return Path.home() / ".venvs" / f"cloudsentinel-prowler-managed-{VERSION}"


def managed_executable():
    root = managed_dir()
    binary = root / "bin/prowler"
    return str(binary) if (root / ".ready").is_file() and binary.is_file() and os.access(binary, os.X_OK) else None


def clean_env():
    # Do not inherit AWS/AI credentials, pip configuration, or arbitrary Python paths.
    return {"HOME": str(Path.home()), "PATH": "/usr/local/bin:/usr/bin:/bin",
            "LANG": "C.UTF-8", "PIP_CONFIG_FILE": os.devnull,
            "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PYTHONNOUSERSITE": "1"}


def version_of(binary):
    try:
        result = subprocess.run([binary, "--version"], env=clean_env(),
                                capture_output=True, timeout=10, check=True)
        match = re.search(r"\b(\d+\.\d+\.\d+)\b", result.stdout.decode(errors="replace"))
        return match.group(1) if match else None
    except (OSError, subprocess.SubprocessError):
        return None


class ScannerSetup:
    def __init__(self):
        self.lock = threading.RLock()
        self.pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="scanner-setup")
        self.state = "idle"
        self.message = "Check the scanner environment before scanning."
        self.cache = None

    def status(self):
        from backend_api.web_scans import executable
        with self.lock:
            binary = executable()
            signature = (binary, Path(binary).stat().st_mtime_ns) if binary else None
            if signature and (not self.cache or self.cache[0] != signature):
                self.cache = (signature, version_of(binary))
            version = self.cache[1] if signature and self.cache else None
            supported = sys.platform.startswith("linux") and sys.version_info >= (3, 10)
            external = bool(os.getenv("CLOUDSENTINEL_PROWLER_BIN"))
            busy = self.state in ("preparing", "installing", "verifying")
            state, message = self.state, self.message
            if state == "idle" and not binary and managed_dir().exists():
                state, message = "interrupted", "An incomplete setup was found. Retry installation to finish it."
            elif state == "idle" and version:
                message = "Prowler is available. No installation is needed."
            return {"installed": bool(binary), "version": version,
                    "verified": bool(version), "supported": supported,
                    "target_version": VERSION, "state": state, "message": message,
                    "busy": busy, "can_install": supported and not binary and not external and not busy,
                    "server_managed": external,
                    "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"}

    def update(self, state, message):
        with self.lock:
            self.state, self.message = state, message

    def start(self):
        from backend_api.web_scans import manager
        with self.lock:
            status = self.status()
            if not status["can_install"]:
                raise ValueError("Installation unavailable: scanner is installed, setup is active, or environment is unsupported/server managed.")
            if manager.active():
                raise ValueError("Wait for the active scan to finish before installing.")
            # Cross-process lock also prevents two backend instances installing together.
            import fcntl
            root = managed_dir()
            root.parent.mkdir(parents=True, exist_ok=True)
            lock_file = open(root.parent / ".cloudsentinel-scanner-install.lock", "a")
            try:
                fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                lock_file.close()
                raise ValueError("Another scanner installation is running. Try again after it finishes.")
            self.update("preparing", "Creating a separate Python environment…")
            try:
                self.pool.submit(self.run, lock_file)
            except Exception:
                lock_file.close()
                self.update("failed", "Unable to start installer. Retry installation.")
                raise
            return self.status()

    def command(self, args, timeout):
        from backend_api.web_scans import WebScans
        wrapper = Path(__file__).with_name("scan_child.py")
        process = subprocess.Popen([sys.executable, "-I", str(wrapper), str(os.getpid()), *args],
                                   env=clean_env(), stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            if process.wait(timeout=timeout) != 0:
                raise RuntimeError("Installer command failed")
        except BaseException:
            WebScans.stop(process)
            raise

    def run(self, lock_file):
        root = managed_dir()
        try:
            # Retry reuses only our dedicated environment; never alters existing scanners.
            root.mkdir(mode=0o700, exist_ok=True)
            if root.is_symlink():
                raise RuntimeError("Managed environment must not be a symlink")
            root.chmod(0o700)
            self.command([sys.executable, "-I", "-m", "venv", str(root)], 120)
            self.update("installing", f"Downloading Prowler {VERSION} and dependencies from PyPI. This may take several minutes…")
            self.command([str(root / "bin/python"), "-I", "-m", "pip", "install",
                          "--index-url", "https://pypi.org/simple", "--no-input", "--timeout", "30",
                          "--retries", "2", f"prowler=={VERSION}"], 1200)
            self.update("verifying", "Checking the installed Prowler executable…")
            if version_of(str(root / "bin/prowler")) != VERSION:
                raise RuntimeError("Version verification failed")
            (root / ".ready").write_text(VERSION, encoding="utf-8")
            self.cache = None
            self.update("completed", "Prowler is ready. Connect AWS in Settings to start scanning.")
        except subprocess.TimeoutExpired:
            self.update("failed", "Installation timed out. Check your network and retry.")
        except Exception:
            self.update("failed", "Setup failed. Check internet access to PyPI, free disk space and Python venv support, then retry. Existing scanners are unchanged.")
        finally:
            lock_file.close()


manager = ScannerSetup()
