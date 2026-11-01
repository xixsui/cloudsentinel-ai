"""Bounded local scan worker. Credentials only enter child environment, never jobs/logs."""
import json
import os
from pathlib import Path
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from prowler_module.scan_jobs import ScanOptions, SAFE_SERVICES
from ai_module.scan_history import ScanHistory
from prowler_module.report_import import import_report
from backend_api.aws_errors import explain


def executable():
    from backend_api.scanner_setup import managed_executable
    explicit = os.getenv("CLOUDSENTINEL_PROWLER_BIN")
    candidate = explicit or shutil.which("prowler") or managed_executable() or str(Path.home()/".venvs/cloudsentinel-prowler/bin/prowler")
    return candidate if Path(candidate).is_file() and os.access(candidate, os.X_OK) else None


def now():
    return datetime.now(timezone.utc).isoformat()


class WebScans:
    def __init__(self):
        self.lock = threading.RLock()
        self.pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="web-prowler")
        self.current = None
        self.cancelled = threading.Event()
        self.initialized = set()

    def init(self, path):
        with self.lock, sqlite3.connect(path) as con:
            con.execute("CREATE TABLE IF NOT EXISTS web_scan_jobs (id TEXT PRIMARY KEY, payload TEXT NOT NULL)")
            if str(path) not in self.initialized:
                for jid, raw in con.execute("SELECT id,payload FROM web_scan_jobs").fetchall():
                    job = json.loads(raw)
                    if job["status"] in ("queued", "running", "importing", "cancelling"):
                        job.update(status="interrupted", message="Backend restarted before completion. Start a new scan.", finished_at=now())
                        con.execute("UPDATE web_scan_jobs SET payload=? WHERE id=?", (json.dumps(job), jid))
                self.initialized.add(str(path))

    def jobs(self, path):
        self.init(path)
        with sqlite3.connect(path) as con:
            return [json.loads(r[0]) for r in con.execute("SELECT payload FROM web_scan_jobs ORDER BY rowid DESC LIMIT 50")]

    def update(self, path, job, **values):
        job.update(values)
        with sqlite3.connect(path, timeout=10) as con:
            con.execute("INSERT INTO web_scan_jobs VALUES (?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload", (job["id"], json.dumps(job)))

    def active(self):
        with self.lock:
            return self.current is not None

    def submit(self, path, connection, account, options, recheck=None):
        binary = executable()
        if not binary:
            raise ValueError("Prowler is not installed on the backend. Follow the local scanning setup guide.")
        if not sys.platform.startswith("linux"):
            raise ValueError("Web scans require Linux/WSL for process cancellation support.")
        self.init(path)
        with self.lock:
            if self.current:
                raise ValueError("A scan is already active. Wait or cancel it first.")
            job = {"id": uuid.uuid4().hex, "account": account, "region": options.region,
                   "services": list(options.services), "status": "queued", "created_at": now(),
                   "finished_at": None, "scan_id": None, "findings_imported": 0,
                   "message": "Waiting for scanner; selected account will be reverified."}
            self.current = job["id"]
            if recheck:
                job["recheck"] = recheck
                job["target_finding_id"] = recheck["finding_id"]
            self.cancelled.clear()
            self.update(path, job)
            try:
                self.pool.submit(self.run, path, job, connection, options, binary)
            except Exception:
                self.current = None
                self.update(path, job, status="failed", message="Could not start worker.", finished_at=now())
                raise
            return dict(job)

    def cancel(self, jid):
        with self.lock:
            if self.current != jid:
                raise ValueError("This scan is no longer active.")
            self.cancelled.set()

    @staticmethod
    def stop(process):
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
            except ProcessLookupError:
                pass

    def run(self, path, job, connection, options, binary):
        process = None
        try:
            identity = connection.test_identity()
            if identity["Account"] != job["account"]:
                raise ValueError("AWS account changed. Reconnect and start a new scan.")
            if self.cancelled.is_set():
                self.update(path, job, status="cancelled", message="Cancelled before scan started.")
                return
            # Temporary directory is private and deleted after ingestion/cancel/failure.
            with tempfile.TemporaryDirectory(prefix="cloudsentinel-scan-") as output:
                command = [binary, "aws", "-M", "json-ocsf", "-F", "scan", "-o", output, *options.cli_args()]
                env = connection.subprocess_env()
                # Do not inherit application API secrets into the scanner.
                allowed = {"PATH", "HOME", "LANG", "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"}
                env = {k:v for k,v in env.items() if k in allowed or k.startswith(("AWS_", "LC_"))}
                env["AWS_SDK_UA_APP_ID"] = "CloudSentinel"
                child = [sys.executable, str(Path(__file__).with_name("scan_child.py")), str(os.getpid()), *command]
                process = subprocess.Popen(child, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
                self.update(path, job, status="running", message="Scanning selected services. Progress is phase-based, not an estimated percentage.")
                deadline = time.monotonic() + options.timeout_seconds
                while process.poll() is None:
                    if self.cancelled.wait(.3) or time.monotonic() >= deadline:
                        self.stop(process)
                        self.update(path, job, status="cancelled" if self.cancelled.is_set() else "timed_out", message="Scan stopped. Partial output was not imported.")
                        return
                if self.cancelled.is_set():
                    self.update(path, job, status="cancelled", message="Cancelled. Output was not imported.")
                    return
                if process.returncode not in (0, 3):
                    raise ValueError("Prowler failed. Check installation, AWS credentials and scanning permissions. Partial output was not imported.")
                files = list(Path(output).glob("scan*.ocsf.json"))
                if len(files) != 1 or files[0].stat().st_size > 10*1024*1024:
                    raise ValueError("Expected one OCSF report under 10 MB. Select fewer services and retry.")
                events = json.loads(files[0].read_text())
                if not isinstance(events, list) or not events:
                    raise ValueError("No check results were produced. This is not proof that the account is secure.")
                accounts = {(e.get("cloud", {}).get("account", {}).get("uid") or e.get("cloud_account_uid")) for e in events}
                if accounts != {job["account"]}:
                    raise ValueError("Report account does not match the connected account. Nothing was imported.")
                with self.lock:
                    if self.cancelled.is_set():
                        self.update(path, job, status="cancelled", message="Cancelled. Output was not imported.")
                        return
                    self.update(path, job, status="importing", message="Saving scan evidence and findings atomically.")
                    result = import_report(ScanHistory(path), events, source="Prowler web scan")
                    if job.get("recheck"):
                        from backend_api.recheck import finish
                        job["verification_result"] = finish(path, job["recheck"], result["id"], job["created_at"])
                    self.update(path, job, status="completed", scan_id=result["id"], findings_imported=result["findings_imported"], message="Scan report imported. Check results describe only the selected scan scope; remediation states were not automatically changed.")
                    if job.get("recheck"):
                        self.update(path, job, message=job["verification_result"] + ". See the finding activity for verification evidence.")
        except ValueError as exc:
            # Only our controlled errors; parser exceptions are not returned verbatim.
            message = str(exc) if str(exc).startswith(("AWS account changed", "Prowler failed", "Expected one", "No check results", "Report account")) else "Scan report could not be imported. Nothing was saved; check report format and size."
            self.update(path, job, status="failed", message=message)
        except Exception as exc:
            self.update(path, job, status="failed", message=explain(exc))
        finally:
            if process:
                self.stop(process)
            with self.lock:
                try:
                    self.update(path, job, finished_at=now())
                finally:
                    self.current = None


manager = WebScans()
