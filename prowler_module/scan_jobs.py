"""One-worker Prowler scan queue for the local, single-operator console.

No shell, no arbitrary CLI input, child-process env only, and no credentials
in log messages. Job status survives Streamlit reruns within this process.
"""
from __future__ import annotations

import re
import shutil
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from cloud_connection.aws import AWSConnection, REGION_RE
from prowler_module.scanner import ProwlerScanner

SAFE_SERVICES = frozenset({"s3", "iam", "ec2", "vpc", "cloudtrail", "rds", "kms", "cloudwatch", "guardduty", "config"})


@dataclass(frozen=True)
class ScanOptions:
    region: str = "ap-southeast-1"
    services: tuple[str, ...] = ("s3", "iam", "ec2")
    timeout_seconds: int = 1800

    def __post_init__(self) -> None:
        if not REGION_RE.fullmatch(self.region):
            raise ValueError("Invalid AWS region")
        if not self.services or not set(self.services) <= SAFE_SERVICES:
            raise ValueError("Select one or more supported AWS services")
        if not 60 <= self.timeout_seconds <= 3600:
            raise ValueError("Scan timeout must be between 60 and 3600 seconds")

    def cli_args(self) -> list[str]:
        return ["--filter-region", self.region, "--services", *self.services]


@dataclass
class ScanJob:
    job_id: str
    account_id: str
    region: str
    services: tuple[str, ...]
    status: str = "queued"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
    finished_at: str = ""
    findings_added: int = 0
    message: str = "Waiting for scan worker"
    output_directory: str = ""
    mode: str = "live"


class ScanManager:
    """Single process / local operator. Requires auth isolation for SaaS use."""

    def __init__(self) -> None:
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="prowler-scan")
        self._lock = threading.RLock()
        self._jobs: dict[str, ScanJob] = {}

    def submit(self, conn: AWSConnection, account_id: str, options: ScanOptions,
               output_dir: str | Path, db_path: str | Path | None = None) -> str:
        if shutil.which("prowler") is None:
            raise RuntimeError("Prowler CLI not installed. Install it before running a live scan.")
        if not re.fullmatch(r"\d{12}", account_id):
            raise ValueError("Connect and verify a real AWS account before scanning")
        with self._lock:
            if any(j.status in ("queued", "running") for j in self._jobs.values()):
                raise RuntimeError("Another Prowler scan is already queued or running")
            job_id = uuid.uuid4().hex
            job = ScanJob(job_id, account_id, options.region, options.services)
            self._jobs[job_id] = job
            self._executor.submit(self._execute, job_id, conn, options, str(output_dir), db_path)
        return job_id

    def run_demo(self, options: ScanOptions, db_path: str | Path) -> str:
        """Run a fully offline, visibly simulated scan using synthetic findings."""
        from ai_module.database import Database
        from mock_data.generate import build_mock_findings

        # Mapping deliberately limited to the synthetic scenarios available.
        service_checks = {
            "s3": ("s3",), "ec2": ("ec2", "ebs", "securitygroup"),
            "iam": ("iam",), "cloudtrail": ("cloudtrail",),
        }
        with self._lock:
            if any(j.status in ("queued", "running") for j in self._jobs.values()):
                raise RuntimeError("Another Prowler scan is running")
            job_id = uuid.uuid4().hex
            job = ScanJob(job_id, "123456789012", options.region, options.services,
                          status="running", message="Generating synthetic findings", mode="demo")
            self._jobs[job_id] = job
        try:
            db = Database(db_path)
            n = 0
            for finding in build_mock_findings():
                if finding.source != "prowler":
                    continue
                check_id = (finding.check_id or "").lower()
                title = finding.title.lower()
                if any(any(token in check_id or token in title
                           for token in service_checks.get(service, ()))
                       for service in options.services):
                    db.upsert_finding(finding)
                    n += 1
            self._update(job_id, status="completed", findings_added=n,
                         message=f"Synthetic scan complete. Imported {n} demo findings.")
        except Exception:
            self._update(job_id, status="failed", message="Demo import failed. Check local database.")
        finally:
            self._update(job_id, finished_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
        return job_id

    def _execute(self, job_id: str, conn: AWSConnection, options: ScanOptions,
                 output_dir: str, db_path: str | Path | None) -> None:
        self._update(job_id, status="running", message="Scanning selected AWS services")
        try:
            from ai_module.database import Database
            db = Database(db_path) if db_path is not None else None
            scanner = ProwlerScanner(db=db)
            count = scanner.run_and_ingest(
                output_dir=output_dir,
                file_prefix="scan",
                provider="aws",
                extra_args=options.cli_args(),
                timeout_seconds=options.timeout_seconds,
                env=conn.subprocess_env(),
            )
            self._update(job_id, status="completed", findings_added=count,
                         message=f"Completed. Ingested {count} FAIL findings.")
        except Exception as exc:
            # Do not expose subprocess stderr or exception text (could include secrets).
            if isinstance(exc, (FileNotFoundError, TimeoutError)):
                detail = "Prowler executable missing or scan timed out."
            else:
                detail = "Scan failed. Check Prowler installation, permissions and server logs."
            self._update(job_id, status="failed", message=detail)
        finally:
            self._update(job_id, finished_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def _update(self, job_id: str, **attrs) -> None:
        with self._lock:
            for k, v in attrs.items():
                setattr(self._jobs[job_id], k, v)

    def get(self, job_id: str) -> ScanJob | None:
        with self._lock:
            job = self._jobs.get(job_id)
            return None if job is None else ScanJob(**vars(job))

    def list_jobs(self, allowed_job_ids: list[str]) -> list[ScanJob]:
        with self._lock:
            return [ScanJob(**vars(self._jobs[jid])) for jid in reversed(allowed_job_ids)
                    if jid in self._jobs]
