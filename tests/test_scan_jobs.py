"""Prowler UI scan worker must be safe without a real AWS account."""

from cloud_connection.aws import AWSConnection
from ai_module.database import Database
from prowler_module.scan_jobs import ScanManager, ScanOptions
import pytest


def test_scanner_options_are_allowlisted():
    config = ScanOptions(region="ap-southeast-1", services=("s3", "iam"))
    assert config.cli_args() == ["--filter-region", "ap-southeast-1", "--services", "s3", "iam"]
    with pytest.raises(ValueError):
        ScanOptions(services=("s3", "--output"))
    with pytest.raises(ValueError):
        ScanOptions(services=())
    with pytest.raises(ValueError):
        ScanOptions(region="us-east-1; touch /tmp/x")
    with pytest.raises(ValueError):
        ScanOptions(timeout_seconds=3601)


def test_demo_scan_ingests_only_synthetic_prowler_findings(tmp_path):
    path = tmp_path / "test.db"
    manager = ScanManager()
    jid = manager.run_demo(ScanOptions(services=("s3", "iam")), path)
    job = manager.get(jid)
    assert job.status == "completed"
    assert job.mode == "demo"
    assert job.findings_added >= 2
    findings = Database(path).get_findings()
    assert len(findings) == job.findings_added
    assert all(f.source == "prowler" for f in findings)
    assert manager.list_jobs([jid])[0].job_id == jid
    assert manager.list_jobs([]) == []
    assert manager.get("missing") is None


def test_demo_scan_never_calls_live_aws_or_prowler(tmp_path, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("Demo must never call AWS / launch subprocess")
    monkeypatch.setattr(AWSConnection, "test_identity", refuse)
    import subprocess
    monkeypatch.setattr(subprocess, "run", refuse)
    jid = ScanManager().run_demo(ScanOptions(), tmp_path / "demo.db")
    assert jid


def test_live_scan_requires_verified_account_and_binary(tmp_path, monkeypatch):
    import prowler_module.scan_jobs as jobs
    monkeypatch.setattr(jobs.shutil, "which", lambda name: "/bin/prowler")
    manager = ScanManager()
    with pytest.raises(ValueError):
        manager.submit(AWSConnection(), "not-an-account", ScanOptions(), tmp_path)


def test_ocfs_events_import_without_disk_upload(tmp_path):
    from prowler_module.scanner import ProwlerScanner
    scanner = ProwlerScanner(Database(tmp_path / "test.db"))
    assert scanner.ingest_events([]) == 0
    with pytest.raises(ValueError):
        scanner.ingest_events(["fake"])
    with pytest.raises(ValueError):
        scanner.ingest_events({"bad": "shape"})
