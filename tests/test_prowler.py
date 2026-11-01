import json
import subprocess
from pathlib import Path

import pytest
from ai_module.database import Database
from prowler_module.scanner import ProwlerScanner


def test_scan_cannot_reingest_stale_file(monkeypatch, tmp_path):
    out = tmp_path / "output"
    out.mkdir()
    (out / "scan-old.ocsf.json").write_text('[]')

    def no_fresh_scan(cmd, **kwargs):
        assert kwargs["timeout"] > 0
        assert kwargs["capture_output"] is True
        return subprocess.CompletedProcess(cmd, 1, "", "scan error")

    monkeypatch.setattr(subprocess, "run", no_fresh_scan)
    scanner = ProwlerScanner(db=Database(tmp_path / "findings.db"))
    with pytest.raises(RuntimeError, match="no OCSF"):
        scanner.run_and_ingest(output_dir=out)


def test_fresh_empty_scan_is_accepted(monkeypatch, tmp_path):
    def fake_scan(cmd, **kwargs):
        run_dir = Path(cmd[cmd.index("-o") + 1])
        (run_dir / "scan-now.ocsf.json").write_text(json.dumps([]))
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_scan)
    scanner = ProwlerScanner(db=Database(tmp_path / "db.sqlite"))
    assert scanner.run_and_ingest(output_dir=tmp_path / "scans") == 0
    assert len(list((tmp_path / "scans").glob("run-*"))) == 1


def test_invalid_prefix_rejected(tmp_path):
    scanner = ProwlerScanner(db=Database(tmp_path / "db.sqlite"))
    with pytest.raises(ValueError):
        scanner.run_and_ingest(file_prefix="../old")
