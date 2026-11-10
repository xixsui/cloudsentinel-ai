"""Atomic historical import: scan evidence plus FAIL findings, never auto-verification."""
from datetime import datetime, timezone
import hashlib

from ai_module.database import Database
from ai_module.scan_history import ScanHistory
from prowler_module.scanner import ProwlerScanner
from prowler_module.event_time import event_time


def import_report(history: ScanHistory, events: list[dict], *, synthetic=False, source="OCSF import") -> dict:
    db = Database(history.db_path)
    parser = ProwlerScanner(db)
    findings = {}
    with history.connect() as con:
        result = history.ingest(events, synthetic=synthetic, connection=con)
        for index, event in enumerate(events, 1):
            if not parser._is_fail(event):
                continue
            try:
                # Prevent the legacy parser inventing a current scan time.
                timestamp = event_time(event)
                normalized = dict(event, time_dt=(timestamp or datetime(1970, 1, 1, tzinfo=timezone.utc)).isoformat())
                finding = parser._to_finding(normalized)
            except (TypeError, AttributeError, ValueError, IndexError) as exc:
                raise ValueError(f"Event {index}: malformed FAIL finding; no report data was saved") from exc
            if synthetic:
                # A demo import must not overwrite the same real finding's evidence.
                finding.finding_id = "demo-" + hashlib.sha256(finding.finding_id.encode()).hexdigest()[:24]
            finding.raw_evidence.update(synthetic_demo=bool(synthetic), historical_import=source == "OCSF import",
                                        scan_time_missing=timestamp is None, scan_history_id=result["id"])
            if timestamp:
                finding.timestamp = timestamp
            findings[finding.finding_id] = finding
        # Reimporting an older report captures history without rolling current evidence back.
        from ai_module.remediation_tracker import parse_dt
        current_findings = []
        for finding in findings.values():
            old = con.execute("SELECT timestamp FROM findings WHERE finding_id=?", (finding.finding_id,)).fetchone()
            if not old or parse_dt(finding.timestamp.isoformat()) >= parse_dt(old[0]):
                current_findings.append(finding)
        db.upsert_findings(current_findings, connection=con)
        con.executemany("UPDATE findings SET timestamp=? WHERE finding_id=?", [(f.timestamp.isoformat(), f.finding_id) for f in current_findings])
        from ai_module.scan_snapshots import save
        save(con, result["id"], list(findings.values()))
        con.executemany("INSERT OR IGNORE INTO scan_finding_links VALUES (?,?)", [(result["id"], fid) for fid in findings])
        if source != "OCSF import":
            con.execute("UPDATE scan_runs SET source=? WHERE id=?", (source, result["id"]))
            result["source"] = source
    result.pop("observations")
    result["findings_imported"] = len(findings)
    return result
