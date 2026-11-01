"""Transactional deletion of local records only. Never calls cloud APIs."""
import json
import sqlite3


def delete_data(path, ids=None):
    with sqlite3.connect(path, timeout=10) as con:
        con.execute("BEGIN IMMEDIATE")
        tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if ids is None:
            count = con.execute("SELECT count(*) FROM findings").fetchone()[0]
            for table in ("advisor_feedback_v09", "advisor_runs_v07", "ai_analysis", "remediation_activity",
                          "remediation_cases", "scan_observations", "scan_runs", "scan_finding_links", "scan_finding_snapshots", "scan_snapshot_runs", "web_scan_jobs", "incident_activity", "incidents", "ai_cache", "findings"):
                if table in tables:
                    con.execute(f"DELETE FROM {table}")
            return count
        ids = list(set(ids))
        placeholders = ",".join("?" for _ in ids)
        count = con.execute(f"SELECT count(*) FROM findings WHERE finding_id IN ({placeholders})", ids).fetchone()[0]
        if count != len(ids):
            raise ValueError("Some selected findings no longer exist. Refresh the list before deleting.")
        for table in ("advisor_feedback_v09", "advisor_runs_v07", "ai_analysis", "remediation_activity", "remediation_cases", "scan_finding_links", "scan_finding_snapshots"):
            if table in tables:
                con.execute(f"DELETE FROM {table} WHERE finding_id IN ({placeholders})", ids)
        if "incidents" in tables:
            for incident_id, raw in con.execute("SELECT incident_id, finding_ids FROM incidents").fetchall():
                linked = json.loads(raw or "[]")
                remaining = [fid for fid in linked if fid not in ids]
                if remaining == linked:
                    continue
                if remaining:
                    con.execute("UPDATE incidents SET finding_ids=?, ai_narrative='' WHERE incident_id=?", (json.dumps(remaining), incident_id))
                else:
                    if "incident_activity" in tables:
                        con.execute("DELETE FROM incident_activity WHERE incident_id=?", (incident_id,))
                    con.execute("DELETE FROM incidents WHERE incident_id=?", (incident_id,))
        # Legacy cache is keyed by prompt hashes, not finding IDs.
        if "ai_cache" in tables:
            con.execute("DELETE FROM ai_cache")
        con.execute(f"DELETE FROM findings WHERE finding_id IN ({placeholders})", ids)
        return count
