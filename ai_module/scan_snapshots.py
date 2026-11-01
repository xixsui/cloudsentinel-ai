"""Immutable normalized FAIL evidence; legacy reports must be reimported."""
import sqlite3
from ai_module.models import Finding


def initialize(con):
    con.execute("CREATE TABLE IF NOT EXISTS scan_snapshot_runs (scan_id TEXT PRIMARY KEY)")
    con.execute("CREATE TABLE IF NOT EXISTS scan_finding_snapshots (scan_id TEXT NOT NULL, finding_id TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(scan_id,finding_id))")


def save(con, scan_id, findings):
    initialize(con)
    if con.execute("SELECT 1 FROM scan_snapshot_runs WHERE scan_id=?", (scan_id,)).fetchone():
        return
    con.executemany("INSERT INTO scan_finding_snapshots VALUES(?,?,?)", [(scan_id, f.finding_id, f.model_dump_json()) for f in findings])
    con.execute("INSERT INTO scan_snapshot_runs VALUES(?)", (scan_id,))


def read(path, scan_id):
    with sqlite3.connect(path) as con:
        initialize(con)
        if not con.execute("SELECT 1 FROM scan_snapshot_runs WHERE scan_id=?", (scan_id,)).fetchone():
            raise LookupError("Historical snapshot unavailable. Reimport the original report to capture its evidence; current findings are not substituted.")
        return [Finding.model_validate_json(row[0]) for row in con.execute("SELECT payload FROM scan_finding_snapshots WHERE scan_id=?", (scan_id,))]
