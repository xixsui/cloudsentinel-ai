"""Local single-user remediation tracking, append-only action log and scan verification.

A manual assertion NEVER becomes verified. Only a newer, distinct Prowler PASS
for the exact same finding ID after the engineer requested verification can do so.
This is a local proof-of-concept, not an authenticated audit system.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

STATES = ("Open", "In Progress", "Pending Verification", "Verified", "Accepted Risk", "False Positive")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_dt(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


class RemediationTracker:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as con:
            con.executescript("""
                CREATE TABLE IF NOT EXISTS remediation_cases (
                    finding_id TEXT PRIMARY KEY, state TEXT NOT NULL DEFAULT 'Open',
                    assignee TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL,
                    pending_at TEXT, verified_at TEXT, verified_scan_id TEXT,
                    verification_evidence TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS remediation_activity (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id TEXT NOT NULL,
                    actor TEXT NOT NULL, action TEXT NOT NULL, previous_state TEXT,
                    new_state TEXT, note TEXT NOT NULL, occurred_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS scan_observations (
                    scan_id TEXT NOT NULL, finding_id TEXT NOT NULL,
                    status TEXT NOT NULL, scanned_at TEXT NOT NULL,
                    PRIMARY KEY(scan_id, finding_id)
                );
                CREATE INDEX IF NOT EXISTS idx_remediation_activity ON remediation_activity(finding_id,id);
            """)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        con = sqlite3.connect(self.db_path, timeout=10)
        con.row_factory = sqlite3.Row
        try:
            yield con
            con.commit()
        finally:
            con.close()

    def get(self, finding_id: str) -> dict:
        with self._conn() as con:
            row = con.execute("SELECT * FROM remediation_cases WHERE finding_id=?", (finding_id,)).fetchone()
        return dict(row) if row else {"finding_id": finding_id, "state": "Open", "assignee": "", "updated_at": "", "pending_at": None,
                                      "verified_at": None, "verified_scan_id": None, "verification_evidence": ""}

    def list_cases(self) -> list[dict]:
        with self._conn() as con:
            return [dict(r) for r in con.execute("SELECT * FROM remediation_cases ORDER BY updated_at DESC")]

    def activity(self, finding_id: str) -> list[dict]:
        with self._conn() as con:
            return [dict(r) for r in con.execute("SELECT * FROM remediation_activity WHERE finding_id=? ORDER BY id DESC", (finding_id,))]

    def update(self, finding_id: str, *, state: str, assignee: str, actor: str, note: str = "") -> None:
        actor, assignee, note = actor.strip(), assignee.strip(), note.strip()
        if not finding_id or not actor or len(actor) > 80 or len(assignee) > 80 or len(note) > 2000:
            raise ValueError("Valid finding ID and analyst label (max 80), assignee (max 80), note (max 2000) required")
        if state not in STATES or state == "Verified":
            raise ValueError("Verified is set only by a new matching Prowler PASS after requesting verification")
        now = utc_now()
        with self._conn() as con:
            if not con.execute("SELECT 1 FROM findings WHERE finding_id=? AND finding_type='misconfig'", (finding_id,)).fetchone():
                raise ValueError("No matching misconfiguration finding")
            old = con.execute("SELECT * FROM remediation_cases WHERE finding_id=?", (finding_id,)).fetchone()
            old_state = old["state"] if old else "Open"
            old_assignee = old["assignee"] if old else ""
            if old_state == "Verified" and state not in {"In Progress"}:
                raise ValueError("Reopen a verified case as In Progress before other changes")
            if state == "Pending Verification" and old_state not in {"In Progress", "Pending Verification"}:
                raise ValueError("Set In Progress before requesting verification")
            if state in {"Accepted Risk", "False Positive"} and not note and old_state != state:
                raise ValueError("A reason is required to accept risk or declare a false positive")
            if state == old_state and assignee == old_assignee and not note:
                raise ValueError("Enter a change or investigation note")
            pending_at = now if state == "Pending Verification" and old_state != state else (
                old["pending_at"] if old and state == "Pending Verification" else None)
            con.execute("""INSERT INTO remediation_cases(finding_id,state,assignee,updated_at,pending_at,verified_at,verified_scan_id,verification_evidence)
                VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(finding_id) DO UPDATE SET
                state=excluded.state,assignee=excluded.assignee,updated_at=excluded.updated_at,
                pending_at=excluded.pending_at,verified_at=NULL,verified_scan_id=NULL,verification_evidence=''""",
                (finding_id, state, assignee, now, pending_at, None, None, ""))
            con.execute("INSERT INTO remediation_activity(finding_id,actor,action,previous_state,new_state,note,occurred_at) VALUES(?,?,?,?,?,?,?)",
                        (finding_id, actor, "workflow_update", old_state, state, note, now))

    def record_observations(self, observations: list[dict]) -> int:
        """Persist scan evidence; complete pending cases only on newer independent PASS.

        The scan_id must come from Prowler and each observation must have a proper
        event time. Reimporting old scan files later does not advance a case.
        """
        verified = 0
        with self._conn() as con:
            for obs in observations:
                if not obs.get("scan_id") or not obs.get("finding_id") or obs.get("status") not in {"PASS", "FAIL"}:
                    continue
                try:
                    scanned_at = parse_dt(obs["scanned_at"])
                except (TypeError, ValueError, KeyError):
                    continue
                scan_id, finding_id = str(obs["scan_id"]), str(obs["finding_id"])
                con.execute("""INSERT OR IGNORE INTO scan_observations(scan_id,finding_id,status,scanned_at) VALUES(?,?,?,?)""",
                            (scan_id, finding_id, obs["status"], scanned_at.isoformat()))
                if obs["status"] != "PASS":
                    continue
                case = con.execute("SELECT * FROM remediation_cases WHERE finding_id=? AND state='Pending Verification'", (finding_id,)).fetchone()
                if case is None or not case["pending_at"] or scanned_at <= parse_dt(case["pending_at"]):
                    continue
                # Avoid any PASS within a scan that also contains this finding as FAIL.
                if con.execute("SELECT 1 FROM scan_observations WHERE scan_id=? AND finding_id=? AND status='FAIL'", (scan_id, finding_id)).fetchone():
                    continue
                # Ensure independent baseline FAIL exists in an earlier distinct scan.
                baseline = con.execute("""SELECT 1 FROM scan_observations WHERE finding_id=? AND status='FAIL' AND scan_id<>?
                    AND scanned_at<? LIMIT 1""", (finding_id, scan_id, scanned_at.isoformat())).fetchone()
                if baseline is None:
                    continue
                verified_at = utc_now()
                con.execute("""UPDATE remediation_cases SET state='Verified',verified_at=?,verified_scan_id=?,
                    verification_evidence=?,updated_at=? WHERE finding_id=? AND state='Pending Verification'""",
                    (verified_at, scan_id, f"Prowler PASS in newer scan {scan_id} at {scanned_at.isoformat()}", verified_at, finding_id))
                con.execute("INSERT INTO remediation_activity(finding_id,actor,action,previous_state,new_state,note,occurred_at) VALUES(?,?,?,?,?,?,?)",
                            (finding_id, "prowler-verifier", "scan_verified", "Pending Verification", "Verified",
                             f"PASS in scan {scan_id}; compare baseline and current resource evidence", verified_at))
                verified += 1
        return verified
