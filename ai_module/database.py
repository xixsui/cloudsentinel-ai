"""
SQLite storage layer for the AI-Assisted Cloud Cybersecurity System.

Everything in the pipeline reads/writes through here:
- Prowler / Wazuh / Suricata write normalised Findings.
- The AI module writes AIAnalysis rows and caches LLM responses.
- The Streamlit dashboard reads Findings + AIAnalysis + Incidents.

A single SQLite file keeps the prototype simple and dependency-free, which
suits a small-scale academic lab (no external DB server to manage).
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager, nullcontext
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional

from ai_module.models import (
    AIAnalysis,
    Finding,
    FindingType,
    Incident,
    Severity,
    Status,
)

# Default DB lives under data/ next to the project root.
DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "findings.db"


class Database:
    """Thin wrapper around SQLite for the project's tables."""

    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    finding_id   TEXT PRIMARY KEY,
                    finding_type TEXT NOT NULL,
                    source       TEXT NOT NULL,
                    severity     TEXT NOT NULL,
                    title        TEXT NOT NULL,
                    description  TEXT,
                    resource     TEXT,
                    account_id   TEXT,
                    region       TEXT,
                    check_id     TEXT,
                    compliance   TEXT,            -- JSON list
                    raw_evidence TEXT,            -- JSON dict
                    timestamp    TEXT NOT NULL,
                    status       TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scan_finding_links (
                    scan_id TEXT NOT NULL, finding_id TEXT NOT NULL,
                    PRIMARY KEY(scan_id, finding_id)
                );
                INSERT OR IGNORE INTO scan_finding_links
                    SELECT json_extract(raw_evidence, '$.scan_history_id'), finding_id FROM findings
                    WHERE json_valid(raw_evidence) AND json_extract(raw_evidence, '$.scan_history_id') IS NOT NULL;
                CREATE TABLE IF NOT EXISTS ai_analysis (
                    finding_id        TEXT PRIMARY KEY,
                    explanation       TEXT,
                    attack_scenario   TEXT,
                    risk_priority     TEXT,
                    risk_justification TEXT,
                    mitigation_steps  TEXT,       -- JSON list
                    references_       TEXT,       -- JSON list
                    model_used        TEXT,
                    duration_ms       INTEGER DEFAULT 0,
                    input_tokens      INTEGER DEFAULT 0,
                    output_tokens     INTEGER DEFAULT 0,
                    analyzed_at       TEXT,
                    FOREIGN KEY (finding_id) REFERENCES findings(finding_id)
                );

                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id   TEXT PRIMARY KEY,
                    title         TEXT,
                    severity      TEXT,
                    summary       TEXT,
                    finding_ids   TEXT,           -- JSON list
                    linked_entity TEXT,
                    ai_narrative  TEXT,
                    timestamp     TEXT,
                    status        TEXT
                );

                -- Cache so identical findings don't re-hit the LLM API (cost control).
                CREATE TABLE IF NOT EXISTS incident_activity (
                    activity_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    previous_value TEXT,
                    new_value TEXT,
                    note TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_incident_activity_incident
                    ON incident_activity (incident_id, activity_id);

                CREATE TABLE IF NOT EXISTS ai_cache (
                    cache_key   TEXT PRIMARY KEY,  -- hash of prompt input
                    response    TEXT,              -- raw JSON response
                    created_at  TEXT
                );
                """
            )
            # Migrations for existing installations — safe to run every time
            # (each column is added only if it doesn't exist yet).
            self._maybe_add_column(conn, "ai_analysis", "duration_ms",   "INTEGER DEFAULT 0")
            self._maybe_add_column(conn, "ai_analysis", "input_tokens",  "INTEGER DEFAULT 0")
            self._maybe_add_column(conn, "ai_analysis", "output_tokens", "INTEGER DEFAULT 0")
            self._maybe_add_column(conn, "incidents", "assignee", "TEXT NOT NULL DEFAULT ''")
            self._maybe_add_column(conn, "incidents", "resolution_note", "TEXT NOT NULL DEFAULT ''")
            self._maybe_add_column(conn, "incidents", "updated_at", "TEXT")

    @staticmethod
    def _maybe_add_column(conn: sqlite3.Connection, table: str,
                          column: str, spec: str) -> None:
        cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}
        if column not in cols:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {spec}")

    # ------------------------------------------------------------------ #
    # Findings
    # ------------------------------------------------------------------ #
    def upsert_finding(self, f: Finding) -> None:
        self.upsert_findings([f])

    def upsert_findings(self, findings: list[Finding], *, connection=None) -> None:
        """Batch writes in one transaction while preserving analyst workflow status."""
        with nullcontext(connection) if connection is not None else self._conn() as conn:
            conn.executemany(
                """
                INSERT INTO findings (finding_id, finding_type, source, severity,
                    title, description, resource, account_id, region, check_id,
                    compliance, raw_evidence, timestamp, status)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(finding_id) DO UPDATE SET
                    severity=excluded.severity,
                    description=excluded.description,
                    title=excluded.title,
                    raw_evidence=excluded.raw_evidence,
                    compliance=excluded.compliance
                """,
                [(
                    f.finding_id, f.finding_type.value, f.source, f.severity.value,
                    f.title, f.description, f.resource, f.account_id, f.region,
                    f.check_id, json.dumps(f.compliance), json.dumps(f.raw_evidence),
                    f.timestamp.isoformat(), f.status.value,
                ) for f in findings],
            )

    def has_synthetic_findings(self) -> bool:
        """Flag labeled demo fixtures, so analysts don't confuse them with live data."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT 1 FROM findings WHERE raw_evidence LIKE ? LIMIT 1",
                ('%"synthetic_demo": true%',),
            ).fetchone()
        return row is not None

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        """Exact-ID lookup for the v0.6 API (no fuzzy resource matching)."""
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM findings WHERE finding_id = ?", (finding_id,)).fetchone()
        return self._row_to_finding(row) if row else None

    def get_findings(
        self,
        status: Optional[Status] = None,
        finding_type: Optional[FindingType] = None,
    ) -> list[Finding]:
        query = "SELECT * FROM findings"
        clauses, params = [], []
        if status:
            clauses.append("status = ?")
            params.append(status.value)
        if finding_type:
            clauses.append("finding_type = ?")
            params.append(finding_type.value)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY timestamp DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def get_unanalyzed_findings(
        self, min_severity: Optional[Severity] = None,
    ) -> list[Finding]:
        """
        Findings that don't yet have an AI analysis row.

        If `min_severity` is given, only return findings at or above that level
        (used by the orchestrator to auto-analyse high-priority items only).
        """
        query = (
            "SELECT f.* FROM findings f "
            "LEFT JOIN ai_analysis a ON f.finding_id = a.finding_id "
            "WHERE a.finding_id IS NULL"
        )
        params: list = []
        if min_severity is not None:
            order = ["Critical", "High", "Medium", "Low", "Informational"]
            allowed = order[: order.index(min_severity.value) + 1]
            placeholders = ",".join("?" for _ in allowed)
            query += f" AND f.severity IN ({placeholders})"
            params.extend(allowed)
        query += " ORDER BY f.timestamp DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def get_findings_filtered(
        self,
        finding_type: Optional[FindingType] = None,
        severities: Optional[list[str]] = None,
        sources: Optional[list[str]] = None,
        statuses: Optional[list[str]] = None,
        search: Optional[str] = None,
        order_by_severity_first: bool = True,
        limit: Optional[int] = None,
        offset: int = 0,
        account_id: str | None = None,
        scan_id: str | None = None,
    ) -> tuple[list[Finding], int]:
        """
        Filtered + paginated findings query.

        Returns (rows, total_count). `total_count` reflects ALL matching rows
        before limit/offset so the UI can show "page 1 of N".
        """
        if scan_id:
            from ai_module.scan_snapshots import read
            rows = read(self.db_path, scan_id)
            rows = [f for f in rows if (not account_id or f.account_id == account_id)
                    and (not finding_type or f.finding_type == finding_type)
                    and (not severities or f.severity.value in severities)
                    and (not sources or f.source in sources)
                    and (not statuses or f.status.value in statuses)
                    and (not search or search.lower() in (f.title + f.description + f.resource).lower())]
            rows.sort(key=lambda f: f.timestamp.isoformat(), reverse=True)
            if order_by_severity_first:
                ranks = {s: i for i, s in enumerate(["Critical", "High", "Medium", "Low", "Informational"])}
                rows.sort(key=lambda f: ranks[f.severity.value])
            return rows[offset:offset + limit if limit is not None else None], len(rows)
        clauses: list[str] = []
        params: list = []
        if account_id:
            clauses.append("account_id = ?")
            params.append(account_id)
        if scan_id:
            clauses.append("finding_id IN (SELECT finding_id FROM scan_finding_links WHERE scan_id=?)")
            params.append(scan_id)
        if finding_type:
            clauses.append("finding_type = ?")
            params.append(finding_type.value)
        if severities:
            clauses.append(f"severity IN ({','.join('?' for _ in severities)})")
            params.extend(severities)
        if sources:
            clauses.append(f"source IN ({','.join('?' for _ in sources)})")
            params.extend(sources)
        if statuses:
            clauses.append(f"status IN ({','.join('?' for _ in statuses)})")
            params.extend(statuses)
        if search:
            like = f"%{search.lower()}%"
            clauses.append(
                "(LOWER(title) LIKE ? OR LOWER(description) LIKE ? OR LOWER(resource) LIKE ?)"
            )
            params.extend([like, like, like])

        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""

        count_q = f"SELECT COUNT(*) c FROM findings{where}"
        with self._conn() as conn:
            total = conn.execute(count_q, params).fetchone()["c"]

            order = (
                "CASE severity "
                "WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 "
                "WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END, "
                "timestamp DESC"
            ) if order_by_severity_first else "timestamp DESC"
            data_q = f"SELECT * FROM findings{where} ORDER BY {order}"
            if limit is not None:
                data_q += " LIMIT ? OFFSET ?"
                params2 = params + [int(limit), int(offset)]
            else:
                params2 = params
            rows = conn.execute(data_q, params2).fetchall()

        return [self._row_to_finding(r) for r in rows], total

    def distinct_values(self, column: str) -> list[str]:
        """Distinct values in a findings column — used to build filter dropdowns."""
        allowed = {"source", "severity", "status", "region", "account_id"}
        if column not in allowed:
            return []
        with self._conn() as conn:
            rows = conn.execute(
                f"SELECT DISTINCT {column} FROM findings WHERE {column} IS NOT NULL "
                f"AND {column} != '' ORDER BY {column}"
            ).fetchall()
        return [r[column] for r in rows]

    def update_status(self, finding_id: str, status: Status) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE findings SET status = ? WHERE finding_id = ?",
                (status.value, finding_id),
            )

    # ------------------------------------------------------------------ #
    # AI analysis
    # ------------------------------------------------------------------ #
    def save_analysis(self, a: AIAnalysis) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO ai_analysis (finding_id, explanation, attack_scenario,
                    risk_priority, risk_justification, mitigation_steps,
                    references_, model_used, duration_ms, input_tokens,
                    output_tokens, analyzed_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(finding_id) DO UPDATE SET
                    explanation=excluded.explanation,
                    attack_scenario=excluded.attack_scenario,
                    risk_priority=excluded.risk_priority,
                    risk_justification=excluded.risk_justification,
                    mitigation_steps=excluded.mitigation_steps,
                    references_=excluded.references_,
                    model_used=excluded.model_used,
                    duration_ms=excluded.duration_ms,
                    input_tokens=excluded.input_tokens,
                    output_tokens=excluded.output_tokens,
                    analyzed_at=excluded.analyzed_at
                """,
                (
                    a.finding_id, a.explanation, a.attack_scenario,
                    a.risk_priority.value, a.risk_justification,
                    json.dumps(a.mitigation_steps), json.dumps(a.references),
                    a.model_used, a.duration_ms, a.input_tokens, a.output_tokens,
                    a.analyzed_at.isoformat(),
                ),
            )
            # Mark the finding as analyzed.
            conn.execute(
                "UPDATE findings SET status = ? WHERE finding_id = ? AND status = ?",
                (Status.ANALYZED.value, a.finding_id, Status.NEW.value),
            )

    def get_analysis(self, finding_id: str) -> Optional[AIAnalysis]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM ai_analysis WHERE finding_id = ?", (finding_id,)
            ).fetchone()
        if not row:
            return None
        # `duration_ms` / `input_tokens` / `output_tokens` may be missing on
        # older rows written before the migration — hence the .get()-style
        # fallbacks via `try/except`.
        def _int(field: str) -> int:
            try:
                return int(row[field] or 0)
            except (KeyError, IndexError, TypeError):
                return 0
        return AIAnalysis(
            finding_id=row["finding_id"],
            explanation=row["explanation"] or "",
            attack_scenario=row["attack_scenario"] or "",
            risk_priority=Severity(row["risk_priority"]) if row["risk_priority"] else Severity.MEDIUM,
            risk_justification=row["risk_justification"] or "",
            mitigation_steps=json.loads(row["mitigation_steps"] or "[]"),
            references=json.loads(row["references_"] or "[]"),
            model_used=row["model_used"] or "",
            duration_ms=_int("duration_ms"),
            input_tokens=_int("input_tokens"),
            output_tokens=_int("output_tokens"),
            analyzed_at=datetime.fromisoformat(row["analyzed_at"]) if row["analyzed_at"] else datetime.utcnow(),
        )

    # ------------------------------------------------------------------ #
    # Incidents
    # ------------------------------------------------------------------ #
    def save_incident(self, inc: Incident) -> None:
        """Upsert automated correlation evidence without resetting analyst decisions."""
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO incidents (incident_id, title, severity, summary,
                    finding_ids, linked_entity, ai_narrative, timestamp, status,
                    assignee, resolution_note, updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(incident_id) DO UPDATE SET
                    title=excluded.title,
                    summary=excluded.summary,
                    ai_narrative=excluded.ai_narrative,
                    severity=excluded.severity,
                    finding_ids=excluded.finding_ids,
                    linked_entity=excluded.linked_entity
                """,
                (
                    inc.incident_id, inc.title, inc.severity.value, inc.summary,
                    json.dumps(inc.finding_ids), inc.linked_entity, inc.ai_narrative,
                    inc.timestamp.isoformat(), inc.status.value,
                    inc.assignee, inc.resolution_note,
                    (inc.updated_at or inc.timestamp).isoformat(),
                ),
            )

    @staticmethod
    def _row_to_incident(r: sqlite3.Row) -> Incident:
        return Incident(
            incident_id=r["incident_id"], title=r["title"] or "",
            severity=Severity(r["severity"]), summary=r["summary"] or "",
            finding_ids=json.loads(r["finding_ids"] or "[]"),
            linked_entity=r["linked_entity"] or "",
            ai_narrative=r["ai_narrative"] or "",
            timestamp=datetime.fromisoformat(r["timestamp"]),
            status=Status(r["status"]), assignee=r["assignee"] or "",
            resolution_note=r["resolution_note"] or "",
            updated_at=(datetime.fromisoformat(r["updated_at"])
                        if r["updated_at"] else None),
        )

    def get_incidents(self) -> list[Incident]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM incidents ORDER BY timestamp DESC").fetchall()
        return [self._row_to_incident(r) for r in rows]

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
        return self._row_to_incident(row) if row else None

    def get_incident_activity(self, incident_id: str) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM incident_activity WHERE incident_id = ? "
                "ORDER BY activity_id DESC", (incident_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    def update_incident_workflow(
        self,
        incident_id: str,
        *,
        status: Status,
        assignee: str,
        actor: str,
        note: str = "",
    ) -> None:
        """Atomically update local triage state and write append-only audit entries.

        Actor is a self-entered display label, NOT authenticated identity.
        No support for multi-user/hosted access is implied by this audit trail.
        """
        allowed = {Status.NEW, Status.ANALYZED, Status.INVESTIGATING,
                   Status.RESOLVED, Status.FALSE_POSITIVE}
        if status not in allowed:
            raise ValueError("Unsupported incident status")
        actor, assignee, note = actor.strip(), assignee.strip(), note.strip()
        if not actor or len(actor) > 80:
            raise ValueError("An analyst label (1–80 characters) is required")
        if len(assignee) > 80 or len(note) > 2000:
            raise ValueError("Assignee or note is too long")
        with self._conn() as conn:
            previous = conn.execute(
                "SELECT status, assignee FROM incidents WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
            if previous is None:
                raise ValueError("Incident not found")
            old_status = Status(previous["status"])
            old_assignee = previous["assignee"] or ""
            # Reopening a closed case must be explicit. A closed incident cannot
            # silently be reset to New or directly flipped to another outcome.
            if old_status in {Status.RESOLVED, Status.FALSE_POSITIVE} and status not in {
                old_status, Status.INVESTIGATING,
            }:
                raise ValueError("Reopen a closed case as Investigating before other changes")
            if old_status == Status.INVESTIGATING and status == Status.NEW:
                raise ValueError("An active investigation cannot be reset to New")
            status_changed = old_status != status
            assignee_changed = old_assignee != assignee
            if not (status_changed or assignee_changed or note):
                raise ValueError("No change or investigation note supplied")
            if status in {Status.RESOLVED, Status.FALSE_POSITIVE} and (
                status_changed or old_status not in {Status.RESOLVED, Status.FALSE_POSITIVE}
            ) and not note:
                raise ValueError("Closing an incident requires a justification note")
            # Preserve an earlier resolution note when merely reassigning an already-closed incident.
            new_resolution = note if status_changed and status in {
                Status.RESOLVED, Status.FALSE_POSITIVE,
            } else ("" if status_changed else None)
            now = datetime.utcnow().isoformat()
            if new_resolution is None:
                conn.execute(
                    "UPDATE incidents SET status=?, assignee=?, updated_at=? WHERE incident_id=?",
                    (status.value, assignee, now, incident_id),
                )
            else:
                conn.execute(
                    "UPDATE incidents SET status=?, assignee=?, resolution_note=?, updated_at=? "
                    "WHERE incident_id=?",
                    (status.value, assignee, new_resolution, now, incident_id),
                )
            events = []
            if status_changed:
                events.append(("status_changed", old_status.value, status.value, note))
            if assignee_changed:
                events.append(("assigned", old_assignee, assignee, "" if status_changed else note))
            if note and not status_changed and not assignee_changed:
                events.append(("analyst_note", "", "", note))
            for action, old_value, new_value, event_note in events:
                conn.execute(
                    "INSERT INTO incident_activity (incident_id, occurred_at, actor, "
                    "action, previous_value, new_value, note) VALUES (?,?,?,?,?,?,?)",
                    (incident_id, now, actor, action, old_value, new_value, event_note),
                )

    # ------------------------------------------------------------------ #
    # AI response cache (cost control)
    # ------------------------------------------------------------------ #
    def get_cached(self, cache_key: str) -> Optional[str]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT response FROM ai_cache WHERE cache_key = ?", (cache_key,)
            ).fetchone()
        return row["response"] if row else None

    def set_cached(self, cache_key: str, response: str) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO ai_cache (cache_key, response, created_at) VALUES (?,?,?)",
                (cache_key, response, datetime.utcnow().isoformat()),
            )

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _row_to_finding(r: sqlite3.Row) -> Finding:
        return Finding(
            finding_id=r["finding_id"],
            finding_type=FindingType(r["finding_type"]),
            source=r["source"],
            severity=Severity(r["severity"]),
            title=r["title"],
            description=r["description"] or "",
            resource=r["resource"] or "",
            account_id=r["account_id"] or "",
            region=r["region"] or "",
            check_id=r["check_id"] or "",
            compliance=json.loads(r["compliance"] or "[]"),
            raw_evidence=json.loads(r["raw_evidence"] or "{}"),
            timestamp=datetime.fromisoformat(r["timestamp"]),
            status=Status(r["status"]),
        )

    def stats(self) -> dict:
        """Quick counts for the dashboard overview page."""
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) c FROM findings").fetchone()["c"]
            by_sev = {
                row["severity"]: row["c"]
                for row in conn.execute(
                    "SELECT severity, COUNT(*) c FROM findings GROUP BY severity"
                ).fetchall()
            }
            by_type = {
                row["finding_type"]: row["c"]
                for row in conn.execute(
                    "SELECT finding_type, COUNT(*) c FROM findings GROUP BY finding_type"
                ).fetchall()
            }
            analyzed = conn.execute("SELECT COUNT(*) c FROM ai_analysis").fetchone()["c"]
            incidents = conn.execute("SELECT COUNT(*) c FROM incidents").fetchone()["c"]
        return {
            "total": total,
            "by_severity": by_sev,
            "by_type": by_type,
            "analyzed": analyzed,
            "incidents": incidents,
        }
