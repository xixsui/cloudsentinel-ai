"""Immutable, content-addressed scan imports and conservative observation comparisons."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone

from ai_module.remediation_tracker import parse_dt, utc_now
from prowler_module.event_time import event_time


class ScanHistory:
    def __init__(self, db_path):
        self.db_path = db_path
        with self.connect() as con:
            con.executescript("""
                CREATE TABLE IF NOT EXISTS scan_runs (
                    id TEXT PRIMARY KEY, imported_at TEXT NOT NULL,
                    scanned_at TEXT, source TEXT NOT NULL, synthetic INTEGER NOT NULL,
                    event_count INTEGER NOT NULL, observations TEXT NOT NULL
                );
            """)

    @contextmanager
    def connect(self):
        con = sqlite3.connect(self.db_path, timeout=10)
        con.row_factory = sqlite3.Row
        try:
            with con:
                yield con
        finally:
            con.close()

    def ingest(self, events, *, synthetic=False, connection=None):
        if not isinstance(events, list) or not events or len(events) > 20000:
            raise ValueError("Provide between 1 and 20000 OCSF events")
        from prowler_module.scanner import ProwlerScanner
        observations = {}
        times = []
        for event in events:
            if not isinstance(event, dict):
                raise ValueError("Each event must be an object")
            for field in ("cloud", "finding_info", "unmapped", "metadata", "remediation"):
                if event.get(field) is not None and not isinstance(event[field], dict):
                    raise ValueError(f"{field} must be an object")
            resources = event.get("resources") or []
            if not isinstance(resources, list) or any(not isinstance(r, dict) for r in resources):
                raise ValueError("resources must be an array of objects")
            cloud = event.get("cloud") or {}
            account = cloud.get("account") or {}
            product = (event.get("metadata") or {}).get("product") or {}
            if not isinstance(account, dict) or not isinstance(product, dict):
                raise ValueError("account and product must be objects")
            unmapped = event.get("unmapped") or {}
            info = event.get("finding_info") or {}
            resource = resources[0] if resources else {}
            account_id = account.get("uid") or event.get("cloud_account_uid") or ""
            region = resource.get("region") or event.get("region") or cloud.get("region") or ""
            resource_id = resource.get("uid") or resource.get("name") or event.get("resource_uid") or event.get("resource") or ""
            uid = info.get("uid") or ""
            if not isinstance(uid, str):
                raise ValueError("Finding UID must be a string")
            analytic = info.get("analytic") or {}
            if not isinstance(analytic, dict):
                raise ValueError("finding_info.analytic must be an object")
            check_id = unmapped.get("check_id") or analytic.get("uid") or ProwlerScanner._derive_check_id(uid) or "unknown_check"
            version = unmapped.get("check_version") or product.get("version") or "unknown"
            provider = cloud.get("provider") or "aws"
            identity = [provider, account_id, region, resource_id, check_id, version]
            if any(not isinstance(v, str) or len(v) > 4096 for v in identity):
                raise ValueError("Identity fields must be strings of at most 4096 characters")
            provider = provider.lower()
            identity[0] = provider
            timestamp = event_time(event)
            key = hashlib.sha256(json.dumps(identity).encode()).hexdigest()
            status = str(event.get("status_code", "UNKNOWN")).upper()
            status = "FAIL" if status == "FAILED" else status
            if status not in {"PASS", "FAIL", "MANUAL"}:
                status = "UNKNOWN"
            complete = all(identity[1:5]) and check_id != "unknown_check" and len(resources) <= 1
            item = {
                "provider": provider,
                "source_scan_id": str((event.get("unmapped") or {}).get("scan_id") or ""),
                "key": key, "account": account_id, "region": region,
                "resource": resource_id, "check": check_id, "version": version,
                "status": status, "comparable": bool(complete and timestamp),
                "scanned_at": timestamp.isoformat() if timestamp else None,
            }
            if key in observations:
                previous = observations[key]
                if previous["status"] != status:
                    item["status"] = "CONFLICT"
                item["comparable"] &= previous["comparable"]
                if item["scanned_at"] != previous["scanned_at"]:
                    item["comparable"] = False
                    item["scanned_at"] = min(item["scanned_at"] or "", previous["scanned_at"] or "") or None
                if item["source_scan_id"] != previous["source_scan_id"]:
                    item["comparable"] = False
            observations[key] = item
            times.append(timestamp)
        canonical = json.dumps(sorted(json.dumps(e, sort_keys=True) for e in events))
        run_id = hashlib.sha256((str(synthetic) + canonical).encode()).hexdigest()
        scanned_at = max(times).isoformat() if all(times) else None
        with nullcontext(connection) if connection is not None else self.connect() as con:
            # Same content hash: refresh derived parsing without duplicating the import.
            con.execute("""INSERT INTO scan_runs VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET scanned_at=excluded.scanned_at,
                observations=excluded.observations""", (
                run_id, utc_now(), scanned_at, "OCSF import", int(synthetic), len(events),
                json.dumps(list(observations.values())),
            ))
            row = con.execute("SELECT * FROM scan_runs WHERE id=?", (run_id,)).fetchone()
            return self.serialize(row, detail=True)

    @staticmethod
    def serialize(row, *, detail=False):
        result = dict(row)
        observations = json.loads(result.pop("observations"))
        result["synthetic"] = bool(result["synthetic"])
        result["counts"] = {s: sum(o["status"] == s for o in observations)
                            for s in ("PASS", "FAIL", "MANUAL", "UNKNOWN", "CONFLICT")}
        result["observation_count"] = len(observations)
        result["comparison_notice"] = ("Scan time could not be read. Reimport the original report; comparison requires valid event time."
                                       if not result["scanned_at"] else "")
        result["scope"] = {
            "accounts": sorted({o["account"] for o in observations if o["account"]}),
            "regions": sorted({o["region"] for o in observations if o["region"]}),
            "providers": sorted({o.get("provider", "aws") for o in observations}),
        }
        if detail:
            result["observations"] = observations
        return result

    def list_runs(self):
        with self.connect() as con:
            return [self.serialize(r) for r in con.execute(
                "SELECT * FROM scan_runs ORDER BY imported_at DESC LIMIT 200")]

    def get(self, run_id):
        with self.connect() as con:
            row = con.execute("SELECT * FROM scan_runs WHERE id=?", (run_id,)).fetchone()
        if row is None:
            raise LookupError("Scan run not found")
        return self.serialize(row, detail=True)

    def compare(self, before_id, after_id):
        before, after = self.get(before_id), self.get(after_id)
        if before_id == after_id or before["synthetic"] != after["synthetic"]:
            raise ValueError("Choose distinct scans with the same synthetic/historical label")
        if not before["scanned_at"] or not after["scanned_at"]:
            raise ValueError("Comparison requires valid, non-future event timestamps")
        if parse_dt(after["scanned_at"]) <= parse_dt(before["scanned_at"]):
            raise ValueError("After scan must be newer by event time, not import time")
        old = {o["key"]: o for o in before["observations"]}
        new = {o["key"]: o for o in after["observations"]}
        items = []
        for key in sorted(old.keys() | new.keys()):
            a, b = old.get(key), new.get(key)
            if not ((a and a["status"] == "FAIL") or (b and b["status"] == "FAIL")):
                continue
            outcome = "Not Rechecked"
            if b and b["comparable"] and (not a or a["comparable"]):
                fresh = not a or parse_dt(b["scanned_at"]) > parse_dt(a["scanned_at"])
                if a and a.get("source_scan_id") and a["source_scan_id"] == b.get("source_scan_id"):
                    fresh = False
                if fresh and b["status"] == "FAIL" and (not a or a["status"] == "PASS"):
                    outcome = "New"
                elif fresh and a and a["status"] == "FAIL":
                    outcome = {"FAIL": "Persisting", "PASS": "Resolved"}.get(b["status"], outcome)
            item = dict(b or a)
            item["account"] = "…" + item["account"][-4:] if item["account"] else "Unknown"
            item.update(outcome=outcome, before_status=a["status"] if a else None,
                        after_status=b["status"] if b else None)
            items.append(item)
        return {"items": items, "counts": {s: sum(i["outcome"] == s for i in items)
                for s in ("New", "Persisting", "Resolved", "Not Rechecked")},
                "notice": "Resolved means a later scanner PASS, not authenticated remediation verification. Missing, manual or conflicting results never resolve a FAIL."}
