"""
Prowler integration — turns Prowler JSON-OCSF output into normalised Findings
that the AI module and dashboard already understand.

Two ways to use it:

1. Parse an existing scan file (works without AWS access — useful for testing):
       from prowler_module.scanner import ProwlerScanner
       s = ProwlerScanner()
       n = s.ingest_file("path/to/scan.ocsf.json")

2. Run a fresh Prowler scan and ingest its output (requires AWS credentials):
       from prowler_module.scanner import ProwlerScanner
       s = ProwlerScanner()
       n = s.run_and_ingest(output_dir="./prowler-scans/output")

Either way the result is the same: FAIL findings end up in the SQLite DB so the
AI module can analyse them and the dashboard can show them.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import subprocess
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from ai_module.database import Database
from ai_module.models import Finding, FindingType, Severity

logger = logging.getLogger("prowler_scanner")

# Prowler severity strings -> our normalised Severity enum.
SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
    "info": Severity.INFO,
    "unknown": Severity.MEDIUM,
}


class ProwlerScanner:
    """Run Prowler and/or parse its OCSF output into the shared DB."""

    def __init__(self, db: Optional[Database] = None):
        self.db = db or Database()

    # ------------------------------------------------------------------ #
    # 1. Run a fresh scan (requires AWS credentials configured via env or
    #    `aws configure`). Skips this and use ingest_file() if you only have
    #    a pre-generated JSON file.
    # ------------------------------------------------------------------ #
    def run_and_ingest(
        self,
        output_dir: str | Path = "./prowler-scans/output",
        file_prefix: str = "scan",
        provider: str = "aws",
        extra_args: Optional[list[str]] = None,
        timeout_seconds: int = 1800,
        env: Optional[dict[str, str]] = None,
    ) -> int:
        """
        Invoke `prowler <provider>` and ingest the resulting OCSF file.
        Returns the number of FAIL findings ingested.
        """
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", file_prefix):
            raise ValueError("Prowler file prefix must contain only letters, numbers, '_' or '-'")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        # Isolate every execution to prevent ingestion of a stale previous scan.
        run_dir = output_dir / f"run-{uuid.uuid4().hex[:12]}"
        run_dir.mkdir(mode=0o700)

        cmd = [
            "prowler", provider,
            "-M", "json-ocsf",
            "-F", file_prefix,
            "-o", str(run_dir),
        ]
        if extra_args:
            cmd.extend(extra_args)

        logger.info("Running: %s", " ".join(cmd))
        # We do NOT check=True because Prowler exits non-zero whenever any check
        # FAILS — which is normal and expected output for us.
        completed = subprocess.run(
            cmd, check=False, timeout=timeout_seconds, capture_output=True, text=True, env=env,
        )
        ocsf_file = self._find_latest_ocsf(run_dir, file_prefix)
        if not ocsf_file:
            raise RuntimeError(
                f"Prowler produced no OCSF output (exit={completed.returncode}) "
                f"in run directory {run_dir}"
            )
        if completed.returncode != 0:
            logger.warning(
                "Prowler exited with code %d; fresh output found and will be ingested",
                completed.returncode,
            )
        logger.info("Ingesting Prowler output: %s", ocsf_file)
        return self.ingest_file(ocsf_file)

    @staticmethod
    def _find_latest_ocsf(output_dir: Path, prefix: str) -> Optional[Path]:
        # Prowler appends timestamp + ".ocsf.json"
        candidates = list(output_dir.glob(f"{prefix}*.ocsf.json"))
        return max(candidates, key=lambda p: p.stat().st_mtime_ns) if candidates else None

    # ------------------------------------------------------------------ #
    # 2. Parse a pre-existing OCSF file into Finding rows.
    # ------------------------------------------------------------------ #
    def ingest_file(self, path: str | Path) -> int:
        """Load a Prowler OCSF JSON file and write FAIL findings into the DB."""
        path = Path(path)
        events = self._load_ocsf(path)

        ingested = self.ingest_events(events)
        logger.info("Ingested %d FAIL findings from %s", ingested, path.name)
        return ingested

    def ingest_events(self, events: list[dict]) -> int:
        """Import already-parsed OCSF events, e.g. from an uploaded JSON file."""
        if not isinstance(events, list):
            raise ValueError("OCSF input must be a list of events")
        ingested = 0
        scan_observations = []
        for event in events:
            if not isinstance(event, dict):
                raise ValueError("Each OCSF event must be a JSON object")
            status_code = str(event.get("status_code", "")).upper()
            if status_code not in {"PASS", "FAIL", "FAILED"}:
                continue
            finding = self._to_finding(event)
            if finding is None:
                continue
            unmapped = event.get("unmapped") or {}
            scan_id = unmapped.get("scan_id") if isinstance(unmapped, dict) else None
            event_time = event.get("time_dt")
            if scan_id and event_time:
                scan_observations.append({
                    "scan_id": scan_id, "finding_id": finding.finding_id,
                    "status": "FAIL" if status_code in {"FAIL", "FAILED"} else "PASS",
                    "scanned_at": event_time,
                })
            if not self._is_fail(event):
                continue
            self.db.upsert_finding(finding)
            ingested += 1
        if scan_observations:
            from ai_module.remediation_tracker import RemediationTracker
            RemediationTracker(self.db.db_path).record_observations(scan_observations)
        return ingested

    # ------------------------------------------------------------------ #
    # OCSF parsing — tolerant of small structural differences across versions
    # ------------------------------------------------------------------ #
    @staticmethod
    def _load_ocsf(path: Path) -> list[dict]:
        """OCSF output is a JSON array of events. A few versions wrap it in a dict."""
        text = path.read_text(encoding="utf-8")
        data = json.loads(text)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in ("findings", "events", "results"):
                if isinstance(data.get(key), list):
                    return data[key]
        raise ValueError(f"Unexpected JSON structure in {path}")

    @staticmethod
    def _is_fail(event: dict) -> bool:
        """Only ingest FAIL findings — PASS/MUTED are noise for an analyst."""
        code = str(event.get("status_code", "")).upper()
        return code in {"FAIL", "FAILED"}

    @staticmethod
    def _safe_get(d: dict, *path, default=None):
        cur = d
        for key in path:
            if not isinstance(cur, dict):
                return default
            cur = cur.get(key)
            if cur is None:
                return default
        return cur

    def _to_finding(self, event: dict) -> Optional[Finding]:
        """Map one OCSF DetectionFinding event to our Finding model."""
        # ---- IDs & titles ---- #
        title = (
            self._safe_get(event, "finding_info", "title")
            or event.get("status_detail")
            or event.get("message")
            or "Prowler finding"
        )
        description = (
            event.get("status_detail")
            or self._safe_get(event, "finding_info", "desc")
            or event.get("message")
            or ""
        )
        risk = event.get("risk_details") or ""
        if risk and risk not in description:
            description = f"{description}\n\nRisk: {risk}".strip()

        # ---- check_id: prefer unmapped.check_id, fall back to derive from uid ---- #
        check_id = (
            self._safe_get(event, "unmapped", "check_id")
            or self._safe_get(event, "finding_info", "analytic", "uid")
            or self._derive_check_id(self._safe_get(event, "finding_info", "uid", default=""))
            or "unknown_check"
        )

        # ---- Resource ---- #
        resources = event.get("resources") or []
        if resources and isinstance(resources[0], dict):
            r0 = resources[0]
            resource = r0.get("uid") or r0.get("name") or ""
            region = r0.get("region", "")
        else:
            resource = event.get("resource_uid") or event.get("resource") or ""
            region = event.get("region", "")

        # ---- Account ---- #
        account_id = (
            self._safe_get(event, "cloud", "account", "uid")
            or event.get("cloud_account_uid")
            or ""
        )
        region = region or self._safe_get(event, "cloud", "region", default="")

        # ---- Severity ---- #
        sev_raw = str(event.get("severity") or "").lower()
        severity = SEVERITY_MAP.get(sev_raw, Severity.MEDIUM)

        # ---- Compliance refs (flatten unmapped.compliance) ---- #
        comp_map = self._safe_get(event, "unmapped", "compliance", default={}) or {}
        compliance: list[str] = []
        if isinstance(comp_map, dict):
            for framework, controls in comp_map.items():
                if isinstance(controls, list):
                    for c in controls:
                        compliance.append(f"{framework} {c}")
                elif controls:
                    compliance.append(f"{framework} {controls}")

        # ---- Remediation URL — useful, attach into raw_evidence ---- #
        remediation_desc = self._safe_get(event, "remediation", "desc", default="")
        remediation_refs = self._safe_get(event, "remediation", "references", default=[]) or []

        # ---- Stable finding_id (so re-running a scan updates, not duplicates) ---- #
        finding_uid = self._safe_get(event, "finding_info", "uid", default="")
        finding_id = (
            self._short_hash(finding_uid)
            if finding_uid
            else self._short_hash(f"{check_id}|{resource}|{account_id}")
        )

        # ---- Timestamp ---- #
        ts_raw = (
            event.get("time_dt")
            or self._safe_get(event, "finding_info", "created_time_dt")
            or datetime.utcnow().isoformat()
        )
        try:
            timestamp = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
            # Strip tz for SQLite-friendly storage (our DB stores naive iso).
            if timestamp.tzinfo is not None:
                timestamp = timestamp.replace(tzinfo=None)
        except (ValueError, TypeError):
            timestamp = datetime.utcnow()

        # ---- Raw evidence kept compact — too large kills the LLM prompt budget ---- #
        raw_evidence = {
            "check_id": check_id,
            "status_detail": event.get("status_detail", ""),
            "risk": risk,
            "remediation": remediation_desc,
            "remediation_refs": remediation_refs[:3],
            "resource_type": self._safe_get(event, "resources", 0, "type", default=""),
            "service": self._safe_get(event, "resources", 0, "group", "name", default=""),
        }

        return Finding(
            finding_id=finding_id,
            finding_type=FindingType.MISCONFIG,
            source="prowler",
            severity=severity,
            title=title,
            description=description,
            resource=resource,
            account_id=account_id,
            region=region,
            check_id=check_id,
            compliance=compliance,
            raw_evidence=raw_evidence,
            timestamp=timestamp,
        )

    @staticmethod
    def _derive_check_id(uid: str) -> str:
        """
        Prowler's finding_info.uid looks like:
        'prowler-aws-s3_bucket_public_access-123456789012-ap-southeast-1-bucket-name'
        The 3rd segment is the check_id. Fallback to empty if shape unexpected.
        """
        parts = uid.split("-")
        return parts[2] if len(parts) >= 3 else ""

    @staticmethod
    def _short_hash(s: str) -> str:
        return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]
