"""
VPC Flow Logs collector.

Pulls AWS VPC Flow Logs from an S3 bucket, parses each flow record, applies
lightweight detection rules to spot suspicious patterns, and writes Findings
into the shared DB so the AI module and dashboard can use them.

Design notes:
- VPC Flow Logs are written to S3 every 1-5 minutes as gzipped plain-text
  files at:
    s3://<bucket>/AWSLogs/<account>/vpcflowlogs/<region>/<yyyy>/<mm>/<dd>/file.log.gz
- We keep a tiny "state" file recording the keys we've already processed so
  repeat runs don't re-ingest the same data.
- We deliberately do NOT turn every single flow record into a Finding (a busy
  VPC can produce millions per day). Instead we aggregate by source IP and
  detect three patterns we care about for the FYP:
    1. REJECT storm    — many blocked connections from one source = scan/recon
    2. Connection sweep — one source hitting many different destination ports
    3. Repeated SSH/RDP attempts — known service ports + multiple flows

Each pattern hit becomes one Finding (not one per flow), which keeps the
volume manageable and the LLM bill sane.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import logging
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from ai_module.database import Database
from ai_module.models import Finding, FindingType, Severity

logger = logging.getLogger("vpcflow_collector")

# Default VPC Flow Logs v2 fields in order.
DEFAULT_FIELDS = [
    "version", "account_id", "interface_id", "srcaddr", "dstaddr",
    "srcport", "dstport", "protocol", "packets", "bytes",
    "start", "end", "action", "log_status",
]

# Protocol numbers we care about (IANA).
PROTO_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP"}

# Well-known sensitive ports — used by the SSH/RDP brute-force rule.
SENSITIVE_PORTS = {
    22: "SSH", 23: "Telnet", 3389: "RDP",
    21: "FTP", 445: "SMB", 1433: "MSSQL",
    3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
    27017: "MongoDB", 9200: "Elasticsearch",
}


# ---------------------------------------------------------------------------
# Detection rule configuration
# ---------------------------------------------------------------------------
@dataclass
class RuleConfig:
    """Tunable thresholds. Override when calling pull_logs() if needed."""
    reject_storm_threshold: int = 20      # REJECTs from one src in the window
    port_sweep_threshold: int = 15        # distinct dst ports hit by one src
    sensitive_port_attempts: int = 5      # connections to SSH/RDP from one src


# ---------------------------------------------------------------------------
# Parsed flow record
# ---------------------------------------------------------------------------
@dataclass
class FlowRecord:
    version: str = ""
    account_id: str = ""
    interface_id: str = ""
    srcaddr: str = ""
    dstaddr: str = ""
    srcport: int = 0
    dstport: int = 0
    protocol: int = 0
    packets: int = 0
    bytes: int = 0
    start: int = 0
    end: int = 0
    action: str = ""          # "ACCEPT" / "REJECT"
    log_status: str = ""      # "OK" / "NODATA" / "SKIPDATA"

    @classmethod
    def from_parts(cls, parts: list[str]) -> Optional["FlowRecord"]:
        """Parse a single flow log line (already split by whitespace)."""
        if len(parts) < len(DEFAULT_FIELDS):
            return None  # malformed
        try:
            return cls(
                version=parts[0],
                account_id=parts[1],
                interface_id=parts[2],
                srcaddr=parts[3],
                dstaddr=parts[4],
                srcport=int(parts[5]) if parts[5] != "-" else 0,
                dstport=int(parts[6]) if parts[6] != "-" else 0,
                protocol=int(parts[7]) if parts[7] != "-" else 0,
                packets=int(parts[8]) if parts[8] != "-" else 0,
                bytes=int(parts[9]) if parts[9] != "-" else 0,
                start=int(parts[10]) if parts[10] != "-" else 0,
                end=int(parts[11]) if parts[11] != "-" else 0,
                action=parts[12],
                log_status=parts[13],
            )
        except (ValueError, IndexError):
            return None


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------
class VPCFlowCollector:
    """Pull VPC Flow Logs from S3, detect patterns, write Findings."""

    def __init__(
        self,
        bucket: str,
        region: str = "ap-southeast-1",
        state_path: Optional[Path] = None,
        db: Optional[Database] = None,
        rules: Optional[RuleConfig] = None,
    ):
        self.bucket = bucket
        self.region = region
        self.db = db or Database()
        self.rules = rules or RuleConfig()
        self.state_path = state_path or (
            Path.home() / ".fyp-ai-cloud-sec" / "vpcflow_state.json"
        )
        self.s3 = boto3.client("s3", region_name=region)

    # ------------------------------------------------------------------ #
    # State (which S3 keys we already processed)
    # ------------------------------------------------------------------ #
    def _load_state(self) -> dict:
        if not self.state_path.exists():
            return {"processed_keys": [], "last_run": None}
        try:
            return json.loads(self.state_path.read_text())
        except (OSError, json.JSONDecodeError):
            return {"processed_keys": [], "last_run": None}

    def _save_state(self, state: dict) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(json.dumps(state, indent=2))

    # ------------------------------------------------------------------ #
    # Public entry point
    # ------------------------------------------------------------------ #
    def pull_logs(
        self,
        prefix: Optional[str] = None,
        max_files: int = 50,
        reset_state: bool = False,
    ) -> int:
        """
        Download new flow log files from S3, parse them, detect patterns,
        and write findings.

        Returns: number of findings produced (not number of flow records).
        """
        state = {"processed_keys": [], "last_run": None} if reset_state else self._load_state()
        already_done = set(state.get("processed_keys", []))

        keys = self._list_new_keys(prefix, already_done, max_files)
        if not keys:
            logger.info("No new flow log files to process.")
            return 0

        # Collect ALL records across the new files, then run detection once
        # over the merged set — patterns often span multiple 1-min files.
        all_records: list[FlowRecord] = []
        for key in keys:
            try:
                lines = self._download_and_decompress(key)
                for line in lines:
                    rec = FlowRecord.from_parts(line.split())
                    if rec is not None and rec.log_status == "OK":
                        all_records.append(rec)
            except (BotoCoreError, ClientError, OSError) as e:
                logger.warning("Failed to read %s: %s", key, e)
                continue

        logger.info("Loaded %d flow records from %d files", len(all_records), len(keys))

        findings = self._detect_patterns(all_records)
        for f in findings:
            self.db.upsert_finding(f)

        # Mark these keys as done so we don't reprocess them next time.
        already_done.update(keys)
        # Keep state file small — cap history at last 500 keys.
        state["processed_keys"] = sorted(already_done)[-500:]
        state["last_run"] = datetime.now(timezone.utc).isoformat()
        self._save_state(state)

        logger.info("Wrote %d findings from VPC Flow Logs", len(findings))
        return len(findings)

    # ------------------------------------------------------------------ #
    # S3 helpers
    # ------------------------------------------------------------------ #
    def _list_new_keys(self, prefix: Optional[str], already_done: set[str],
                       max_files: int) -> list[str]:
        """List unprocessed .log.gz keys, sorted by upload time (oldest first)."""
        paginator = self.s3.get_paginator("list_objects_v2")
        params = {"Bucket": self.bucket}
        if prefix:
            params["Prefix"] = prefix

        objects = []
        for page in paginator.paginate(**params):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if not key.endswith(".log.gz"):
                    continue
                if key in already_done:
                    continue
                objects.append((obj["LastModified"], key))

        objects.sort()
        keys = [k for _, k in objects[:max_files]]
        logger.info("Found %d new flow log file(s) to process", len(keys))
        return keys

    def _download_and_decompress(self, key: str) -> Iterable[str]:
        """Pull one .log.gz, gunzip, return lines (skipping header)."""
        resp = self.s3.get_object(Bucket=self.bucket, Key=key)
        body = resp["Body"].read()
        with gzip.GzipFile(fileobj=io.BytesIO(body)) as gz:
            text = gz.read().decode("utf-8", errors="replace")
        lines = text.strip().splitlines()
        # First line is a header listing field names — skip it.
        if lines and lines[0].startswith("version"):
            lines = lines[1:]
        return lines

    # ------------------------------------------------------------------ #
    # Detection rules
    # ------------------------------------------------------------------ #
    def _detect_patterns(self, records: list[FlowRecord]) -> list[Finding]:
        """Aggregate by source IP and apply rules. Returns a list of Findings."""
        if not records:
            return []

        # Group by source IP
        by_src: dict[str, list[FlowRecord]] = defaultdict(list)
        for r in records:
            by_src[r.srcaddr].append(r)

        findings: list[Finding] = []
        account = records[0].account_id  # all in same account
        for src_ip, flows in by_src.items():
            if not src_ip or src_ip == "-":
                continue

            # Rule 1 — REJECT storm
            rejects = [f for f in flows if f.action == "REJECT"]
            if len(rejects) >= self.rules.reject_storm_threshold:
                findings.append(self._make_finding(
                    rule="reject_storm",
                    severity=Severity.HIGH,
                    title=f"Reject storm from {src_ip}",
                    description=(
                        f"{src_ip} generated {len(rejects)} REJECTed connections "
                        f"in this window, consistent with reconnaissance / port scanning."
                    ),
                    src_ip=src_ip, account=account, flows=rejects,
                    compliance=["MITRE T1046", "MITRE Tactic: Reconnaissance"],
                ))

            # Rule 2 — connection sweep (one src, many destination ports)
            distinct_ports = {f.dstport for f in flows if f.dstport > 0}
            if len(distinct_ports) >= self.rules.port_sweep_threshold:
                findings.append(self._make_finding(
                    rule="port_sweep",
                    severity=Severity.HIGH,
                    title=f"Port sweep from {src_ip}",
                    description=(
                        f"{src_ip} attempted connections to {len(distinct_ports)} distinct "
                        f"destination ports. Likely host fingerprinting / service discovery."
                    ),
                    src_ip=src_ip, account=account, flows=flows,
                    compliance=["MITRE T1046"],
                ))

            # Rule 3 — repeated attempts on sensitive service ports
            sensitive_flows = [f for f in flows if f.dstport in SENSITIVE_PORTS]
            if len(sensitive_flows) >= self.rules.sensitive_port_attempts:
                # Group by which sensitive port for a clearer title.
                port_counts: dict[int, int] = defaultdict(int)
                for f in sensitive_flows:
                    port_counts[f.dstport] += 1
                top_port, top_count = max(port_counts.items(), key=lambda x: x[1])
                svc = SENSITIVE_PORTS[top_port]
                findings.append(self._make_finding(
                    rule="sensitive_service_attempts",
                    severity=Severity.CRITICAL if top_count >= 20 else Severity.HIGH,
                    title=f"Repeated {svc} (:{top_port}) attempts from {src_ip}",
                    description=(
                        f"{src_ip} made {top_count} connection attempts to {svc} "
                        f"(port {top_port}). Possible brute-force or credential-stuffing."
                    ),
                    src_ip=src_ip, account=account, flows=sensitive_flows,
                    compliance=["MITRE T1110", "MITRE Tactic: Credential Access"],
                ))

        return findings

    # ------------------------------------------------------------------ #
    # Finding construction
    # ------------------------------------------------------------------ #
    def _make_finding(
        self, rule: str, severity: Severity, title: str, description: str,
        src_ip: str, account: str, flows: list[FlowRecord],
        compliance: Optional[list[str]] = None,
    ) -> Finding:
        # Stable ID per src_ip + rule + day, so re-runs in the same day update
        # the existing row instead of creating duplicates.
        day = datetime.utcnow().strftime("%Y%m%d")
        finding_id = hashlib.sha256(
            f"vpcflow|{rule}|{src_ip}|{day}".encode()
        ).hexdigest()[:16]

        unique_dst = sorted({f.dstaddr for f in flows if f.dstaddr})
        # Keep evidence compact — first 5 unique destinations + counts only.
        raw_evidence = {
            "rule": rule,
            "source_ip": src_ip,
            "flow_count": len(flows),
            "unique_destinations": unique_dst[:5],
            "destinations_total": len(unique_dst),
            "unique_dst_ports": sorted({f.dstport for f in flows if f.dstport > 0})[:10],
            "protocols": sorted({PROTO_NAMES.get(f.protocol, str(f.protocol)) for f in flows}),
            "total_bytes": sum(f.bytes for f in flows),
            "total_packets": sum(f.packets for f in flows),
        }

        # The "resource" field should describe what was attacked. If all flows
        # share one destination, name it; else show "multiple targets in <vpc>".
        if len(unique_dst) == 1:
            resource = f"{unique_dst[0]} (from {src_ip})"
        else:
            resource = f"multiple targets in account {account} (from {src_ip})"

        return Finding(
            finding_id=finding_id,
            finding_type=FindingType.THREAT,
            source="vpc-flow-logs",
            severity=severity,
            title=title,
            description=description,
            resource=resource,
            account_id=account,
            region=self.region,
            check_id=f"vpcflow.{rule}",
            compliance=compliance or [],
            raw_evidence=raw_evidence,
            timestamp=datetime.utcnow(),
        )
