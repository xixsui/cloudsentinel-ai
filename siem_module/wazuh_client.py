"""
Wazuh integration — pulls alerts from the Wazuh indexer and turns them into
normalised Finding rows the AI module and dashboard already understand.

Why query the indexer directly (not the Wazuh manager API)?
- The indexer holds the FULL processed alert (rule + decoded fields + raw event).
- The Wazuh manager REST API exposes config/cluster ops, not the alert stream.
- The indexer speaks OpenSearch DSL, which is well-documented and Pythonic.

How:
    from siem_module.wazuh_client import WazuhClient
    c = WazuhClient(
        host="https://localhost:9200",
        username="admin",
        password=os.environ["WAZUH_INDEXER_PASSWORD"],
    )
    n = c.pull_alerts(since="1h")   # ingest last hour of alerts -> DB
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

import requests
from requests.auth import HTTPBasicAuth

from ai_module.database import Database
from ai_module.models import Finding, FindingType, Severity

logger = logging.getLogger("wazuh_client")


def _wazuh_level_to_severity(level: int) -> Severity:
    """
    Wazuh rule.level is 0–15. Translate into our 5-bucket severity scale.
    See: https://documentation.wazuh.com/current/user-manual/ruleset/rules/rules-classification.html
    """
    if level >= 12:
        return Severity.CRITICAL     # 12-15: severe attack, root access
    if level >= 9:
        return Severity.HIGH         # 9-11:  errors of critical importance
    if level >= 6:
        return Severity.MEDIUM       # 6-8:   normal errors / warnings
    if level >= 3:
        return Severity.LOW          # 3-5:   informational / minor
    return Severity.INFO             # 0-2:   noise


class WazuhClient:
    """Pulls alerts from the Wazuh indexer (OpenSearch) into the shared DB."""

    def __init__(
        self,
        host: str = "https://localhost:9200",
        username: str = "admin",
        password: str = "",
        index_pattern: str = "wazuh-alerts-*",
        verify_ssl: bool | str = True,
        db: Optional[Database] = None,
    ):
        if not host.startswith("https://"):
            raise ValueError("Wazuh indexer host must use HTTPS")
        self.host = host.rstrip("/")
        self.auth = HTTPBasicAuth(username, password)
        self.index_pattern = index_pattern
        self.verify_ssl = verify_ssl
        self.db = db or Database()

    # ------------------------------------------------------------------ #
    # Connectivity check
    # ------------------------------------------------------------------ #
    def test(self) -> tuple[bool, str]:
        """Quick health check used by the dashboard's Settings page."""
        try:
            r = requests.get(
                f"{self.host}/_cluster/health",
                auth=self.auth, verify=self.verify_ssl, timeout=10,
            )
            r.raise_for_status()
            data = r.json()
            return True, f"OK — cluster status: {data.get('status', 'unknown')}"
        except Exception as e:  # noqa: BLE001
            return False, f"{type(e).__name__}: {e}"

    # ------------------------------------------------------------------ #
    # Main entry point — pull and ingest
    # ------------------------------------------------------------------ #
    def pull_alerts(
        self,
        since: str = "1h",
        min_rule_level: int = 6,
        max_results: int = 500,
        sources: Optional[list[str]] = None,
    ) -> int:
        """
        Fetch alerts from the indexer and write them as Findings.

        Args:
            since: time window relative to now ("15m", "1h", "24h", "7d", ...)
                   passed straight to OpenSearch (e.g. "now-1h").
            min_rule_level: skip rule levels below this (default 6 = medium and up).
                            Wazuh generates a LOT of low-level alerts (SCA, status...)
                            that aren't worth analysing with an LLM.
            max_results: cap response size to avoid blowing up the LLM budget.
            sources: optional filter on `data.aws.source`, e.g. ["aws"]. If None,
                     all alert sources are pulled.

        Returns: number of findings ingested.
        """
        query = self._build_query(since, min_rule_level, sources, max_results)
        url = f"{self.host}/{self.index_pattern}/_search"

        logger.info("Querying Wazuh indexer: since=%s min_level=%d", since, min_rule_level)
        try:
            r = requests.post(
                url, json=query, auth=self.auth,
                verify=self.verify_ssl, timeout=30,
            )
            r.raise_for_status()
        except requests.RequestException as e:
            logger.error("Wazuh query failed: %s", e)
            raise

        hits = r.json().get("hits", {}).get("hits", [])
        logger.info("Got %d hits from Wazuh", len(hits))

        ingested = 0
        for hit in hits:
            try:
                finding = self._hit_to_finding(hit)
            except Exception as e:  # noqa: BLE001
                logger.warning("Skipping malformed hit %s: %s", hit.get("_id"), e)
                continue
            if finding is None:
                continue
            self.db.upsert_finding(finding)
            ingested += 1

        logger.info("Ingested %d findings into DB", ingested)
        return ingested

    # ------------------------------------------------------------------ #
    # OpenSearch query construction
    # ------------------------------------------------------------------ #
    @staticmethod
    def _build_query(
        since: str, min_rule_level: int,
        sources: Optional[list[str]], max_results: int,
    ) -> dict:
        filters: list[dict] = [
            {"range": {"@timestamp": {"gte": f"now-{since}"}}},
            {"range": {"rule.level": {"gte": min_rule_level}}},
        ]
        if sources:
            # Match alerts where the integration source matches (e.g. AWS).
            filters.append({"terms": {"data.integration": sources}})

        return {
            "size": max_results,
            "query": {"bool": {"filter": filters}},
            "sort": [{"@timestamp": "desc"}],
        }

    # ------------------------------------------------------------------ #
    # Convert one indexer hit into a Finding
    # ------------------------------------------------------------------ #
    def _hit_to_finding(self, hit: dict) -> Optional[Finding]:
        src = hit.get("_source", {})
        rule = src.get("rule", {}) or {}
        data = src.get("data", {}) or {}

        # ---- Identity ---- #
        # Use Wazuh's internal alert id as the basis so re-pulls upsert, not duplicate.
        wazuh_id = src.get("id") or hit.get("_id") or ""
        finding_id = hashlib.sha256(f"wazuh|{wazuh_id}".encode()).hexdigest()[:16]

        # ---- Severity from rule.level ---- #
        level = int(rule.get("level", 0))
        severity = _wazuh_level_to_severity(level)

        # ---- Title & description ---- #
        title = rule.get("description", "Wazuh alert")
        rule_id = str(rule.get("id", ""))

        # ---- Detect source (aws / suricata / linux ...) for the `source` field ---- #
        # Priority: explicit integration > data.aws presence > rule group > generic.
        integration = data.get("integration", "")
        if integration:
            source = integration
        elif "aws" in data:
            source = "wazuh-aws"
        elif rule.get("groups"):
            source = f"wazuh-{rule['groups'][0]}"
        else:
            source = "wazuh"

        # ---- Resource: try hardest to extract something useful ---- #
        # CloudTrail-style alerts have data.aws.* with rich context.
        aws = data.get("aws", {}) or {}
        if aws:
            resource = self._extract_aws_resource(aws)
            account_id = aws.get("recipientAccountId", "") or aws.get("userIdentity", {}).get("accountId", "")
            region = aws.get("awsRegion", "")
        else:
            # Suricata / generic alerts
            resource = (
                data.get("srcip", "")
                or src.get("agent", {}).get("name", "")
                or ""
            )
            account_id = ""
            region = ""

        # ---- Description: build a coherent short paragraph ---- #
        description_parts = [rule.get("description", "")]
        if aws.get("eventName"):
            description_parts.append(f"AWS API call: {aws['eventName']}")
        if aws.get("userIdentity", {}).get("arn"):
            description_parts.append(f"Actor: {aws['userIdentity']['arn']}")
        if aws.get("sourceIPAddress"):
            description_parts.append(f"Source IP: {aws['sourceIPAddress']}")
        if aws.get("errorCode"):
            description_parts.append(f"Error: {aws['errorCode']}")
        description = " | ".join(p for p in description_parts if p)

        # ---- Compliance / MITRE mapping if present ---- #
        compliance: list[str] = []
        mitre = rule.get("mitre", {}) or {}
        for tactic in mitre.get("tactic", []) or []:
            compliance.append(f"MITRE Tactic: {tactic}")
        for technique in mitre.get("technique", []) or []:
            compliance.append(f"MITRE Technique: {technique}")
        for tid in mitre.get("id", []) or []:
            compliance.append(f"MITRE {tid}")
        # Other compliance frameworks (CIS, PCI, etc.) Wazuh tags on the rule
        for fw in ("pci_dss", "gdpr", "hipaa", "nist_800_53", "tsc"):
            for ref in rule.get(fw, []) or []:
                compliance.append(f"{fw.upper()} {ref}")

        # ---- Timestamp ---- #
        ts_raw = src.get("@timestamp") or src.get("timestamp")
        try:
            timestamp = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
            if timestamp.tzinfo is not None:
                timestamp = timestamp.astimezone(timezone.utc).replace(tzinfo=None)
        except (ValueError, TypeError):
            timestamp = datetime.utcnow()

        # ---- Raw evidence — keep it small to protect LLM budget ---- #
        raw_evidence = {
            "rule_id": rule_id,
            "rule_level": level,
            "rule_groups": rule.get("groups", []),
            "agent": src.get("agent", {}).get("name", ""),
        }
        if aws:
            # Keep just the high-signal subset of the CloudTrail event.
            raw_evidence["aws"] = {
                "eventName": aws.get("eventName"),
                "eventSource": aws.get("eventSource"),
                "sourceIPAddress": aws.get("sourceIPAddress"),
                "userIdentity": aws.get("userIdentity"),
                "errorCode": aws.get("errorCode"),
                "errorMessage": aws.get("errorMessage"),
                "requestParameters": str(aws.get("requestParameters", ""))[:300],
            }

        return Finding(
            finding_id=finding_id,
            finding_type=FindingType.THREAT,
            source=source,
            severity=severity,
            title=title,
            description=description or "(no description)",
            resource=resource,
            account_id=account_id,
            region=region,
            check_id=rule_id,
            compliance=compliance,
            raw_evidence=raw_evidence,
            timestamp=timestamp,
        )

    @staticmethod
    def _extract_aws_resource(aws: dict) -> str:
        """Pick the most identifying field from a CloudTrail event."""
        # Order of preference: ARN of the actor, then any resource ARN in the
        # event, then bucket name, then a fallback combo.
        ui = aws.get("userIdentity", {}) or {}
        if ui.get("arn"):
            return ui["arn"]

        resources = aws.get("resources") or []
        if resources and isinstance(resources[0], dict):
            arn = resources[0].get("ARN") or resources[0].get("arn")
            if arn:
                return arn

        # Some S3 events store bucket name in requestParameters.
        rp = aws.get("requestParameters", {}) or {}
        if isinstance(rp, dict) and rp.get("bucketName"):
            return f"s3://{rp['bucketName']}"

        return aws.get("eventSource", "") or "aws"
