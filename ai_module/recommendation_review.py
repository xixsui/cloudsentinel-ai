"""Conservative, rule-based review of AI remediation guidance.

This is a safety *screen*, not command validation. Alerts do not prove a defect;
an empty alert list does not establish correctness or safe execution.
"""
from __future__ import annotations

import re
from typing import Any, Mapping

from ai_module.models import Finding

REVIEW_VERSION = "recommendation-review-v1"


def _alert(code: str, title: str, explanation: str, check: str, level: str = "warning") -> dict[str, str]:
    return {"code": code, "level": level, "title": title,
            "explanation": explanation, "engineer_check": check}


def review_recommendation(finding: Finding, analysis: Mapping[str, Any]) -> dict[str, Any]:
    """Review bounded, schema-validated AI content without external calls.

    Only an allowlist of fields is examined. Untrusted model output is never run.
    """
    mitigation = [str(s) for s in analysis.get("mitigation_steps", []) if isinstance(s, str)]
    verification = [str(s) for s in analysis.get("verification_steps", []) if isinstance(s, str)]
    narrative = " ".join(str(analysis.get(k, "")) for k in
                         ("explanation", "attack_scenario", "risk_justification"))
    all_text = " ".join([narrative, *mitigation, *verification]).lower()
    fix_text = " ".join(mitigation).lower()
    alerts: list[dict[str, str]] = []

    sg_check = "security_group" in finding.check_id.lower() or (
        "ec2_instance_port" in finding.check_id.lower())
    if (sg_check and "authorize-security-group-ingress" in fix_text
            and not re.search(r"revoke-security-group-ingress|modify-security-group-rules|"
                              r"remove (?:the |any )?(?:old |existing |overly broad |public )?"
                              r"(?:ingress |security group )?rules?|"
                              r"revoke (?:the |any )?(?:old |existing |public |overly broad )?rule",
                              fix_text)):
        alerts.append(_alert(
            "SG_ADD_ONLY", "Adding a rule does not remove existing exposure",
            "The suggestion mentions authorizing ingress, but does not clearly address "
            "the existing overly permissive inbound rule.",
            "Inspect the existing rule ID; modify or revoke the broad rule after "
            "confirming legitimate access and rollback options.", "high"))

    if any(("cloudtrail" in s.lower() and re.search(
            r"rdp|ssh|3389|\b22\b", s.lower()) and re.search(
            r"connection|login|logon|authentication|failed|denied|traffic|session", s.lower()))
           for s in verification):
        alerts.append(_alert(
            "CLOUDTRAIL_AUTH_LOG", "CloudTrail is not an RDP/SSH authentication log",
            "CloudTrail primarily records AWS API and service activity, not host-level "
            "RDP/SSH login attempts or packet-level connectivity.",
            "Use appropriate host authentication logs and, if configured, VPC Flow Logs "
            "for network evidence; neither alone proves a successful login."))

    if re.search(r"(?:aws\s+s3\s+rb\s+\S+\s+--force|terraform\s+destroy|"
                 r"aws\s+\w+\s+delete-[\w-]+)", fix_text):
        alerts.append(_alert(
            "DESTRUCTIVE_OPERATION", "Potentially destructive remediation command",
            "The recommendation includes a deletion or destroy command.",
            "Check exact resource, dependencies, backups, change approval and rollback before proceeding.",
            "high"))

    if re.search(r"\b(?:confirmed breach|attack (?:has )?succeeded|was exploited|"
                 r"attacker (?:has|already) (?:accessed|stolen|compromised))\b", narrative.lower()) and not re.search(
                 r"(?:not |no |unconfirmed |cannot be )\s*(?:a )?confirmed breach", narrative.lower()):
        alerts.append(_alert(
            "UNSUPPORTED_COMPROMISE", "Claim of compromise needs behavioral evidence",
            "A configuration finding alone cannot confirm malicious activity or exploitation.",
            "Review relevant telemetry separately; label the attack path as a possibility until corroborated."))

    if sg_check:
        gaps = ["Verify whether this resource is actually internet-reachable "
                "(routing, public addressing, NACL and listening service)."]
    elif "s3" in finding.check_id.lower():
        gaps = ["Verify effective bucket/object permissions and intended public access "
                "before changing access controls."]
    elif "iam" in finding.check_id.lower():
        gaps = ["Validate effective permissions, policy inheritance and legitimate workload needs."]
    else:
        gaps = ["Validate the real-world impact and relevant dependencies for this resource."]
    gaps.append("Confirm the change in AWS and re-run the same Prowler check; "
                "the historical FAIL finding does not prove the current state.")
    return {
        "version": REVIEW_VERSION,
        "assessment": "manual_review_required" if alerts else "no_known_pattern_flagged",
        "alerts": alerts,
        "scan_evidence": [
            {"label": "Check ID", "value": finding.check_id[:160]},
            {"label": "Finding severity", "value": finding.severity.value},
            {"label": "Finding source", "value": finding.source[:80]},
        ],
        "unverified_conditions": gaps,
        "activity_evidence": "Not assessed by this static misconfiguration review; no attack is confirmed.",
        "disclaimer": "Pattern checks are incomplete and cannot certify command safety. "
                      "Engineer review and controlled change procedures are required.",
    }
