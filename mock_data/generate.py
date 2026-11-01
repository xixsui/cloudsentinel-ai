"""
Mock data generator.

Produces realistic-looking findings so you can build & test the AI module and
the dashboard BEFORE you have AWS access or real Prowler/Wazuh output.

These mock findings mirror the exact test scenarios from your IR report
(public S3, SSH open to world, over-permissive IAM, brute-force SSH, port scan,
unauthorised API calls), so the demo data is consistent with your documentation.

Run:  python -m mock_data.generate
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta

from ai_module.database import Database
from ai_module.correlation import build_candidates
from ai_module.models import Finding, FindingType, Severity, Incident


def _fid(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def build_mock_findings() -> list[Finding]:
    now = datetime.utcnow()
    acct = "123456789012"
    region = "ap-southeast-1"

    findings: list[Finding] = [
        # ----- Misconfigurations (Prowler-style) ----- #
        Finding(
            finding_id=_fid("misconfig", "s3-public"),
            finding_type=FindingType.MISCONFIG,
            source="prowler",
            severity=Severity.CRITICAL,
            title="S3 bucket allows public read access",
            description="Bucket 'fyp-misconfig-bucket' has a policy and ACL permitting "
                        "public 's3:GetObject', exposing all objects to the internet.",
            resource="arn:aws:s3:::fyp-misconfig-bucket",
            account_id=acct, region=region,
            check_id="s3_bucket_public_access",
            compliance=["CIS AWS 2.1.5", "NIST CSF PR.AC-4"],
            raw_evidence={"PublicAccessBlock": "disabled", "ACL": "public-read"},
            timestamp=now - timedelta(minutes=50),
        ),
        Finding(
            finding_id=_fid("misconfig", "sg-ssh-open"),
            finding_type=FindingType.MISCONFIG,
            source="prowler",
            severity=Severity.HIGH,
            title="Security group allows SSH (22) from 0.0.0.0/0",
            description="Security group 'sg-0ab12' permits inbound TCP 22 from any source, "
                        "exposing SSH to the entire internet.",
            resource="sg-0ab12 / i-0fyp34ec2",
            account_id=acct, region=region,
            check_id="ec2_securitygroup_allow_ingress_from_internet_to_port_22",
            compliance=["CIS AWS 5.2", "NIST CSF PR.AC-5"],
            raw_evidence={"port": 22, "cidr": "0.0.0.0/0", "protocol": "tcp"},
            timestamp=now - timedelta(minutes=48),
        ),
        Finding(
            finding_id=_fid("misconfig", "iam-overpriv"),
            finding_type=FindingType.MISCONFIG,
            source="prowler",
            severity=Severity.HIGH,
            title="IAM user has AdministratorAccess policy attached",
            description="IAM user 'fyp-user-overpriv' is attached directly to the "
                        "AWS-managed AdministratorAccess policy, violating least privilege.",
            resource="arn:aws:iam::123456789012:user/fyp-user-overpriv",
            account_id=acct, region=region,
            check_id="iam_policy_attached_only_to_group_or_roles",
            compliance=["CIS AWS 1.16", "NIST CSF PR.AC-4"],
            raw_evidence={"policy": "AdministratorAccess", "attachment": "direct"},
            timestamp=now - timedelta(minutes=45),
        ),
        Finding(
            finding_id=_fid("misconfig", "ebs-unencrypted"),
            finding_type=FindingType.MISCONFIG,
            source="prowler",
            severity=Severity.MEDIUM,
            title="EBS volume is not encrypted at rest",
            description="Volume 'vol-0fyp99' is not encrypted, so data at rest is unprotected "
                        "if the underlying storage is compromised.",
            resource="vol-0fyp99",
            account_id=acct, region=region,
            check_id="ec2_ebs_volume_encryption",
            compliance=["CIS AWS 2.2.1", "NIST CSF PR.DS-1"],
            raw_evidence={"encrypted": False},
            timestamp=now - timedelta(minutes=40),
        ),
        Finding(
            finding_id=_fid("misconfig", "cloudtrail-no-validation"),
            finding_type=FindingType.MISCONFIG,
            source="prowler",
            severity=Severity.LOW,
            title="CloudTrail log file validation is disabled",
            description="Trail 'fyp-cloudtrail' has log file validation turned off, so log "
                        "tampering cannot be reliably detected.",
            resource="fyp-cloudtrail",
            account_id=acct, region=region,
            check_id="cloudtrail_log_file_validation_enabled",
            compliance=["CIS AWS 3.2", "NIST CSF PR.DS-6"],
            raw_evidence={"LogFileValidationEnabled": False},
            timestamp=now - timedelta(minutes=38),
        ),

        # ----- Threats (Wazuh / Suricata-style) ----- #
        Finding(
            finding_id=_fid("threat", "ssh-bruteforce"),
            finding_type=FindingType.THREAT,
            source="wazuh",
            severity=Severity.HIGH,
            title="Multiple failed SSH login attempts (possible brute-force)",
            description="Host i-0fyp34ec2 recorded 240 failed SSH authentications from "
                        "203.0.113.45 within 3 minutes, consistent with brute-force.",
            resource="i-0fyp34ec2 (203.0.113.45)",
            account_id=acct, region=region,
            check_id="5712",
            compliance=["MITRE ATT&CK T1110"],
            raw_evidence={"failed_attempts": 240, "src_ip": "203.0.113.45", "window": "3m"},
            timestamp=now - timedelta(minutes=30),
        ),
        Finding(
            finding_id=_fid("threat", "port-scan"),
            finding_type=FindingType.THREAT,
            source="suricata",
            severity=Severity.MEDIUM,
            title="Network port scan detected",
            description="Suricata detected sequential connection attempts across many ports "
                        "on i-0fyp34ec2 from 203.0.113.45, indicating reconnaissance.",
            resource="i-0fyp34ec2 (203.0.113.45)",
            account_id=acct, region=region,
            check_id="2010937",
            compliance=["MITRE ATT&CK T1046"],
            raw_evidence={"ports_scanned": 1024, "src_ip": "203.0.113.45"},
            timestamp=now - timedelta(minutes=33),
        ),
        Finding(
            finding_id=_fid("threat", "s3-mass-get"),
            finding_type=FindingType.THREAT,
            source="wazuh",
            severity=Severity.HIGH,
            title="Unusual high-volume S3 object access",
            description="CloudTrail shows IAM user 'fyp-user-overpriv' issued 1,500 GetObject "
                        "calls on 'fyp-misconfig-bucket' in 5 minutes — far above its baseline.",
            resource="arn:aws:s3:::fyp-misconfig-bucket",
            account_id=acct, region=region,
            check_id="80200",
            compliance=["MITRE ATT&CK T1530"],
            raw_evidence={"api": "GetObject", "count": 1500, "actor": "fyp-user-overpriv"},
            timestamp=now - timedelta(minutes=20),
        ),
        Finding(
            finding_id=_fid("threat", "unauthorized-api"),
            finding_type=FindingType.THREAT,
            source="wazuh",
            severity=Severity.MEDIUM,
            title="Repeated AccessDenied API calls",
            description="IAM user 'fyp-user-leastpriv' generated 60 AccessDenied responses "
                        "attempting iam:CreateUser and iam:AttachUserPolicy.",
            resource="arn:aws:iam::123456789012:user/fyp-user-leastpriv",
            account_id=acct, region=region,
            check_id="80201",
            compliance=["MITRE ATT&CK T1078"],
            raw_evidence={"denied_count": 60, "actions": ["iam:CreateUser", "iam:AttachUserPolicy"]},
            timestamp=now - timedelta(minutes=15),
        ),
    ]
    for finding in findings:
        finding.raw_evidence["synthetic_demo"] = True
    return findings


def seed_demo_incidents(db: Database, findings: list[Finding]) -> int:
    """Seed synthetic *potential* incidents; no LLM/confirmed compromise asserted."""
    count = 0
    for candidate in build_candidates(findings):
        group = candidate.findings
        ids = sorted(f.finding_id for f in group)
        entity = candidate.linked_entity
        ident = hashlib.sha256(f"{entity}|{'|'.join(ids)}".encode()).hexdigest()[:16]
        sources = {f.source for f in group}
        if "suricata" in sources:
            title = "Possible reconnaissance followed by SSH authentication attempts"
            summary = ("Synthetic scenario: port-scanning and failed SSH authentication "
                       "observations share an asset and time window. This is not proof "
                       "of unauthorized access.")
        else:
            title = "Potential S3 exposure and high-volume access"
            summary = ("Synthetic scenario: public-access posture and elevated S3 "
                       "GetObject activity are associated with one bucket. "
                       "Human investigation is required.")
        db.save_incident(Incident(
            incident_id=ident, title=title,
            severity=max((f.severity for f in group),
                         key=lambda sev: {Severity.INFO: 0, Severity.LOW: 1,
                                          Severity.MEDIUM: 2, Severity.HIGH: 3,
                                          Severity.CRITICAL: 4}[sev]),
            summary=summary, finding_ids=ids, linked_entity=entity,
            ai_narrative="", timestamp=max(f.timestamp for f in group),
        ))
        count += 1
    return count


def seed(db: Database | None = None) -> int:
    db = db or Database()
    findings = build_mock_findings()
    for f in findings:
        db.upsert_finding(f)
    incidents = seed_demo_incidents(db, findings)
    print(f"Seeded {len(findings)} mock findings and {incidents} demo incident(s) into {db.db_path}")
    return len(findings)


if __name__ == "__main__":
    seed()
