"""
Data models for the AI-Assisted Cloud Cybersecurity System.

These Pydantic models define the unified structure used across the whole
pipeline: Prowler (misconfig) findings, Wazuh/Suricata (threat) alerts, and
the AI-generated analysis attached to each finding.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class FindingType(str, Enum):
    """Where a finding originated."""
    MISCONFIG = "misconfig"      # from Prowler (CSPM)
    THREAT = "threat"            # from Wazuh / Suricata (SIEM / NIDS)
    CORRELATED = "correlated"    # an incident built from multiple findings


class Severity(str, Enum):
    """Normalised severity scale used everywhere in the system."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"


class Status(str, Enum):
    """Analyst workflow status for a finding."""
    NEW = "New"
    ANALYZED = "Analyzed"          # AI has produced an explanation
    INVESTIGATING = "Investigating"  # actively triaged incident
    RESOLVED = "Resolved"
    FALSE_POSITIVE = "False Positive"


class Finding(BaseModel):
    """
    A single normalised security finding.

    This is the common format that Prowler output, Wazuh alerts, and Suricata
    alerts all get converted into before they reach the AI module or the
    dashboard.
    """
    finding_id: str = Field(..., description="Unique ID (hash or source ID)")
    finding_type: FindingType
    source: str = Field(..., description="e.g. 'prowler', 'wazuh', 'suricata'")
    severity: Severity = Severity.MEDIUM
    title: str
    description: str
    resource: str = Field("", description="Affected resource (ARN, IP, bucket, etc.)")
    account_id: str = Field("", description="Cloud account / environment ID")
    region: str = ""
    check_id: str = Field("", description="e.g. CIS / Prowler check ID, Suricata SID")
    compliance: list[str] = Field(default_factory=list, description="Standards e.g. CIS, NIST")
    raw_evidence: dict = Field(default_factory=dict, description="Original raw event data")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    status: Status = Status.NEW


class AIAnalysis(BaseModel):
    """
    AI-generated decision-support output attached to a finding.

    This is what the LLM returns after analysing a Finding. It is the
    "explainable AI" layer the project promises: plain-English explanation,
    risk interpretation, prioritisation, and mitigation steps.
    """
    finding_id: str
    explanation: str = Field(..., description="Plain-English: why this matters")
    attack_scenario: str = Field("", description="What an attacker could do")
    risk_priority: Severity = Severity.MEDIUM
    risk_justification: str = ""
    mitigation_steps: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list, description="CIS/NIST/OWASP refs")
    model_used: str = ""
    duration_ms: int = Field(0, description="How long the AI call took (milliseconds)")
    input_tokens: int = 0
    output_tokens: int = 0
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


class Incident(BaseModel):
    """
    A correlated incident built from multiple related findings.

    Example: an over-permissive IAM user (misconfig) + a burst of S3 GetObject
    calls (CloudTrail/Wazuh) + outbound traffic to an unknown IP (VPC flow)
    grouped into one "possible data exfiltration" incident.
    """
    incident_id: str
    title: str
    severity: Severity = Severity.HIGH
    summary: str = ""
    finding_ids: list[str] = Field(default_factory=list)
    linked_entity: str = Field("", description="Common entity, e.g. IAM user / IP")
    ai_narrative: str = Field("", description="AI-built attack-chain story")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    status: Status = Status.NEW
    assignee: str = ""
    resolution_note: str = ""
    updated_at: Optional[datetime] = None
