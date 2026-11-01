"""Explainable, deterministic triage and conservative ATT&CK evidence mapping.

Not an intrusion detector, model confidence, exploitability calculation, or
probability of compromise. Mappings require specific event evidence and may
still describe benign administrative behaviour.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from ai_module.models import Finding, FindingType, Incident, Severity


@dataclass(frozen=True)
class TechniqueMatch:
    technique_id: str
    name: str
    tactic: str
    evidence: str

    @property
    def url(self) -> str:
        return f"https://attack.mitre.org/techniques/{self.technique_id.replace('.', '/')}/"


@dataclass(frozen=True)
class RiskFactor:
    label: str
    points: int
    rationale: str


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    priority: Severity
    factors: tuple[RiskFactor, ...]


_BASE = {
    Severity.CRITICAL: 80,
    Severity.HIGH: 60,
    Severity.MEDIUM: 40,
    Severity.LOW: 20,
    Severity.INFO: 5,
}


def _integer(value: object) -> int:
    try:
        if isinstance(value, bool):
            return 0
        return max(0, int(value))
    except (ValueError, TypeError, OverflowError):
        return 0


def techniques_for_finding(f: Finding) -> tuple[TechniqueMatch, ...]:
    """Map only known, evidence-backed event types (never severity or title alone)."""
    if f.finding_type != FindingType.THREAT:
        return ()
    e = f.raw_evidence or {}
    mapped = []
    if f.source.lower() == "wazuh" and f.check_id == "5712" and _integer(e.get("failed_attempts")) >= 10:
        mapped.append(TechniqueMatch(
            "T1110", "Brute Force", "Credential Access",
            f"{_integer(e['failed_attempts'])} recorded failed authentication attempts (Wazuh 5712)",
        ))
    if f.source.lower() == "suricata" and f.check_id == "2010937" and _integer(e.get("ports_scanned")) >= 20:
        mapped.append(TechniqueMatch(
            "T1046", "Network Service Discovery", "Discovery",
            f"{_integer(e['ports_scanned'])} destination ports reported (Suricata 2010937)",
        ))
    if (f.source.lower() == "wazuh" and f.check_id == "80200"
            and e.get("api") == "GetObject" and _integer(e.get("count")) >= 100):
        mapped.append(TechniqueMatch(
            "T1530", "Data from Cloud Storage", "Collection",
            f"{_integer(e['count'])} GetObject API calls recorded (Wazuh 80200)",
        ))
    return tuple(mapped)


def techniques_for_incident(findings: Iterable[Finding]) -> tuple[TechniqueMatch, ...]:
    unique: dict[str, TechniqueMatch] = {}
    for finding in findings:
        for match in techniques_for_finding(finding):
            unique.setdefault(match.technique_id, match)
    return tuple(unique[k] for k in sorted(unique))


def _to_priority(score: int) -> Severity:
    if score >= 85:
        return Severity.CRITICAL
    if score >= 65:
        return Severity.HIGH
    if score >= 40:
        return Severity.MEDIUM
    if score >= 20:
        return Severity.LOW
    return Severity.INFO


def score_finding(f: Finding) -> RiskAssessment:
    factors = [RiskFactor(
        f"Reported severity: {f.severity.value}", _BASE[f.severity],
        "Base points from the normalized scanner/SIEM severity, not an AI prediction.",
    )]
    if f.finding_type == FindingType.THREAT:
        factors.append(RiskFactor(
            "Observed threat event", 6,
            "Threat telemetry takes triage precedence over configuration-only findings.",
        ))
    if techniques_for_finding(f):
        factors.append(RiskFactor(
            "Rule-matched behavioural evidence", 8,
            "An explicit supported detector and evidence threshold were both matched.",
        ))
    if f.finding_type == FindingType.MISCONFIG and (
        f.raw_evidence.get("public") is True
        or f.raw_evidence.get("public_access") is True
    ):
        factors.append(RiskFactor("Confirmed public exposure flag", 8,
                                  "Scanner evidence explicitly reports public exposure."))
    score = min(100, sum(p.points for p in factors))
    return RiskAssessment(score, _to_priority(score), tuple(factors))


def score_incident(inc: Incident, linked_findings: Iterable[Finding]) -> RiskAssessment:
    findings = list({f.finding_id: f for f in linked_findings}.values())
    if not findings:
        # If the evidence has been deleted, *never* use the incident headline to
        # invent a high-confidence risk. Show missing evidence explicitly.
        factors = (RiskFactor("No linked evidence available", 0,
                              "The original incident severity cannot be independently verified."),)
        return RiskAssessment(0, Severity.INFO, factors)

    base = max(findings, key=lambda f: _BASE[f.severity])
    factors = [RiskFactor(
        f"Highest source severity: {base.severity.value}", _BASE[base.severity],
        f"Based on finding ID {base.finding_id}.",
    )]
    additional = min(8, 4 * (len(findings) - 1))
    if additional:
        factors.append(RiskFactor("Additional linked observations", additional,
                                  f"{len(findings)} distinct linked finding IDs; capped at 8 points."))
    sources = {f.source.lower() for f in findings}
    if len(sources) >= 2:
        factors.append(RiskFactor("Independent telemetry sources", 7,
                                  f"Observed across {len(sources)} unique sources."))
    kinds = {f.finding_type for f in findings}
    if FindingType.MISCONFIG in kinds and FindingType.THREAT in kinds:
        factors.append(RiskFactor("Configuration plus threat telemetry", 5,
                                  "A potential exposure coexists with observed activity."))
    if techniques_for_incident(findings):
        factors.append(RiskFactor("Evidence-backed ATT&CK behaviour", 4,
                                  "At least one known behaviour matches an explicit rule."))
    score = min(100, sum(p.points for p in factors))
    return RiskAssessment(score, _to_priority(score), tuple(factors))
