"""Deterministic, conservative candidate selection before LLM investigation.

A common AWS account is not evidence of a related incident. The correlator
requires an explicit common resource, at least two different ingestion sources,
a threat indicator, and a bounded event-time window. These are *candidates*,
not confirmed compromises; the LLM is only a decision-support analyst.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from ai_module.models import Finding, FindingType, Status

PLACEHOLDERS = frozenset({"", "unknown", "n/a", "none", "aws", "-", "null"})


@dataclass(frozen=True)
class CorrelationCandidate:
    linked_entity: str
    findings: tuple[Finding, ...]


def _utc_naive(value: datetime) -> datetime:
    """Normalize timestamps for comparisons without local-time assumptions."""
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def build_candidates(
    findings: list[Finding],
    window: timedelta = timedelta(hours=24),
    max_findings: int = 20,
    max_candidates: int = 25,
) -> list[CorrelationCandidate]:
    if window <= timedelta(0) or max_findings < 2 or max_candidates < 1:
        raise ValueError("Invalid candidate window or limits")

    buckets: dict[tuple[str, str, str], list[Finding]] = defaultdict(list)
    for f in findings:
        resource = f.resource.strip()
        if resource.lower() in PLACEHOLDERS:
            continue
        if f.status in (Status.RESOLVED, Status.FALSE_POSITIVE):
            continue
        # Do not correlate two accounts merely because they use the same name.
        key = (f.account_id.strip(), f.region.strip(), resource)
        buckets[key].append(f)

    candidates = []
    for (account, region, resource), items in sorted(buckets.items()):
        ordered = sorted(items, key=lambda f: (_utc_naive(f.timestamp), f.finding_id))
        windows: list[list[Finding]] = []
        current: list[Finding] = []
        for f in ordered:
            if current and (
                _utc_naive(f.timestamp) - _utc_naive(current[0].timestamp) > window
                or len(current) >= max_findings
            ):
                windows.append(current)
                current = []
            current.append(f)
        if current:
            windows.append(current)

        for group in windows:
            if len({f.finding_id for f in group}) < 2:
                continue
            if len({f.source for f in group}) < 2:
                continue
            if not any(f.finding_type == FindingType.THREAT for f in group):
                continue
            entity = " | ".join(x for x in (account, region, resource) if x)
            candidates.append(CorrelationCandidate(entity, tuple(group)))

    # Prefer the latest candidate groups under a hard LLM cost limit.
    candidates.sort(key=lambda c: max(_utc_naive(f.timestamp) for f in c.findings), reverse=True)
    return candidates[:max_candidates]
