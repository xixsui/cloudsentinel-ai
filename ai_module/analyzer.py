"""
AI analysis module — the "decision-support / explainable AI" layer.

This is the refactored version that uses the provider abstraction. The analyzer
itself no longer knows about specific LLM SDKs — it asks `providers.get_provider()`
for whatever backend the user has selected in Settings, and calls `.complete()`.

Switching provider = one click in the dashboard. Adding a new provider = one
file in `providers/`. The analyzer doesn't change.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Optional

from ai_module.correlation import build_candidates
from ai_module.database import Database
from ai_module.models import (
    AIAnalysis,
    Finding,
    FindingType,
    Incident,
    Severity,
    Status,
)
from ai_module.providers.base import BaseProvider, get_provider
from config import user_settings

logger = logging.getLogger("ai_module")

PROMPT_DIR = Path(__file__).resolve().parent / "prompts"


def _load_prompt(name: str) -> str:
    return (PROMPT_DIR / name).read_text(encoding="utf-8")


def _extract_json(text: str) -> dict:
    """Strip ```json fences if present, then grab the first {...} block."""
    cleaned = text.strip()
    cleaned = re.sub(r"^```(?:json)?", "", cleaned).strip()
    cleaned = re.sub(r"```$", "", cleaned).strip()
    if not cleaned.startswith("{"):
        m = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if m:
            cleaned = m.group(0)
    return json.loads(cleaned)


def _to_severity(value: str) -> Severity:
    try:
        return Severity(value.strip().capitalize())
    except (ValueError, AttributeError):
        return Severity.MEDIUM


class AIAnalyzer:
    """
    Analyses Findings using whichever LLM provider is currently active in
    settings (or one explicitly passed in).
    """

    def __init__(self, db: Database, provider: Optional[BaseProvider] = None):
        self.db = db
        if provider is not None:
            self.provider = provider
        else:
            self.provider = self._build_active_provider()

    # ------------------------------------------------------------------ #
    # Provider plumbing
    # ------------------------------------------------------------------ #
    @staticmethod
    def _build_active_provider() -> BaseProvider:
        s = user_settings.load()
        pid = s.get("active_provider", "gemini")
        model = s.get("active_model") or s.get("preferred_models", {}).get(pid)
        api_key = user_settings.get_api_key(pid)
        rate = float(s.get("rate_limit_seconds", 1.0))
        return get_provider(pid, api_key=api_key, model=model, rate_limit_seconds=rate)

    def reload_provider(self) -> None:
        """Re-read settings (useful if the user just changed provider in the UI)."""
        self.provider = self._build_active_provider()

    # ------------------------------------------------------------------ #
    # Cache helpers (same as before)
    # ------------------------------------------------------------------ #
    @staticmethod
    def _cache_key(prompt: str, model: str) -> str:
        return hashlib.sha256(f"{model}:{prompt}".encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------ #
    # Single-finding analysis
    # ------------------------------------------------------------------ #
    def analyze_finding(self, finding: Finding, use_cache: bool = True) -> AIAnalysis:
        import time as _time

        template = (
            _load_prompt("misconfig_prompt.txt")
            if finding.finding_type == FindingType.MISCONFIG
            else _load_prompt("threat_prompt.txt")
        )
        prompt = template.format(
            title=finding.title,
            source=finding.source,
            resource=finding.resource or "N/A",
            account_id=finding.account_id or "N/A",
            region=finding.region or "N/A",
            check_id=finding.check_id or "N/A",
            compliance=", ".join(finding.compliance) or "N/A",
            description=finding.description,
            raw_evidence=json.dumps(finding.raw_evidence)[:1500],
        )

        cache_key = self._cache_key(prompt, self.provider.model)
        raw: Optional[str] = self.db.get_cached(cache_key) if use_cache else None

        # Track per-call timing and token usage so the dashboard can show
        # how much AI compute each finding cost.
        duration_ms = 0
        input_tokens = 0
        output_tokens = 0

        if raw is None:
            t0 = _time.perf_counter()
            result = self.provider.complete(prompt)
            duration_ms = int((_time.perf_counter() - t0) * 1000)

            if result.error:
                logger.error("Provider error on %s: %s", finding.finding_id, result.error)
                analysis = AIAnalysis(
                    finding_id=finding.finding_id,
                    explanation=f"(AI provider error: {result.error})",
                    risk_priority=finding.severity,
                    risk_justification="Provider call failed; original severity retained.",
                    model_used=self.provider.model,
                    duration_ms=duration_ms,
                )
                self.db.save_analysis(analysis)
                return analysis

            raw = result.text
            input_tokens = result.input_tokens
            output_tokens = result.output_tokens
            self.db.set_cached(cache_key, raw)
            user_settings.record_usage(
                self.provider.info.id, result.input_tokens, result.output_tokens
            )
            logger.info(
                "LLM call for finding %s (in=%d out=%d, %d ms)",
                finding.finding_id, result.input_tokens, result.output_tokens,
                duration_ms,
            )
        else:
            logger.info("Cache hit for finding %s", finding.finding_id)

        try:
            data = _extract_json(raw)
        except json.JSONDecodeError:
            logger.error("Failed to parse LLM JSON for %s; raw=%s", finding.finding_id, raw[:300])
            data = {}

        analysis = AIAnalysis(
            finding_id=finding.finding_id,
            explanation=data.get("explanation", "(no explanation produced)"),
            attack_scenario=data.get("attack_scenario", ""),
            risk_priority=_to_severity(data.get("risk_priority", finding.severity.value)),
            risk_justification=data.get("risk_justification", ""),
            mitigation_steps=data.get("mitigation_steps", []),
            references=data.get("references", []),
            model_used=self.provider.model,
            duration_ms=duration_ms,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )
        self.db.save_analysis(analysis)
        return analysis

    def analyze_all_pending(
        self, min_severity: Optional[Severity] = None,
    ) -> int:
        """
        Analyse every finding that has no AI analysis yet.

        When `min_severity` is set (e.g. Severity.HIGH), only findings at or
        above that severity get auto-analysed — used by the orchestrator's
        "high-priority only" mode so we don't burn LLM quota on Low/Info noise.
        Lower-priority findings can still be analysed on-demand by calling
        `analyze_finding()` directly (the dashboard's "Analyze with AI" button).
        """
        pending = self.db.get_unanalyzed_findings(min_severity=min_severity)
        for f in pending:
            self.analyze_finding(f)
        logger.info(
            "Analysed %d pending findings (min_severity=%s)",
            len(pending), min_severity.value if min_severity else "all",
        )
        return len(pending)

    # ------------------------------------------------------------------ #
    # Correlation
    # ------------------------------------------------------------------ #
    def correlate(self) -> list[Incident]:
        """Ask the LLM to assess *evidence-linked* candidate groups only.

        Correlation does not establish that an attack occurred. Analyst review
        is necessary. This method will never send account-only groups or
        unrelated single-source findings to the provider.
        """
        candidates = build_candidates(self.db.get_findings())
        incidents: list[Incident] = []
        template = _load_prompt("correlation_prompt.txt")

        for candidate in candidates:
            group = candidate.findings
            entity = candidate.linked_entity
            findings_block = "\n".join(
                f"- [{f.timestamp.isoformat()}] "
                f"({f.finding_type.value}/{f.severity.value}, source={f.source[:60]}) "
                f"{f.title[:200]} on {f.resource[:250]}"
                for f in group
            )
            prompt = template.format(
                linked_entity=entity[:350], findings_block=findings_block[:9000],
            )
            cache_key = self._cache_key(prompt, self.provider.model)
            raw = self.db.get_cached(cache_key)
            if raw is None:
                result = self.provider.complete(prompt)
                if result.error:
                    logger.error("Correlation provider error: %s", result.error)
                    continue
                raw = result.text
                self.db.set_cached(cache_key, raw)
                user_settings.record_usage(
                    self.provider.info.id, result.input_tokens, result.output_tokens,
                )
            try:
                data = _extract_json(raw)
            except (json.JSONDecodeError, TypeError):
                logger.warning("Invalid LLM JSON returned for correlation candidate")
                continue
            if not isinstance(data, dict) or data.get("is_incident") is not True:
                continue

            # Hash evidence IDs as well as the entity: a later, independent
            # incident on the same resource won't overwrite this incident.
            joined_ids = "|".join(sorted(f.finding_id for f in group))
            incident_id = hashlib.sha256(f"{entity}|{joined_ids}".encode()).hexdigest()[:16]
            inc = Incident(
                incident_id=incident_id,
                title=str(data.get("title") or f"Potential incident on {entity}")[:250],
                severity=_to_severity(data.get("severity", "High")),
                summary=str(data.get("summary") or "")[:3000],
                finding_ids=[f.finding_id for f in group],
                linked_entity=entity,
                ai_narrative=str(data.get("summary") or "")[:3000],
            )
            self.db.save_incident(inc)
            incidents.append(inc)

        logger.info("Correlation produced %d candidate incidents", len(incidents))
        return incidents
