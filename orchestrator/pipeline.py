"""
Pipeline orchestrator.

Runs the whole data-flow as one command:

    Prowler scan       (CSPM misconfigurations)
        ↓
    Wazuh alerts pull  (CloudTrail-via-Wazuh threats)
        ↓
    VPC Flow Logs pull (network-level threats)
        ↓
    AI analysis        (decision-support per finding)
        ↓
    Correlation        (cross-source attack chains)

Each step is optional (e.g. skip Wazuh if it's not running), and each
reports progress via a callback so the Streamlit UI can show a progress bar.

The same orchestrator powers both the "Run full pipeline" button on the
dashboard AND the background scheduler.
"""

from __future__ import annotations

import logging
import os
import time
import traceback
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from ai_module.analyzer import AIAnalyzer
from ai_module.database import Database

logger = logging.getLogger("orchestrator")


# ---------------------------------------------------------------------------
# Step results (one per source) — so the UI can show what happened
# ---------------------------------------------------------------------------
@dataclass
class StepResult:
    name: str
    ok: bool = False
    findings_added: int = 0
    duration_s: float = 0.0
    message: str = ""           # one-line summary shown in UI
    error: Optional[str] = None # if ok=False


@dataclass
class PipelineResult:
    started_at: datetime = field(default_factory=datetime.utcnow)
    finished_at: Optional[datetime] = None
    steps: list[StepResult] = field(default_factory=list)
    total_findings: int = 0
    total_incidents: int = 0

    @property
    def total_duration_s(self) -> float:
        if not self.finished_at:
            return 0.0
        return (self.finished_at - self.started_at).total_seconds()


# ---------------------------------------------------------------------------
# Configuration — Settings UI fills this in
# ---------------------------------------------------------------------------
@dataclass
class PipelineConfig:
    """Everything the pipeline needs to know to run. Set unused sources to None."""

    # ---- Prowler ----
    prowler_enabled: bool = True
    prowler_output_dir: str = "./prowler-scans/output"
    prowler_prefix: str = "scan"
    # If set, ingest this existing file instead of running prowler.
    # Useful when prowler is too slow for the user to wait synchronously.
    prowler_ingest_file: Optional[str] = None

    # ---- Wazuh ----
    wazuh_enabled: bool = True
    wazuh_host: str = "https://localhost:9200"
    wazuh_username: str = "admin"
    wazuh_password: str = field(default="", repr=False)
    wazuh_ca_bundle: str = ""
    wazuh_since: str = "1h"
    wazuh_min_level: int = 3
    wazuh_aws_only: bool = False

    # ---- VPC Flow Logs ----
    vpcflow_enabled: bool = True
    vpcflow_bucket: str = ""           # required if enabled
    vpcflow_region: str = "ap-southeast-1"
    vpcflow_max_files: int = 50
    vpcflow_reject_threshold: int = 5  # lab-friendly defaults
    vpcflow_sweep_threshold: int = 5
    vpcflow_sensitive_threshold: int = 3
    vpcflow_reset_state: bool = False

    # ---- AI ----
    ai_enabled: bool = True
    correlate_enabled: bool = True
    # Only auto-analyse findings at or above this severity. Default is "High"
    # so pipelines stay fast and cheap; lower-severity findings can still be
    # analysed on-demand via the dashboard buttons.
    ai_min_severity: str = "High"   # "None" | "Critical" | "High" | "Medium" | "Low" | "" (all)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------
ProgressCallback = Callable[[str, float, str], None]
"""Signature: (step_name, fraction_0_to_1, message)"""


class Orchestrator:
    """Drives the full pipeline. Reports progress via a callback."""

    NUM_STEPS = 5  # prowler, wazuh, vpcflow, ai, correlate

    def __init__(self, db: Optional[Database] = None,
                 on_progress: Optional[ProgressCallback] = None):
        self.db = db or Database()
        self.on_progress = on_progress or (lambda *args, **kwargs: None)

    def _progress(self, step_idx: int, name: str, msg: str) -> None:
        """Report fractional progress (step_idx / NUM_STEPS)."""
        fraction = step_idx / self.NUM_STEPS
        try:
            self.on_progress(name, fraction, msg)
        except Exception:  # noqa: BLE001
            logger.exception("Progress callback raised")

    # ------------------------------------------------------------------ #
    # Main entry
    # ------------------------------------------------------------------ #
    def run(self, cfg: PipelineConfig) -> PipelineResult:
        if os.getenv("CLOUDSENTINEL_DEMO", "").lower() in {"1", "true", "yes"}:
            # Treat the demo flag as a safety boundary, not just a UI badge.
            # Never make AWS/Wazuh/LLM network calls while it is active.
            cfg = replace(
                cfg, prowler_enabled=False, wazuh_enabled=False,
                vpcflow_enabled=False, ai_enabled=False, correlate_enabled=False,
            )
        result = PipelineResult()
        # Snapshot finding count so we can measure what *this* run added.
        starting_count = self.db.stats().get("total", 0)

        # ---- Step 1: Prowler ---- #
        self._progress(0, "prowler", "Starting Prowler scan...")
        result.steps.append(self._run_prowler(cfg) if cfg.prowler_enabled
                            else StepResult(name="prowler", ok=True, message="Skipped"))

        # ---- Step 2: Wazuh ---- #
        self._progress(1, "wazuh", "Pulling Wazuh alerts...")
        result.steps.append(self._run_wazuh(cfg) if cfg.wazuh_enabled
                            else StepResult(name="wazuh", ok=True, message="Skipped"))

        # ---- Step 3: VPC Flow Logs ---- #
        self._progress(2, "vpcflow", "Pulling VPC Flow Logs from S3...")
        result.steps.append(self._run_vpcflow(cfg) if cfg.vpcflow_enabled
                            else StepResult(name="vpcflow", ok=True, message="Skipped"))

        # ---- Step 4: AI analysis ---- #
        self._progress(3, "ai", "Running AI analysis on new findings...")
        result.steps.append(self._run_ai(cfg) if cfg.ai_enabled
                            else StepResult(name="ai", ok=True, message="Skipped"))

        # ---- Step 5: Correlation ---- #
        self._progress(4, "correlate", "Correlating findings into incidents...")
        result.steps.append(self._run_correlate(cfg) if cfg.correlate_enabled
                            else StepResult(name="correlate", ok=True, message="Skipped"))

        self._progress(self.NUM_STEPS, "done", "Pipeline finished")

        result.finished_at = datetime.utcnow()
        ending_count = self.db.stats().get("total", 0)
        result.total_findings = ending_count - starting_count
        result.total_incidents = self.db.stats().get("incidents", 0)
        return result

    # ------------------------------------------------------------------ #
    # Individual steps. Each catches its own errors so one failure doesn't
    # abort the rest — partial results are still useful.
    # ------------------------------------------------------------------ #
    def _run_prowler(self, cfg: PipelineConfig) -> StepResult:
        step = StepResult(name="prowler")
        t0 = time.time()
        try:
            from prowler_module.scanner import ProwlerScanner
            scanner = ProwlerScanner(db=self.db)

            if cfg.prowler_ingest_file:
                file = Path(cfg.prowler_ingest_file)
                if "*" in str(file):
                    # Glob support
                    matches = sorted(Path(file.parent).glob(file.name))
                    if not matches:
                        raise FileNotFoundError(f"No file matched {file}")
                    file = matches[-1]
                step.findings_added = scanner.ingest_file(file)
                step.message = f"Ingested {step.findings_added} findings from {file.name}"
            else:
                step.findings_added = scanner.run_and_ingest(
                    output_dir=cfg.prowler_output_dir,
                    file_prefix=cfg.prowler_prefix,
                )
                step.message = f"Scan complete: {step.findings_added} findings ingested"

            step.ok = True
        except Exception as e:  # noqa: BLE001
            step.error = f"{type(e).__name__}: {e}"
            step.message = "Prowler step failed (see Details)"
            logger.exception("Prowler step failed")
        step.duration_s = time.time() - t0
        return step

    def _run_wazuh(self, cfg: PipelineConfig) -> StepResult:
        step = StepResult(name="wazuh")
        t0 = time.time()
        try:
            from siem_module.wazuh_client import WazuhClient
            client = WazuhClient(
                host=cfg.wazuh_host,
                username=cfg.wazuh_username,
                password=cfg.wazuh_password,
                verify_ssl=cfg.wazuh_ca_bundle or True,
                db=self.db,
            )
            sources = ["aws"] if cfg.wazuh_aws_only else None
            step.findings_added = client.pull_alerts(
                since=cfg.wazuh_since,
                min_rule_level=cfg.wazuh_min_level,
                sources=sources,
            )
            step.ok = True
            step.message = f"Pulled {step.findings_added} alerts (last {cfg.wazuh_since})"
        except Exception as e:  # noqa: BLE001
            step.error = f"{type(e).__name__}: {e}"
            step.message = "Wazuh pull failed (is the indexer reachable?)"
            logger.exception("Wazuh step failed")
        step.duration_s = time.time() - t0
        return step

    def _run_vpcflow(self, cfg: PipelineConfig) -> StepResult:
        step = StepResult(name="vpcflow")
        t0 = time.time()
        try:
            if not cfg.vpcflow_bucket:
                raise ValueError("VPC Flow bucket name is empty in settings")
            from siem_module.vpcflow_collector import VPCFlowCollector, RuleConfig
            collector = VPCFlowCollector(
                bucket=cfg.vpcflow_bucket,
                region=cfg.vpcflow_region,
                db=self.db,
                rules=RuleConfig(
                    reject_storm_threshold=cfg.vpcflow_reject_threshold,
                    port_sweep_threshold=cfg.vpcflow_sweep_threshold,
                    sensitive_port_attempts=cfg.vpcflow_sensitive_threshold,
                ),
            )
            step.findings_added = collector.pull_logs(
                max_files=cfg.vpcflow_max_files,
                reset_state=cfg.vpcflow_reset_state,
            )
            step.ok = True
            step.message = f"Wrote {step.findings_added} findings from flow logs"
        except Exception as e:  # noqa: BLE001
            step.error = f"{type(e).__name__}: {e}"
            step.message = "VPC Flow step failed (AWS credentials/bucket OK?)"
            logger.exception("VPC Flow step failed")
        step.duration_s = time.time() - t0
        return step

    def _run_ai(self, cfg: PipelineConfig) -> StepResult:
        step = StepResult(name="ai")
        t0 = time.time()
        try:
            # "None" means skip auto-analysis entirely — user will analyse
            # individual findings manually from the dashboard.
            if cfg.ai_min_severity == "None":
                step.ok = True
                step.message = "Skipped (set to manual-only in Settings)"
                step.duration_s = time.time() - t0
                return step

            from ai_module.models import Severity
            analyzer = AIAnalyzer(self.db)
            # Resolve the min_severity setting into an enum (or None = all).
            min_sev = None
            if cfg.ai_min_severity:
                try:
                    min_sev = Severity(cfg.ai_min_severity)
                except ValueError:
                    min_sev = None
            step.findings_added = analyzer.analyze_all_pending(min_severity=min_sev)
            step.ok = True
            label = (
                f"≥{min_sev.value} severity" if min_sev else "all severities"
            )
            step.message = (
                f"Analysed {step.findings_added} new finding(s) "
                f"({label}) using {analyzer.provider.info.display_name}"
            )
        except Exception as e:  # noqa: BLE001
            step.error = f"{type(e).__name__}: {e}"
            step.message = "AI analysis failed (check API key in Settings)"
            logger.exception("AI step failed")
        step.duration_s = time.time() - t0
        return step

    def _run_correlate(self, cfg: PipelineConfig) -> StepResult:
        step = StepResult(name="correlate")
        t0 = time.time()
        try:
            analyzer = AIAnalyzer(self.db)
            incidents = analyzer.correlate()
            step.findings_added = len(incidents)
            step.ok = True
            step.message = f"Built {len(incidents)} correlated incident(s)"
        except Exception as e:  # noqa: BLE001
            step.error = f"{type(e).__name__}: {e}"
            step.message = "Correlation failed"
            logger.exception("Correlation step failed")
        step.duration_s = time.time() - t0
        return step


# ---------------------------------------------------------------------------
# Convenience builder — reads user_settings to construct a PipelineConfig.
# Means the dashboard doesn't have to assemble it manually.
# ---------------------------------------------------------------------------
def build_config_from_user_settings() -> PipelineConfig:
    from config import user_settings
    s = user_settings.load()
    p = s.get("pipeline", {}) or {}
    return PipelineConfig(
        prowler_enabled=p.get("prowler_enabled", True),
        prowler_output_dir=p.get("prowler_output_dir", "./prowler-scans/output"),
        prowler_prefix=p.get("prowler_prefix", "scan"),
        prowler_ingest_file=p.get("prowler_ingest_file") or None,

        wazuh_enabled=p.get("wazuh_enabled", True),
        wazuh_host=p.get("wazuh_host", "https://localhost:9200"),
        wazuh_username=p.get("wazuh_username", "admin"),
        wazuh_password=user_settings.get_wazuh_password(),
        wazuh_ca_bundle=p.get("wazuh_ca_bundle") or os.getenv("WAZUH_CA_BUNDLE", ""),
        wazuh_since=p.get("wazuh_since", "1h"),
        wazuh_min_level=int(p.get("wazuh_min_level", 3)),
        wazuh_aws_only=p.get("wazuh_aws_only", False),

        vpcflow_enabled=p.get("vpcflow_enabled", True),
        vpcflow_bucket=p.get("vpcflow_bucket", ""),
        vpcflow_region=p.get("vpcflow_region", "ap-southeast-1"),
        vpcflow_max_files=int(p.get("vpcflow_max_files", 50)),
        vpcflow_reject_threshold=int(p.get("vpcflow_reject_threshold", 5)),
        vpcflow_sweep_threshold=int(p.get("vpcflow_sweep_threshold", 5)),
        vpcflow_sensitive_threshold=int(p.get("vpcflow_sensitive_threshold", 3)),

        ai_enabled=p.get("ai_enabled", True),
        correlate_enabled=p.get("correlate_enabled", True),
        ai_min_severity=p.get("ai_min_severity", "High"),
    )
