"""Threat Alerts page — Wazuh / VPC Flow Logs / other SIEM sources."""

from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ai_module.models import FindingType  # noqa: E402
from config import user_settings  # noqa: E402
from dashboard.common import get_db  # noqa: E402
from dashboard.findings_browser import render_findings_browser  # noqa: E402
from dashboard.theme import apply_theme, page_title, render_sidebar  # noqa: E402

st.set_page_config(page_title="Threat Alerts", page_icon=None,
                   layout="wide", initial_sidebar_state="expanded")
apply_theme()

db = get_db()
settings = user_settings.load()


def _source_health() -> dict:
    sources_in_db = db.distinct_values("source") or []
    return {
        "Prowler":  "ok" if "prowler" in sources_in_db else "warning",
        "Wazuh":    "ok" if any(s.startswith("wazuh") or s == "aws" for s in sources_in_db) else "warning",
        "VPC Flow": "ok" if "vpc-flow-logs" in sources_in_db else "warning",
    }


render_sidebar(source_status=_source_health(),
               provider_label=settings.get("active_provider", "gemini").capitalize())

page_title(
    "Threat Alerts",
    subtitle="Runtime threat detections from Wazuh (CloudTrail) and VPC Flow Logs.",
    icon="ti-alert-triangle",
)

render_findings_browser(
    db=db,
    finding_type=FindingType.THREAT,
    label_singular="alert",
    key_prefix="th",
)
