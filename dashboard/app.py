"""
CloudSentinel AI — Home / Overview page.

Professional SOC-style dashboard. No emoji; uses Tabler outline icons.
Sidebar holds nav + system status; the main canvas shows posture + inventory.
"""

from __future__ import annotations

import sys
import os
from html import escape
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import user_settings  # noqa: E402
from dashboard.aws_inventory import AWSInventory  # noqa: E402
from dashboard.overview_charts import severity_chart, type_chart, sources_chart  # noqa: E402
from dashboard.common import get_db  # noqa: E402
from ai_module.models import FindingType, Severity  # noqa: E402
from ai_module.remediation_tracker import RemediationTracker  # noqa: E402
from dashboard.theme import (  # noqa: E402
    apply_theme,
    icon,
    page_title,
    render_sidebar,
    severity_chip,
    status_pill,
    time_range_selector,
)

st.set_page_config(
    page_title="Home — CloudSentinel AI",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded",
)
apply_theme()

db = get_db()
stats = db.stats()
misconfig_findings = db.get_findings(finding_type=FindingType.MISCONFIG)
remediation_cases = RemediationTracker(db.db_path).list_cases()
settings = user_settings.load()
DEMO_MODE = os.getenv("CLOUDSENTINEL_DEMO", "").lower() in {"1", "true", "yes"}
if DEMO_MODE:
    st.info("DEMO MODE — using synthetic findings. Live AWS inventory and source pulls are not active.")
elif db.has_synthetic_findings():
    st.warning("**Sample data detected:** this workspace includes synthetic demo findings. Do not treat the full risk summary as a live AWS assessment. Before auditing a real account, move the local database to a separate demo backup and restart the app.")

# ----- Compute system status for the sidebar ----- #
def _source_health() -> dict:
    health: dict[str, str] = {}
    sources_in_db = db.distinct_values("source") or []
    def _match(candidates):
        return any(c in sources_in_db for c in candidates)
    def _match_prefix(prefixes):
        return any(any(s.startswith(p) for s in sources_in_db) for p in prefixes)

    health["Prowler"]  = "ok" if _match(["prowler"]) else "warning"
    # Wazuh emits many sub-sources (wazuh-aws, wazuh-ossec, wazuh-sca, ...) so
    # match anything that starts with "wazuh" or is exactly "aws".
    # SIEM/flow telemetry is optional in the CSPM workflow.
    if _match_prefix(["wazuh"]) or _match(["aws"]):
        health["Wazuh (optional)"] = "ok"
    if _match(["vpc-flow-logs"]):
        health["VPC Flow (optional)"] = "ok"
    return health


provider_label = settings.get("active_provider", "gemini").capitalize()

# Last-sync derived from the background scheduler, if running
last_sync_label = None
try:
    from orchestrator.scheduler import BackgroundScheduler
    @st.cache_resource
    def _get_sched() -> BackgroundScheduler:
        return BackgroundScheduler()
    sched = _get_sched()
    sstat = sched.status()
    if sstat.get("last_run_at"):
        ago = datetime.utcnow() - sstat["last_run_at"]
        if ago < timedelta(minutes=2):
            last_sync_label = "just now"
        elif ago < timedelta(hours=1):
            last_sync_label = f"{int(ago.total_seconds() // 60)}m ago"
        else:
            last_sync_label = f"{int(ago.total_seconds() // 3600)}h ago"
except Exception:
    sstat = {}


render_sidebar(
    source_status=_source_health(),
    last_sync=last_sync_label,
    provider_label=provider_label,
)

# ===========================================================================
# Page header
# ===========================================================================
# Right-aligned time-range
header_cols = st.columns([5, 2])
with header_cols[0]:
    page_title(
        "Overview",
        subtitle="AWS cloud posture, prioritized misconfigurations and engineer-controlled remediation.",
        icon="ti-dashboard",
    )
with header_cols[1]:
    st.markdown('<div style="padding-top:1.25rem;"></div>', unsafe_allow_html=True)
    time_window = time_range_selector()

# Dashboard home: orient new users before they configure any cloud integration.
connection_label = "SIMULATED DATA" if DEMO_MODE else (
    "AWS CONNECTED" if st.session_state.get("aws_identity") else "LOCAL WORKSPACE")
st.markdown(
    '<div class="cs-hero">'
    f'<span class="cs-hero-chip">{connection_label}</span>'
    '<div class="cs-hero-title" style="margin-top:12px">Cloud security at a glance</div>'
    '<div class="cs-hero-sub">Explore posture findings, correlate security signals, '
    'and guide engineers through review, manual remediation and rescan verification. Start offline or connect a read-only AWS identity.</div>'
    '</div>', unsafe_allow_html=True)
nav_a, nav_b, nav_c = st.columns(3)
with nav_a:
    st.page_link("pages/4_Cloud_Connections.py", label="Connect AWS", icon="🔐", use_container_width=True)
with nav_b:
    st.page_link("pages/5_Scan_Center.py", label="Open Scan Center", icon="🛡️", use_container_width=True)
with nav_c:
    st.page_link("pages/1_Misconfigurations.py", label="Review & Remediate", icon="🔎", use_container_width=True)
st.page_link("pages/7_Remediation_Tracker.py", label="Open Remediation Tracker →", icon="📝")

# ===========================================================================
# Risk score + KPIs
# ===========================================================================
by_sev = {sev.value: sum(f.severity == sev for f in misconfig_findings) for sev in Severity}
penalty = (
    by_sev.get("Critical", 0) * 10
    + by_sev.get("High", 0) * 5
    + by_sev.get("Medium", 0) * 2
    + by_sev.get("Low", 0) * 0.5
)
risk_score = max(0, min(100, int(100 - penalty)))

if risk_score >= 80:
    score_color, score_state = "#34D399", "Healthy"
elif risk_score >= 60:
    score_color, score_state = "#FBBF24", "At Risk"
elif risk_score >= 30:
    score_color, score_state = "#FB923C", "Degraded"
else:
    score_color, score_state = "#FB7185", "Critical"

score_col, metric_cols = st.columns([1.3, 4])
with score_col:
    with st.container(border=True):
        st.markdown(
            f'<div class="soc-score">'
            f'<div class="soc-score-num" style="color:{score_color}">{risk_score}</div>'
            f'<div class="soc-score-label">Indicative posture</div>'
            f'<div style="margin-top:6px;font-size:0.78rem;font-weight:500;'
            f'color:{score_color}">{score_state}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

with metric_cols:
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Misconfigurations", len(misconfig_findings))
    m2.metric("Critical", by_sev.get("Critical", 0))
    m3.metric("High", by_sev.get("High", 0))
    m4.metric("AI Analysed", sum(db.get_analysis(f.finding_id) is not None for f in misconfig_findings))
    m5.metric("Tracked fixes", len(remediation_cases))

st.caption("Indicative posture is based on imported misconfiguration severity counts; not a measured compromise probability, scan coverage percentage, or industry risk score. Historic data may be stale.")

# ===========================================================================
# Security summary charts
# Native Streamlit containers replace the former HTML open/close wrappers:
# Streamlit widgets were siblings of HTML <div> tags, not their children.
# ===========================================================================
chart_cols = st.columns([1.05, 1, 1.15], gap="medium")

with chart_cols[0]:
    with st.container(border=True):
        st.markdown('**Severity Breakdown**')
        st.caption('Findings by reported severity')
        if any(by_sev.values()):
            st.plotly_chart(severity_chart(by_sev), use_container_width=True, theme=None,
                            config={"displayModeBar": False}, key="overview_severity_plot")
        else:
            st.info("No severity data yet. Run a demo scan to get started.")

with chart_cols[1]:
    with st.container(border=True):
        st.markdown('**Finding Type**')
        st.caption('Cloud configuration findings')
        by_type = {"misconfig": len(misconfig_findings)}
        if any(by_type.values()):
            st.plotly_chart(type_chart(by_type), use_container_width=True, theme=None,
                            config={"displayModeBar": False}, key="overview_type_plot")
        else:
            st.info("No finding types yet.")

with chart_cols[2]:
    with st.container(border=True):
        st.markdown('**Findings by Source**')
        st.caption('Most active detection sources')
        source_counts = {}
        for f in misconfig_findings:
            source_counts[f.source] = source_counts.get(f.source, 0) + 1
        if any(source_counts.values()):
            figure, remaining = sources_chart(source_counts)
            st.plotly_chart(figure, use_container_width=True, theme=None,
                            config={"displayModeBar": False}, key="overview_sources_plot")
            if remaining:
                st.caption(f"Showing the top 6 sources · {remaining} more available in Findings")
        else:
            st.info("No sources yet.")

# ===========================================================================
# AWS Inventory + Top Risks
# ===========================================================================
inv_cols = st.columns([1.5, 1])

with inv_cols[0]:
    verified_connection = st.session_state.get("aws_connection") if not DEMO_MODE else None
    verified_identity = st.session_state.get("aws_identity") if not DEMO_MODE else None
    region = verified_connection.region if verified_connection else settings.get("pipeline", {}).get("vpcflow_region", "ap-southeast-1")

    h_cols = st.columns([3, 1])
    with h_cols[0]:
        st.markdown(
            f'<h3 style="margin:0.7rem 0 0.2rem;">'
            f'{icon("ti-cloud", size="1.1em")} &nbsp;AWS Inventory</h3>'
            f'<p style="font-size:0.78rem;opacity:0.6;margin:0 0 0.5rem;">'
            f'Region <code>{region}</code> · uses configured AWS credentials</p>',
            unsafe_allow_html=True,
        )
    with h_cols[1]:
        if st.button("Refresh", key="refresh_inv", use_container_width=True):
            if "_aws_inventory_snapshot" in st.session_state:
                del st.session_state["_aws_inventory_snapshot"]
            st.rerun()

    current_inventory_identity = (verified_identity["Account"], region) if verified_identity else ("offline", region)
    if st.session_state.get("_aws_inventory_identity") != current_inventory_identity:
        st.session_state.pop("_aws_inventory_snapshot", None)
        st.session_state["_aws_inventory_identity"] = current_inventory_identity

    if "_aws_inventory_snapshot" not in st.session_state:
        with st.spinner("Loading AWS inventory..."):
            if not verified_connection or not verified_identity:
                from dashboard.aws_inventory import InventorySnapshot
                snap = InventorySnapshot(fetched_at=datetime.utcnow(), region=region, resources=[])
            else:
                snap = AWSInventory(region=region, db=db, session=verified_connection.session(),
                                    account_id=verified_identity["Account"]).fetch()
            st.session_state["_aws_inventory_snapshot"] = snap
    snap = st.session_state["_aws_inventory_snapshot"]

    if not snap.resources and snap.errors:
        st.warning("AWS inventory could not be fetched. Check region, permissions or connection status.")
    elif not snap.resources:
        if DEMO_MODE:
            st.info("Inventory is disabled in offline demo mode. Synthetic security findings are available above.")
        elif not verified_identity:
            st.info("No cloud account connected. Use **Cloud Connections** to verify an identity before viewing inventory.")
        else:
            st.info("No inventory items returned for the connected account and region.")
    else:
        # Service summary inline (no emoji)
        summary_html = " &nbsp;·&nbsp; ".join(
            f'<b>{c}</b> <span style="opacity:0.7">{svc}</span>'
            for svc, c in sorted(snap.stats().items(), key=lambda x: -x[1])
        )
        st.markdown(
            f'<div style="font-size:0.86rem;margin:0 0 0.5rem;">{summary_html}</div>',
            unsafe_allow_html=True,
        )

        # Service tabs
        services_sorted = sorted(snap.by_service.items())
        service_tabs = st.tabs([f"{svc} ({len(rs)})" for svc, rs in services_sorted])
        for tab, (svc, resources) in zip(service_tabs, services_sorted):
            with tab:
                rows = []
                for r in resources:
                    rows.append({
                        "Type": r.type,
                        "Name": r.name,
                        "Identifier": (r.arn_or_id[:70] + "...") if len(r.arn_or_id) > 70
                                      else r.arn_or_id,
                        "Region": r.region,
                        "State": r.state,
                        "Findings": r.findings_count,
                    })
                df = pd.DataFrame(rows)
                st.dataframe(
                    df, use_container_width=True, hide_index=True,
                    column_config={
                        "Findings": st.column_config.NumberColumn(
                            help="Number of findings linked to this resource",
                            format="%d",
                        ),
                    },
                )

with inv_cols[1]:
    st.markdown(
        f'<h3 style="margin:0.7rem 0 0.2rem;">'
        f'{icon("ti-flame", size="1.1em")} &nbsp;Top Risks</h3>'
        f'<p style="font-size:0.78rem;opacity:0.6;margin:0 0 0.5rem;">'
        f'Highest-priority unresolved findings</p>',
        unsafe_allow_html=True,
    )

    top_findings, _ = db.get_findings_filtered(
        severities=["Critical", "High"],
        statuses=["New", "Analyzed"],
        limit=8,
    )
    if not top_findings:
        st.info("No high-priority findings.")
    else:
        for f in top_findings:
            with st.container(border=True):
                st.markdown(
                    f"{severity_chip(f.severity.value)}  "
                    f"<span style='opacity:0.55;font-size:0.74rem;'>{escape(f.source)}</span>"
                    f"<br><span style='font-weight:500;font-size:0.86rem;'>"
                    f"{escape(f.title[:80])}</span>"
                    f"<br><span style='opacity:0.55;font-size:0.74rem;font-family:monospace;'>"
                    f"{escape((f.resource[:55] + '...') if len(f.resource) > 55 else f.resource)}</span>",
                    unsafe_allow_html=True,
                )

# ===========================================================================
# Recent Activity (Incidents) + last pipeline run
# ===========================================================================
st.markdown(
    f'<h3 style="margin:1rem 0 0.3rem;">'
    f'{icon("ti-activity", size="1.1em")} &nbsp;Recent Activity</h3>',
    unsafe_allow_html=True,
)
act_cols = st.columns([2, 1])

with act_cols[0]:
    incidents = db.get_incidents()[:5]
    if incidents:
        for inc in incidents:
            with st.container(border=True):
                st.markdown(
                    f"{severity_chip(inc.severity.value)}  "
                    f"<span style='font-weight:500;'>{escape(inc.title)}</span>"
                    f"<br><span style='opacity:0.7;font-size:0.82rem;'>"
                    f"{escape(inc.summary[:200])}</span>"
                    f"<br><span style='opacity:0.5;font-size:0.72rem;'>"
                    f"{inc.timestamp.strftime('%Y-%m-%d %H:%M UTC')} · "
                    f"{len(inc.finding_ids)} linked findings · "
                    f"entity <code>{escape(inc.linked_entity)}</code></span>",
                    unsafe_allow_html=True,
                )
    else:
        st.caption("No correlated incidents yet — run pipeline with correlation enabled.")

with act_cols[1]:
    st.markdown(
        f'<div style="font-size:0.74rem;font-weight:600;text-transform:uppercase;'
        f'letter-spacing:0.06em;opacity:0.6;margin-bottom:0.4rem;">'
        f'Last Pipeline Run</div>',
        unsafe_allow_html=True,
    )
    if sstat.get("last_steps"):
        for name, ok, n, msg in sstat["last_steps"]:
            pill = status_pill(name, "ok" if ok else "error")
            st.markdown(
                f"{pill} &nbsp; <span style='font-size:0.78rem;opacity:0.7;'>"
                f"+{n}</span>",
                unsafe_allow_html=True,
            )
    else:
        st.caption("No runs yet.")

    if sstat.get("enabled"):
        st.caption(f"Auto-sync every {sstat['interval_minutes']}m")
    else:
        st.caption("Auto-sync OFF")
