"""Read-only Prowler scan launcher and local OCSF import / synthetic demo."""
from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cloud_connection.aws import REGION_CHOICES
from dashboard.common import get_db
from dashboard.theme import apply_theme, page_title, render_sidebar
from prowler_module.scan_jobs import SAFE_SERVICES, ScanManager, ScanOptions
from prowler_module.scanner import ProwlerScanner

st.set_page_config(page_title="Scan Center · CloudSentinel", page_icon="🛡️", layout="wide")
apply_theme()
render_sidebar()
page_title("Scan Center", subtitle="On-demand cloud posture scanning, safe offline simulation and OCSF import.", icon="ti-radar")
DEMO = os.getenv("CLOUDSENTINEL_DEMO", "").lower() in {"1", "true", "yes"}
DB = get_db()

@st.cache_resource
def get_scan_manager() -> ScanManager:
    return ScanManager()

manager = get_scan_manager()
if "scan_job_ids" not in st.session_state:
    st.session_state["scan_job_ids"] = []
identity = st.session_state.get("aws_identity") if not DEMO else None
connection = st.session_state.get("aws_connection") if not DEMO else None
prowler_available = shutil.which("prowler") is not None

with st.container(border=True):
    a, b, c = st.columns([1, 1, 1])
    a.metric("Source", "Synthetic" if DEMO else ("AWS " + identity["Account"] if identity else "Not connected"))
    b.metric("Prowler CLI", "Installed" if prowler_available else "Not detected")
    c.metric("Scan mode", "Offline simulation" if DEMO else "Read-only live")
    if DEMO:
        st.info("**Offline demonstration:** scan results are generated from a small, labeled synthetic dataset. No AWS request and no Prowler executable are involved.")
    elif not identity:
        st.warning("Connect and verify an AWS identity in **Cloud Connections** before starting a live scan. Alternatively, import an OCSF scan report below.")
        st.page_link("pages/4_Cloud_Connections.py", label="Configure AWS connection →", icon="🔐")
    elif not prowler_available:
        st.warning("Prowler CLI not found on the machine running Streamlit. Install it into the same Python environment (`pip install prowler`) before scanning. Offline report import is still available.")

left, right = st.columns([1.7, 1], gap="large")
with left:
    st.markdown("#### New security scan")
    with st.form("scan_builder"):
        preset = st.selectbox("Scan profile", ["Essential posture", "Network exposure", "Extended review", "Custom"],
                              help="Profiles only choose the scan scope; they don't change any AWS resources.")
        defaults = {
            "Essential posture": ("iam", "s3", "ec2", "cloudtrail"),
            "Network exposure": ("ec2", "vpc", "cloudtrail"),
            "Extended review": tuple(sorted(SAFE_SERVICES)),
            "Custom": ("s3", "iam", "ec2"),
        }
        services = st.multiselect("AWS services to assess", sorted(SAFE_SERVICES),
                                  default=defaults[preset],
                                  help="Use a small scope for a first scan; checks and required IAM permissions vary by service.")
        selected_region = st.selectbox("Region", list(REGION_CHOICES),
                                       index=list(REGION_CHOICES).index(connection.region)
                                       if connection and connection.region in REGION_CHOICES else 0,
                                       help="Malaysia (ap-southeast-5) is an AWS opt-in region and may need enabling in the account.")
        region = selected_region
        timeout = st.select_slider("Maximum scan duration", options=[300, 600, 900, 1800, 3600], value=1800,
                                   format_func=lambda seconds: f"{seconds // 60} minutes")
        st.caption("Prowler performs read-only security assessments. Findings are stored locally in SQLite. Repeated imports update existing findings.")
        disabled = not DEMO and (connection is None or identity is None or not prowler_available)
        submitted = st.form_submit_button("Run demo scan" if DEMO else "Start Prowler scan", type="primary",
                                          use_container_width=True, disabled=disabled)

    if submitted:
        try:
            opts = ScanOptions(region=region, services=tuple(services), timeout_seconds=int(timeout))
            if DEMO:
                job_id = manager.run_demo(opts, DB.db_path)
            else:
                job_id = manager.submit(connection, identity["Account"], opts,
                                        ROOT / "prowler-scans" / "output", DB.db_path)
            st.session_state["scan_job_ids"].append(job_id)
            st.session_state["last_scan_job_id"] = job_id
            st.rerun()
        except (ValueError, RuntimeError) as exc:
            st.error(str(exc))

with right:
    st.markdown("#### Before you scan")
    with st.container(border=True):
        st.markdown("**1 · Verify identity**")
        st.caption("Select a profile or temporary IAM role credentials from Cloud Connections.")
        st.markdown("**2 · Choose scope**")
        st.caption("Start with a small region/service set and read-only IAM permissions.")
        st.markdown("**3 · Review findings**")
        st.caption("The results become searchable in Misconfigurations and the Overview.")
        st.markdown("**4 · Investigate evidence**")
        st.caption("AI-generated analysis is optional and is not required to assess Prowler findings.")
    st.page_link("pages/1_Misconfigurations.py", label="Browse security findings →", icon="🔎")

st.divider()
st.markdown("#### Scan activity")
row1, row2 = st.columns([4, 1])
with row1:
    st.caption("Scan history for this browser session. A live scan runs as a single local background job; large accounts can take several minutes.")
with row2:
    st.button("Refresh status", use_container_width=True)
jobs = manager.list_jobs(st.session_state["scan_job_ids"])
# Persist result feedback across the page rerun instead of briefly showing a
# success toast that disappears before the user can read it.
last_job = next((j for j in jobs if j.job_id == st.session_state.get("last_scan_job_id")), None)
if last_job:
    if last_job.status == "completed":
        st.success(f"{'Demo' if last_job.mode == 'demo' else 'Prowler'} scan completed · "
                   f"{last_job.findings_added} findings imported.")
    elif last_job.status == "failed":
        st.error(f"Scan failed · {last_job.message}")
    else:
        st.info(f"Scan {last_job.status} · refresh status below to check progress.")
if jobs:
    st.dataframe([
        {"Scan ID": j.job_id[:8], "Mode": j.mode.upper(), "Account": j.account_id,
         "Region": j.region, "Services": ", ".join(j.services),
         "Status": j.status.upper(), "Findings processed": j.findings_added,
         "Started (UTC)": j.created_at, "Finished (UTC)": j.finished_at or "—",
         "Notes": j.message}
        for j in jobs], use_container_width=True, hide_index=True)
    if any(j.status in ("queued", "running") for j in jobs):
        st.info("Scan in progress. Select **Refresh status** to check completion. Do not close the server while the scan is running.")
else:
    st.info("No scans in this session. Run the demo above, connect AWS for a live scan, or import an existing report below.")

st.divider()
st.markdown("#### Import existing Prowler report")
st.caption("You can review scan output without AWS credentials. Upload a Prowler OCSF JSON report (up to 10 MB). Importing does not run any cloud commands.")
with st.expander("Import OCSF JSON", expanded=False):
    uploaded = st.file_uploader("Choose .json report", type=["json"], key="ocsf_upload")
    if uploaded is not None:
        st.caption(f"Selected: {uploaded.name} ({uploaded.size / 1024:.1f} KB)")
        if st.button("Validate and import findings", type="primary"):
            if uploaded.size > 10 * 1024 * 1024:
                st.error("Report exceeds the 10 MB limit.")
            else:
                try:
                    parsed = json.loads(uploaded.getvalue().decode("utf-8"))
                    if isinstance(parsed, dict):
                        parsed = next((parsed[k] for k in ("findings", "events", "results")
                                       if isinstance(parsed.get(k), list)), None)
                    if not isinstance(parsed, list):
                        raise ValueError("Unexpected OCSF structure")
                    count = ProwlerScanner(db=DB).ingest_events(parsed)
                except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
                    st.error("The file is not a supported Prowler OCSF JSON report. Check the export format.")
                else:
                    st.success(f"Report imported: {count} FAIL finding(s) processed. Re-importing a finding will update its record.")
    st.warning("Reports can contain account IDs, resource metadata and private addresses. Keep raw reports out of public repositories and only upload files from trusted sources.")
