"""
Settings & Operations page.

Sections:
  1. Run Full Pipeline (one-click + background auto-sync)
  2. Pipeline source configuration (Prowler / Wazuh / VPC Flow / AI / Correlate)
  3. Active AI Backend selection
  4. API Key management
  5. Token usage stats
  6. Manual operations (load demo data, clear cache)
  7. DB / config inspection
"""

from __future__ import annotations

import sys
import os
import time
from datetime import datetime, timedelta
from pathlib import Path

import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ai_module.analyzer import AIAnalyzer  # noqa: E402
from ai_module.providers.base import get_provider, list_providers  # noqa: E402
from config import user_settings  # noqa: E402
from dashboard.common import get_db  # noqa: E402
from dashboard.theme import apply_theme, page_title, render_sidebar  # noqa: E402
from orchestrator.pipeline import (  # noqa: E402
    Orchestrator,
    PipelineConfig,
    build_config_from_user_settings,
)
from orchestrator.scheduler import BackgroundScheduler  # noqa: E402

st.set_page_config(page_title="Settings", page_icon=None,
                   layout="wide", initial_sidebar_state="expanded")
apply_theme()

db = get_db()
settings = user_settings.load()
if os.getenv("CLOUDSENTINEL_DEMO", "").lower() in {"1", "true", "yes"}:
    st.info("Demo mode: all external pipeline sources and AI calls are disabled. "
            "Unset CLOUDSENTINEL_DEMO to enable live integrations.")


# ---------------------------------------------------------------------- #
# Singleton scheduler — survives Streamlit reruns
# ---------------------------------------------------------------------- #
@st.cache_resource
def get_scheduler() -> BackgroundScheduler:
    return BackgroundScheduler()


scheduler = get_scheduler()


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
    "Settings & Operations",
    subtitle="Run the pipeline manually, schedule auto-sync, and manage data sources & AI providers.",
    icon="ti-settings",
)

st.info("**Two scanning workflows:** Use **Cloud Connections → Scan Center** for a verified, per-session AWS scan. This legacy full pipeline uses separate **server-side** data source credentials (Prowler/Wazuh/VPC/LLM), not the Cloud Connections session key.")
st.page_link("pages/5_Scan_Center.py", label="Go to Scan Center →", icon="🛡️")

# ====================================================================== #
# Section 1: Run Full Pipeline + Auto-sync toggle
# ====================================================================== #
st.subheader("Run Full Pipeline")

p_settings = settings.get("pipeline", {}) or {}

# ---- One-click run ----
top1, top2 = st.columns([1, 1])
with top1:
    run_now = st.button(
        "Run all sources now",
        type="primary",
        use_container_width=True,
        help="Runs Prowler → Wazuh → VPC Flow → AI analysis → Correlation, in order.",
    )

# ---- Background scheduler controls ----
with top2:
    sched_status = scheduler.status()
    interval_default = sched_status["interval_minutes"]
    interval = st.number_input(
        "Auto-sync interval (minutes)",
        min_value=1, max_value=120, value=interval_default, step=5,
    )
    sched_col_a, sched_col_b = st.columns(2)
    with sched_col_a:
        if sched_status["enabled"]:
            if st.button("Stop auto-sync", use_container_width=True):
                scheduler.stop()
                st.rerun()
        else:
            if st.button("Start auto-sync", use_container_width=True):
                scheduler.start(int(interval))
                st.rerun()
    with sched_col_b:
        if sched_status["enabled"]:
            st.success(
                f"Auto-sync ON every {sched_status['interval_minutes']}m "
                f"(runs: {sched_status['runs_total']})"
            )
        else:
            st.info("Auto-sync OFF")

# Scheduler runtime info
if sched_status["enabled"]:
    s1, s2, s3 = st.columns(3)
    s1.metric("Total runs", sched_status["runs_total"])
    s2.metric(
        "Last run",
        sched_status["last_run_at"].strftime("%H:%M:%S")
        if sched_status["last_run_at"] else "—",
    )
    s3.metric(
        "Next run",
        sched_status["next_run_at"].strftime("%H:%M:%S")
        if sched_status["next_run_at"] else "—",
    )

    if sched_status["is_running_now"]:
        st.warning("A scheduled run is in progress...")
    if sched_status["last_steps"]:
        with st.expander("Last scheduled run details"):
            for name, ok, n, msg in sched_status["last_steps"]:
                icon = "OK" if ok else "FAIL"
                st.write(f"{icon} **{name}** — {msg} (+{n})")

# ---- Execute the synchronous run when the button is pressed ----
if run_now:
    cfg = build_config_from_user_settings()

    # Visual progress
    progress_bar = st.progress(0.0, text="Starting...")
    status_lines = st.empty()
    log_lines: list[str] = []

    def on_progress(step_name: str, fraction: float, message: str) -> None:
        log_lines.append(f"[{step_name}] {message}")
        progress_bar.progress(min(fraction, 1.0), text=message)
        status_lines.markdown("\n".join(f"• {l}" for l in log_lines))

    orch = Orchestrator(db=db, on_progress=on_progress)

    # Snapshot the AI usage stats BEFORE the run so we can show what this
    # specific run added.
    pre_usage = user_settings.load().get("usage", {})
    pre_totals = {p: sum(v.values()) for p, v in pre_usage.items() if isinstance(v, dict)}

    with st.spinner("Pipeline running..."):
        result = orch.run(cfg)
    progress_bar.progress(1.0, text="Done")

    # Compute what THIS run consumed (delta of usage counters).
    post_usage = user_settings.load().get("usage", {})
    run_input_tokens = 0
    run_output_tokens = 0
    run_calls = 0
    for pid, u in post_usage.items():
        prev = pre_usage.get(pid, {"input": 0, "output": 0, "calls": 0})
        run_input_tokens += u.get("input", 0) - prev.get("input", 0)
        run_output_tokens += u.get("output", 0) - prev.get("output", 0)
        run_calls += u.get("calls", 0) - prev.get("calls", 0)
    run_total_tokens = run_input_tokens + run_output_tokens

    # Summary line
    st.success(
        f"Pipeline finished in {result.total_duration_s:.1f}s — "
        f"{result.total_findings} new finding(s), "
        f"{result.total_incidents} incident(s) total."
    )

    # AI-specific metrics box (only shown if AI actually ran)
    if run_calls > 0:
        st.markdown(
            f"<div style='border:1px solid rgba(24,95,165,0.25);"
            f"background:rgba(24,95,165,0.05);border-radius:6px;"
            f"padding:10px 14px;margin:8px 0;font-size:0.86rem;'>"
            f"<b>AI usage this run:</b> "
            f"<b>{run_calls}</b> LLM call(s) &nbsp;·&nbsp; "
            f"<b>{run_total_tokens:,}</b> tokens "
            f"<span style='opacity:0.75;'>({run_input_tokens:,} in / "
            f"{run_output_tokens:,} out)</span>"
            f"</div>",
            unsafe_allow_html=True,
        )

    # Step-by-step results
    st.markdown("**Per-step results:**")
    for step in result.steps:
        step_icon = "OK" if step.ok else "FAIL"
        st.markdown(
            f"{step_icon} **{step.name}** — {step.message} "
            f"<span style='color:#64748b;'>({step.duration_s:.1f}s, +{step.findings_added})</span>",
            unsafe_allow_html=True,
        )
        if step.error:
            with st.expander(f"Error detail — {step.name}"):
                st.code(step.error)

st.divider()


# ====================================================================== #
# Section 2: Pipeline source configuration
# ====================================================================== #
st.subheader("Pipeline Sources")
st.caption("Configure each source. Disable any source you don't want included in pipeline runs.")

p_cfg = settings.get("pipeline", {}) or {}


def _save_pipeline_settings(updates: dict) -> None:
    s = user_settings.load()
    pcfg = s.setdefault("pipeline", {})
    pcfg.update(updates)
    user_settings.save(s)


tabs = st.tabs(["Prowler (CSPM)", "Wazuh (SIEM)", "VPC Flow Logs (Network)", "AI / Correlation"])

# ---- Prowler tab ----
with tabs[0]:
    en = st.checkbox("Enable Prowler", value=p_cfg.get("prowler_enabled", True),
                     key="cb_prowler")
    out_dir = st.text_input(
        "Output directory",
        value=p_cfg.get("prowler_output_dir", "./prowler-scans/output"),
        help="Where Prowler writes its scan files.",
    )
    prefix = st.text_input("Filename prefix", value=p_cfg.get("prowler_prefix", "scan"))
    ingest_file = st.text_input(
        "Ingest existing file instead of scanning (optional, supports * glob)",
        value=p_cfg.get("prowler_ingest_file", ""),
        help="If set, skip running prowler and just parse this OCSF JSON. "
             "Useful if scans take too long for an interactive run.",
    )
    if st.button("Save Prowler settings", key="save_prowler"):
        _save_pipeline_settings({
            "prowler_enabled": en,
            "prowler_output_dir": out_dir,
            "prowler_prefix": prefix,
            "prowler_ingest_file": ingest_file,
        })
        st.toast("Settings saved")
        st.rerun()

# ---- Wazuh tab ----
with tabs[1]:
    en_w = st.checkbox("Enable Wazuh", value=p_cfg.get("wazuh_enabled", True),
                       key="cb_wazuh")
    host = st.text_input("Indexer host", value=p_cfg.get("wazuh_host", "https://localhost:9200"))
    cwa, cwb = st.columns(2)
    with cwa:
        username = st.text_input("Username", value=p_cfg.get("wazuh_username", "admin"))
    with cwb:
        password = st.text_input("Indexer password (optional: stored in OS keyring)",
                                 value="", type="password",
                                 help="For headless systems set WAZUH_INDEXER_PASSWORD instead.")
    cwc, cwd = st.columns(2)
    with cwc:
        since = st.text_input(
            "Time window",
            value=p_cfg.get("wazuh_since", "24h"),
            help=(
                "How far back to pull alerts from the Wazuh indexer.\n\n"
                "Format: number + unit — s (seconds), m (MINUTES), "
                "h (hours), d (days).\n\n"
                "Examples: 15m, 1h, 24h, 7d, 30d.\n\n"
                "Note: 'm' means MINUTES not months. Use '30d' for one month."
            ),
        )
    with cwd:
        min_level = st.number_input("Min rule level", min_value=0, max_value=15,
                                    value=int(p_cfg.get("wazuh_min_level", 3)))
    ca_bundle = st.text_input(
        "Wazuh trusted CA bundle (PEM path)",
        value=p_cfg.get("wazuh_ca_bundle", ""),
        help="Leave blank for the system trust store. TLS verification remains enabled.",
    )
    aws_only = st.checkbox("Pull only AWS-sourced alerts",
                           value=p_cfg.get("wazuh_aws_only", False))

    cw_test, cw_save = st.columns(2)
    with cw_test:
        if st.button("Test connection", key="test_wazuh"):
            from siem_module.wazuh_client import WazuhClient
            with st.spinner("Testing..."):
                ok, msg = WazuhClient(
                    host=host, username=username,
                    password=password or user_settings.get_wazuh_password(),
                    verify_ssl=ca_bundle or True,
                ).test()
            st.success(msg) if ok else st.error(msg)
    with cw_save:
        if st.button("Save Wazuh settings", key="save_wazuh"):
            try:
                if password:
                    user_settings.set_wazuh_password(password)
            except RuntimeError as exc:
                st.error(str(exc))
                st.stop()
            _save_pipeline_settings({
                "wazuh_enabled": en_w,
                "wazuh_host": host, "wazuh_username": username,
                "wazuh_ca_bundle": ca_bundle, "wazuh_since": since,
                "wazuh_min_level": int(min_level), "wazuh_aws_only": aws_only,
            })
            st.toast("Settings saved")
            st.rerun()

# ---- VPC Flow tab ----
with tabs[2]:
    en_v = st.checkbox("Enable VPC Flow Logs", value=p_cfg.get("vpcflow_enabled", True),
                       key="cb_vpcflow")
    bucket = st.text_input("S3 bucket holding flow logs",
                           value=p_cfg.get("vpcflow_bucket", ""),
                           placeholder="e.g. fyp-vpcflowlogs-s3")
    region = st.text_input("Region", value=p_cfg.get("vpcflow_region", "ap-southeast-1"))
    max_files = st.number_input("Max files per run", min_value=1, max_value=500,
                                value=int(p_cfg.get("vpcflow_max_files", 50)))

    st.markdown("**Detection thresholds**")
    cv1, cv2, cv3 = st.columns(3)
    with cv1:
        rj = st.number_input("Reject storm",
                             value=int(p_cfg.get("vpcflow_reject_threshold", 5)),
                             min_value=1, help="# of REJECTed connections from one src.")
    with cv2:
        sw = st.number_input("Port sweep",
                             value=int(p_cfg.get("vpcflow_sweep_threshold", 5)),
                             min_value=1, help="# of distinct dst ports from one src.")
    with cv3:
        ss = st.number_input("Sensitive port",
                             value=int(p_cfg.get("vpcflow_sensitive_threshold", 3)),
                             min_value=1, help="# of attempts to SSH/RDP/DB ports.")

    if st.button("Save VPC Flow settings", key="save_vpcflow"):
        _save_pipeline_settings({
            "vpcflow_enabled": en_v, "vpcflow_bucket": bucket,
            "vpcflow_region": region, "vpcflow_max_files": int(max_files),
            "vpcflow_reject_threshold": int(rj),
            "vpcflow_sweep_threshold": int(sw),
            "vpcflow_sensitive_threshold": int(ss),
        })
        st.toast("Settings saved")
        st.rerun()

# ---- AI tab ----
with tabs[3]:
    en_ai = st.checkbox("Run AI analysis on new findings",
                        value=p_cfg.get("ai_enabled", True), key="cb_ai")
    en_corr = st.checkbox("Run correlation engine after analysis",
                          value=p_cfg.get("correlate_enabled", True), key="cb_corr")

    severity_options = ["None", "Critical", "High", "Medium", "Low", ""]
    severity_labels = {
        "None": "None — do not auto-analyse (manual only)",
        "Critical": "Critical only",
        "High": "Critical + High (recommended)",
        "Medium": "Critical + High + Medium",
        "Low": "Everything except Informational",
        "": "All severities (slow + expensive)",
    }
    current_min = p_cfg.get("ai_min_severity", "High")
    if current_min not in severity_options:
        current_min = "High"
    min_sev = st.selectbox(
        "Auto-analyse minimum severity",
        severity_options,
        index=severity_options.index(current_min),
        format_func=lambda v: severity_labels.get(v, v),
        help=(
            "During a full pipeline run, only auto-analyse findings at or "
            "above this severity. Lower-severity findings still get stored "
            "and can be analysed on-demand by clicking 'Analyze with AI' on "
            "their card. This keeps pipeline runs fast and LLM costs low."
        ),
    )

    if st.button("Save AI settings", key="save_ai"):
        _save_pipeline_settings({
            "ai_enabled": en_ai,
            "correlate_enabled": en_corr,
            "ai_min_severity": min_sev,
        })
        st.toast("Settings saved")
        st.rerun()
    st.caption("(The AI provider itself is configured below.)")

st.divider()


# ====================================================================== #
# Section 3: Active AI Backend
# ====================================================================== #
st.subheader("Active AI Backend")
st.caption("Which LLM provider/model the AI module uses.")

provider_infos = list_providers()
provider_options = {p.display_name: p.id for p in provider_infos}
current_pid = settings.get("active_provider", "gemini")
current_display = next(
    (name for name, pid in provider_options.items() if pid == current_pid),
    list(provider_options.keys())[0],
)

col_p, col_m = st.columns([2, 2])
with col_p:
    chosen_display = st.selectbox(
        "Provider",
        list(provider_options.keys()),
        index=list(provider_options.keys()).index(current_display),
    )
    chosen_pid = provider_options[chosen_display]

chosen_info = next(p for p in provider_infos if p.id == chosen_pid)
preferred = settings.get("preferred_models", {}).get(chosen_pid, chosen_info.default_model)
with col_m:
    model_idx = chosen_info.models.index(preferred) if preferred in chosen_info.models else 0
    chosen_model = st.selectbox("Model", chosen_info.models, index=model_idx)

if chosen_info.pricing_note:
    st.caption(f"{chosen_info.pricing_note}")

needs_key = chosen_info.requires_api_key and not user_settings.get_api_key(chosen_pid)
if needs_key:
    st.warning(
        f"No API key saved for {chosen_info.display_name}. "
        f"Set one below before activating."
    )

act_col1, act_col2 = st.columns([1, 4])
with act_col1:
    if st.button("Activate", type="primary", use_container_width=True, disabled=needs_key):
        user_settings.set_active_provider(chosen_pid, chosen_model)
        st.success(f"Active backend → {chosen_info.display_name} / {chosen_model}")
        st.rerun()
with act_col2:
    current_model = settings.get("active_model", "")
    st.info(f"Currently active: **{current_pid}** / `{current_model}`")

st.divider()


# ====================================================================== #
# Section 4: API key management
# ====================================================================== #
st.subheader("API Keys")
st.caption("API keys are read from environment variables or your OS credential store. They are never saved in config.json. Headless servers: set *_API_KEY environment variables.")

key_tabs = st.tabs([p.display_name for p in provider_infos if p.requires_api_key])
key_providers = [p for p in provider_infos if p.requires_api_key]

for tab, pinfo in zip(key_tabs, key_providers):
    with tab:
        existing = user_settings.get_api_key(pinfo.id)
        status_text = "Key saved" if existing else "No key set"
        st.caption(f"{status_text}  •  {pinfo.api_key_help}")
        if pinfo.homepage:
            st.caption(f"Get a key: {pinfo.homepage}")

        new_key = st.text_input("API Key", type="password",
                                placeholder="Paste key (leave blank to keep existing)",
                                key=f"key_input_{pinfo.id}")

        b1, b2, b3 = st.columns(3)
        with b1:
            if st.button("Save", key=f"save_{pinfo.id}", use_container_width=True):
                if new_key.strip():
                    try:
                        user_settings.set_api_key(pinfo.id, new_key.strip())
                        st.toast("API key saved in OS keyring")
                        st.rerun()
                    except RuntimeError as exc:
                        st.error(str(exc))
                else:
                    st.warning("Paste a key first.")
        with b2:
            if st.button("Test", key=f"test_{pinfo.id}", use_container_width=True,
                         disabled=not (existing or new_key.strip())):
                key_to_test = new_key.strip() or existing
                with st.spinner("Calling provider..."):
                    prov = get_provider(pinfo.id, api_key=key_to_test,
                                        model=pinfo.default_model)
                    ok, msg = prov.test()
                st.success(msg) if ok else st.error(msg)
        with b3:
            if st.button("Clear", key=f"clear_{pinfo.id}", use_container_width=True,
                         disabled=not existing):
                try:
                    user_settings.set_api_key(pinfo.id, "")
                    st.info("Removed from OS keyring. Environment overrides remain active.")
                    st.rerun()
                except RuntimeError as exc:
                    st.error(str(exc))

st.divider()

# ====================================================================== #
# Section 5: Usage stats
# ====================================================================== #
st.subheader("Token Usage")
usage = settings.get("usage", {})
usage_rows = []
for pinfo in provider_infos:
    u = usage.get(pinfo.id, {"input": 0, "output": 0, "calls": 0})
    usage_rows.append({
        "Provider": pinfo.display_name,
        "Calls": u.get("calls", 0),
        "Input tokens": f"{u.get('input', 0):,}",
        "Output tokens": f"{u.get('output', 0):,}",
        "Total": f"{u.get('input', 0) + u.get('output', 0):,}",
    })
st.dataframe(usage_rows, use_container_width=True, hide_index=True)
if st.button("Reset usage counters"):
    user_settings.reset_usage()
    st.success("Reset.")
    st.rerun()

st.divider()

# ====================================================================== #
# Section 6: Other manual ops
# ====================================================================== #
st.subheader("Other Operations")
op1, op2, op3 = st.columns(3)
with op1:
    if st.button("Load demo data", use_container_width=True,
                 help="Insert a set of sample findings so you can explore the UI "
                      "without connecting to real AWS."):
        from mock_data.generate import seed
        n = seed(db)
        st.toast(f"Loaded {n} demo findings")
        st.rerun()
with op2:
    if st.button("Clear AI cache and analyses", use_container_width=True,
                 help="Forces re-analysis on next run."):
        import sqlite3
        conn = sqlite3.connect(db.db_path)
        conn.execute("DELETE FROM ai_cache")
        conn.execute("DELETE FROM ai_analysis")
        conn.execute("UPDATE findings SET status='New'")
        conn.commit()
        conn.close()
        st.success("Cleared.")
        st.rerun()
with op3:
    if st.button("Wipe all findings", use_container_width=True,
                 help="Removes every finding/analysis/incident. Cannot be undone."):
        import sqlite3
        conn = sqlite3.connect(db.db_path)
        for tbl in ("findings", "ai_analysis", "ai_cache", "incidents"):
            conn.execute(f"DELETE FROM {tbl}")
        conn.commit()
        conn.close()
        st.success("Database wiped.")
        st.rerun()

st.divider()

# ====================================================================== #
# Section 7: DB info
# ====================================================================== #
with st.expander("Database and config paths"):
    st.write(f"**Database:** `{db.db_path}`")
    st.write(f"**Settings file:** `{user_settings.CONFIG_FILE}`")
    st.write("Database stats:")
    st.json(db.stats())
