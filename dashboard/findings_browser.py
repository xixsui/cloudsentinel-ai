"""
Reusable findings browser component.

Used by the Misconfigurations and Threat Alerts pages — same UI logic, just
filtered by FindingType. Provides:

- Filter row: severity multi-select, source multi-select, status multi-select, search box
- View toggle: Compact table (default) vs Detailed cards
- Pagination
- Per-row "Analyze with AI" button for findings that haven't been analysed yet
- Resolve / False positive action buttons (inside detail expander)

This is built so a page file is tiny — just a header and one call to
`render_findings_browser(...)`.
"""

from __future__ import annotations

from html import escape
import streamlit as st

from ai_module.analyzer import AIAnalyzer
from config import user_settings
from ai_module.database import Database
from ai_module.models import Finding, FindingType, Status
from dashboard.common import (
    SEVERITY_ORDER,
    severity_badge,
    status_badge,
)


PAGE_SIZES = [10, 25, 50, 100]


def render_findings_browser(
    db: Database,
    finding_type: FindingType,
    label_singular: str = "finding",
    key_prefix: str = "ft",
) -> None:
    """
    Render the filter row + view toggle + table-or-card list + pagination.

    `key_prefix` lets the same component appear twice (e.g. misconfig + threat)
    on different pages without their widget keys colliding.
    """
    settings = user_settings.load()
    active_provider = settings.get("active_provider", "gemini")
    ai_ready = bool(user_settings.get_api_key(active_provider))
    if not ai_ready:
        st.info(
            f"AI analysis is not configured for **{active_provider.capitalize()}**. "
            "You can investigate demo findings without an API key. "
            "To enable live AI analysis, add a provider key in **Settings** "
            "(or use its environment variable in WSL2).",
            icon="ℹ️",
        )

    # ---------- Filter row ---------- #
    sources_in_db = db.distinct_values("source") or []
    statuses_in_db = db.distinct_values("status") or [s.value for s in Status]

    fc1, fc2, fc3, fc4 = st.columns([1.3, 1.3, 1.2, 2])
    with fc1:
        severity_filter = st.multiselect(
            "Severity",
            SEVERITY_ORDER,
            default=["Critical", "High", "Medium", "Low"],
            key=f"{key_prefix}_sev",
        )
    with fc2:
        source_filter = st.multiselect(
            "Source",
            sources_in_db,
            default=sources_in_db,
            key=f"{key_prefix}_src",
        )
    with fc3:
        status_filter = st.multiselect(
            "Status",
            statuses_in_db,
            default=[s for s in statuses_in_db if s != Status.RESOLVED.value],
            key=f"{key_prefix}_status",
        )
    with fc4:
        search = st.text_input(
            "Search (title, description, resource)",
            placeholder="e.g. S3, IAM, 198.51.100.42",
            key=f"{key_prefix}_search",
        )

    # ---------- View toggle + page size ---------- #
    vc1, vc2, vc3 = st.columns([1.5, 1, 3])
    with vc1:
        view_mode = st.radio(
            "View",
            ["Compact table", "Detailed cards"],
            horizontal=True,
            key=f"{key_prefix}_view",
        )
    with vc2:
        page_size = st.selectbox(
            "Per page", PAGE_SIZES, index=0, key=f"{key_prefix}_psize"
        )

    # ---------- Query DB ---------- #
    # Stash current page in session state, reset on filter change.
    page_key = f"{key_prefix}_page"
    if page_key not in st.session_state:
        st.session_state[page_key] = 0

    # If the user changed a filter the previous page might be out of range —
    # reset to 0 whenever filters change.
    filter_signature = (
        tuple(severity_filter), tuple(source_filter),
        tuple(status_filter), search, page_size,
    )
    sig_key = f"{key_prefix}_sig"
    if st.session_state.get(sig_key) != filter_signature:
        st.session_state[page_key] = 0
        st.session_state[sig_key] = filter_signature

    findings, total = db.get_findings_filtered(
        finding_type=finding_type,
        severities=severity_filter or None,
        sources=source_filter or None,
        statuses=status_filter or None,
        search=search.strip() or None,
        limit=page_size,
        offset=st.session_state[page_key] * page_size,
    )

    # ---------- Pagination header ---------- #
    total_pages = max(1, -(-total // page_size))   # ceil
    current_page = st.session_state[page_key]
    if current_page >= total_pages:
        st.session_state[page_key] = max(0, total_pages - 1)
        current_page = st.session_state[page_key]

    head_cols = st.columns([3, 1, 1, 1])
    with head_cols[0]:
        st.caption(
            f"Showing **{len(findings)}** of **{total}** {label_singular}(s) "
            f"• page **{current_page + 1}** / **{total_pages}**"
        )
    with head_cols[1]:
        if st.button("Prev", key=f"{key_prefix}_prev",
                     disabled=current_page <= 0, use_container_width=True):
            st.session_state[page_key] = max(0, current_page - 1)
            st.rerun()
    with head_cols[2]:
        if st.button("Next", key=f"{key_prefix}_next",
                     disabled=current_page >= total_pages - 1,
                     use_container_width=True):
            st.session_state[page_key] = min(total_pages - 1, current_page + 1)
            st.rerun()
    with head_cols[3]:
        if st.button("Analyze visible", key=f"{key_prefix}_batch",
                     disabled=not ai_ready,
                     use_container_width=True,
                     help="Run AI analysis on every finding shown on this page "
                          "that hasn't been analysed yet."):
            _batch_analyze(db, findings)
            st.rerun()

    st.divider()

    if not findings:
        st.info("No findings match the current filters.")
        return

    # ---------- Render rows ---------- #
    if view_mode == "Compact table":
        _render_table(db, findings, key_prefix, ai_ready)
    else:
        _render_cards(db, findings, key_prefix, ai_ready)


# ============================================================================
# Table view — one row per finding, click to expand details inline.
# ============================================================================
def _render_table(db: Database, findings: list[Finding], key_prefix: str, ai_ready: bool) -> None:
    # We use a raw HTML table instead of st.dataframe so severity chips can
    # render with their proper colour. st.dataframe doesn't respect embedded
    # HTML/CSS, so the coloured chips would show up as plain text.
    from dashboard.theme import SEVERITY_COLORS, SEVERITY_BG

    def _chip(sev: str) -> str:
        c = SEVERITY_COLORS.get(sev, "#5F5E5A")
        b = SEVERITY_BG.get(sev, "rgba(95,94,90,0.10)")
        return (
            f'<span style="display:inline-block;padding:1px 8px;border-radius:3px;'
            f'font-size:0.68rem;font-weight:600;letter-spacing:0.02em;'
            f'text-transform:uppercase;color:{c};background:{b};">{sev}</span>'
        )

    header = (
        '<tr style="border-bottom:1px solid rgba(0,0,0,0.15);'
        'text-align:left;font-size:0.72rem;font-weight:600;'
        'text-transform:uppercase;letter-spacing:0.05em;opacity:0.65;">'
        '<th style="padding:8px 6px;">Severity</th>'
        '<th style="padding:8px 6px;">AI Risk</th>'
        '<th style="padding:8px 6px;">Source</th>'
        '<th style="padding:8px 6px;">Title</th>'
        '<th style="padding:8px 6px;">Resource</th>'
        '<th style="padding:8px 6px;">Status</th>'
        '<th style="padding:8px 6px;">Time</th>'
        '<th style="padding:8px 6px; text-align:center;">Analysed</th>'
        '</tr>'
    )

    body_rows = []
    for f in findings:
        a = db.get_analysis(f.finding_id)
        sev_chip = _chip(f.severity.value)
        ai_chip = _chip(a.risk_priority.value) if a else '<span style="opacity:0.4;">—</span>'
        title_short = f.title if len(f.title) <= 65 else f.title[:62] + "..."
        resource_short = f.resource if len(f.resource) <= 45 else f.resource[:42] + "..."
        analysed_icon = (
            '<span style="color:#0F6E56;font-weight:600;">yes</span>' if a
            else '<span style="opacity:0.4;">—</span>'
        )
        body_rows.append(
            f'<tr style="border-bottom:1px solid rgba(0,0,0,0.05);font-size:0.82rem;">'
            f'<td style="padding:6px;">{sev_chip}</td>'
            f'<td style="padding:6px;">{ai_chip}</td>'
            f'<td style="padding:6px;"><code style="font-size:0.72rem;">{escape(f.source)}</code></td>'
            f'<td style="padding:6px;">{escape(title_short)}</td>'
            f'<td style="padding:6px;"><code style="font-size:0.72rem;opacity:0.75;">{escape(resource_short)}</code></td>'
            f'<td style="padding:6px;font-size:0.75rem;opacity:0.75;">{f.status.value}</td>'
            f'<td style="padding:6px;font-size:0.75rem;opacity:0.75;">{f.timestamp.strftime("%m-%d %H:%M")}</td>'
            f'<td style="padding:6px;text-align:center;">{analysed_icon}</td>'
            f'</tr>'
        )

    st.markdown(
        '<table style="width:100%;border-collapse:collapse;margin-bottom:0.5rem;">'
        f'<thead>{header}</thead>'
        f'<tbody>{"".join(body_rows)}</tbody>'
        '</table>',
        unsafe_allow_html=True,
    )

    # Expandable detail per finding below the table
    st.caption("Click any finding ID below to expand its detail.")
    for f in findings:
        _render_finding_expander(db, f, key_prefix, ai_ready)


# ============================================================================
# Card view — full detail per finding (the original look).
# ============================================================================
def _render_cards(db: Database, findings: list[Finding], key_prefix: str, ai_ready: bool) -> None:
    for f in findings:
        _render_finding_card(db, f, key_prefix, ai_ready)


# Own the expander/card *inside* each fragment. Writing widgets into a
# container created outside the fragment is not supported by Streamlit.
# Clicking Analyze or Regenerate reruns only this finding's inspector.
@st.fragment
def _render_finding_expander(db: Database, f: Finding, key_prefix: str, ai_ready: bool) -> None:
    with st.expander(f"[{f.severity.value}] {f.title}  —  {f.resource[:80]}"):
        _render_detail(db, f, key_prefix, ai_ready)


@st.fragment
def _render_finding_card(db: Database, f: Finding, key_prefix: str, ai_ready: bool) -> None:
    with st.container(border=True):
        _render_detail(db, f, key_prefix, ai_ready)


# ============================================================================
# Shared detail panel
# ============================================================================
def _render_detail(db: Database, f: Finding, key_prefix: str, ai_ready: bool) -> None:
    from dashboard.remediation_ui import render_finding_workbench

    head1, head2 = st.columns([5, 1])
    with head1:
        st.markdown(f"**{escape(f.title)}**  &nbsp; {severity_badge(f.severity.value)}",
                    unsafe_allow_html=True)
        st.caption(f"Source: {f.source}  •  Resource: {f.resource}  •  Check: {f.check_id}")
    with head2:
        st.caption(f.timestamp.strftime("%Y-%m-%d %H:%M") + " UTC")

    if f.finding_type == FindingType.MISCONFIG:
        render_finding_workbench(db, f, ai_ready=ai_ready, prefix=key_prefix)
        return

    # Legacy optional SIEM finding workflow remains unchanged.
    analysis = db.get_analysis(f.finding_id)
    if analysis:
        st.write("AI explanation:", analysis.explanation)
    if st.button("Analyze with AI", key=f"{key_prefix}_analyze_{f.finding_id}", disabled=not ai_ready):
        with st.spinner("Analyzing…"):
            AIAnalyzer(db).analyze_finding(f)
        st.rerun(scope="fragment")
    with st.expander("Raw evidence"):
        st.json(f.raw_evidence)


# ============================================================================
# Batch analysis helper — analyses every finding on the current page that
# hasn't been analysed yet. Has a per-page progress bar.
# ============================================================================
def _batch_analyze(db: Database, findings: list[Finding]) -> None:
    pending = [f for f in findings if not db.get_analysis(f.finding_id)]
    if not pending:
        st.toast("All visible findings already have AI analysis.")
        return
    progress = st.progress(0.0, text=f"Analysing 0/{len(pending)}...")
    analyzer = AIAnalyzer(db)
    for i, f in enumerate(pending, 1):
        analyzer.analyze_finding(f)
        progress.progress(i / len(pending), text=f"Analysing {i}/{len(pending)}...")
    progress.empty()
    st.toast(f"Analysed {len(pending)} finding(s).")
