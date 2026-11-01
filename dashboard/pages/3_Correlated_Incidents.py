"""CloudSentinel investigation workbench: explainable, analyst-reviewed incidents.

Works offline with synthetic cases; no AWS credentials or LLM key required.
This is a local single-user prototype, NOT an authenticated multi-tenant SOC.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from pathlib import Path

import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ai_module.investigation import score_incident, techniques_for_incident  # noqa: E402
from ai_module.models import Finding, Incident, Severity, Status  # noqa: E402
from config import user_settings  # noqa: E402
from dashboard.common import get_db  # noqa: E402
from dashboard.theme import apply_theme, page_title, render_sidebar  # noqa: E402

st.set_page_config(page_title="Incident Investigation | CloudSentinel AI",
                   layout="wide", initial_sidebar_state="expanded")
apply_theme()

db = get_db()
settings = user_settings.load()
sources = db.distinct_values("source")
render_sidebar(source_status={
    "Prowler": "ok" if "prowler" in sources else "warning",
    "Wazuh": "ok" if "wazuh" in sources else "warning",
    "VPC Flow": "ok" if "vpc-flow-logs" in sources else "warning",
}, provider_label=settings.get("active_provider", "gemini").capitalize())
page_title(
    "Incident Investigation",
    subtitle="Review evidence, prioritize cases, and record analyst decisions. ATT&CK tags are behavioural hypotheses, not proof of compromise.",
    icon="ti-shield-search",
)

WORKFLOW_STATUSES = (
    Status.NEW, Status.INVESTIGATING, Status.RESOLVED, Status.FALSE_POSITIVE,
)


def _is_demo(findings: list[Finding]) -> bool:
    return bool(findings) and all(f.raw_evidence.get("synthetic_demo") is True for f in findings)


def _linked(incident: Incident, lookup: dict[str, Finding]) -> list[Finding]:
    return sorted((lookup[fid] for fid in incident.finding_ids if fid in lookup),
                  key=lambda f: (f.timestamp, f.finding_id))


def _export_report(inc: Incident, linked: list[Finding], activity: list[dict]) -> str:
    assessment = score_incident(inc, linked)
    report = {
        "case_id": inc.incident_id,
        "title": inc.title,
        "summary": inc.summary,
        "source_severity": inc.severity.value,
        "triage_score": assessment.score,
        "triage_priority": assessment.priority.value,
        "triage_score_is_probability": False,
        "factors": [{"label": x.label, "points": x.points, "reason": x.rationale}
                    for x in assessment.factors],
        "status": inc.status.value,
        "assignee": inc.assignee,
        "resolution_note": inc.resolution_note,
        "synthetic_demo": _is_demo(linked),
        "linked_entity": inc.linked_entity,
        "findings": [{
            "id": f.finding_id, "source": f.source, "severity": f.severity.value,
            "title": f.title, "timestamp": f.timestamp.isoformat(),
        } for f in linked],
        "attack_techniques": [{"id": m.technique_id, "name": m.name,
                               "tactic": m.tactic, "evidence": m.evidence,
                               "reference": m.url}
                              for m in techniques_for_incident(linked)],
        "activity": activity,
        "caveat": "Analyst decision support only; mappings and score do not establish an intrusion. "
                  "This report omits raw evidence, but identifiers may still be sensitive.",
    }
    return json.dumps(report, indent=2, ensure_ascii=False)


def _case_detail(inc: Incident, all_findings: dict[str, Finding]) -> None:
    linked = _linked(inc, all_findings)
    assessment = score_incident(inc, linked)
    technique_matches = techniques_for_incident(linked)
    activity = db.get_incident_activity(inc.incident_id)
    not_found = len(set(inc.finding_ids)) - len(linked)
    demo_count = sum(f.raw_evidence.get("synthetic_demo") is True for f in linked)

    st.markdown(f"### {inc.title}")
    if _is_demo(linked):
        st.info("**SYNTHETIC DEMO CASE** — Generated from mock findings. No AWS scan, AI conclusion, or confirmed breach.")
    elif demo_count:
        st.warning(f"This case mixes {demo_count} synthetic finding(s) with other evidence. Review provenance before taking action.")
    if not_found:
        st.warning(f"{not_found} linked finding(s) are missing from the local database. The triage score may be incomplete.")

    a, b, c, d = st.columns(4)
    a.metric("Triage score / 100", assessment.score, help="Deterministic heuristic, NOT the likelihood of compromise")
    b.metric("Suggested priority", assessment.priority.value, help="Derived from evidence and transparent point factors")
    c.metric("Source severity", inc.severity.value)
    d.metric("Linked events", len(linked))

    left, right = st.columns([2.25, 1], gap="large")
    with left:
        overview, timeline, mapping, audit = st.tabs([
            "Case overview", "Evidence timeline", "ATT&CK & risk", "Activity log",
        ])
        with overview:
            st.markdown("#### Analyst summary")
            st.write(inc.summary or "No summary is available.")
            if inc.ai_narrative:
                st.markdown("#### AI-generated interpretation (unverified)")
                st.write(inc.ai_narrative)
            st.caption("Correlation links records by explicit resource and time window. It does not prove an attack chain.")
            st.markdown("#### Case metadata")
            st.text(f"Case ID: {inc.incident_id}")
            st.text(f"Linked entity: {inc.linked_entity or 'Unspecified'}")
            st.text(f"First recorded: {inc.timestamp.strftime('%Y-%m-%d %H:%M')} UTC")
            st.text(f"Status: {inc.status.value} · Assignee: {inc.assignee or 'Unassigned'}")
            if inc.resolution_note:
                st.markdown("**Resolution rationale**")
                st.write(inc.resolution_note)
        with timeline:
            if not linked:
                st.info("No linked finding records are available. Import evidence before investigating.")
            for number, finding in enumerate(linked, 1):
                with st.container(border=True):
                    st.caption(f"EVENT {number:02d}  ·  {finding.timestamp.strftime('%Y-%m-%d %H:%M:%S')} UTC  ·  "
                               f"{finding.source}  ·  {finding.severity.value}")
                    st.markdown(f"**{finding.title}**")
                    st.write(finding.description)
                    st.caption(f"Resource: {finding.resource or 'unknown'}  ·  Event ID: {finding.finding_id}")
                    with st.expander("Source evidence (raw)"):
                        st.json(finding.raw_evidence)
        with mapping:
            st.markdown("#### Explainable risk score")
            st.progress(assessment.score / 100)
            st.caption("Heuristic prioritization only. It is not an AI confidence, probability of compromise, or validated CVSS metric.")
            for factor in assessment.factors:
                with st.container(border=True):
                    x, y = st.columns([4, 1])
                    x.write(f"**{factor.label}**")
                    y.write(f"+{factor.points}")
                    st.caption(factor.rationale)
            st.markdown("#### MITRE ATT&CK technique candidates")
            if not technique_matches:
                st.info("No supported evidence-backed technique match. A vulnerability or misconfiguration is not automatically an attack.")
            for m in technique_matches:
                with st.container(border=True):
                    st.markdown(f"**[{m.technique_id} — {m.name}]({m.url})** · {m.tactic}")
                    st.caption(m.evidence)
            st.caption("Mappings are fixed local rules, not LLM classifications. They indicate observed behaviour only, not attacker intent.")
        with audit:
            st.caption("Local audit log: display labels are self-entered and NOT authenticated users.")
            if not activity:
                st.info("No analyst actions yet. Record a case status, assignment or investigation note.")
            for event in activity:
                with st.container(border=True):
                    st.markdown(f"**{event['action'].replace('_', ' ').title()}** · {event['actor']}")
                    st.caption(event["occurred_at"] + " UTC")
                    if event["previous_value"] or event["new_value"]:
                        st.text(f"{event['previous_value'] or 'Unassigned'}  →  {event['new_value'] or 'Unassigned'}")
                    if event["note"]:
                        st.write(event["note"])
            st.download_button(
                "Export case report (JSON)",
                data=_export_report(inc, linked, activity),
                file_name=f"cloudsentinel-case-{inc.incident_id}.json",
                mime="application/json", key=f"report-{inc.incident_id}",
            )
            st.caption("Export contains IDs and analyst comments; treat it as internal security data.")
    with right:
        with st.container(border=True):
            st.markdown("#### Analyst workflow")
            st.caption("Local prototype only — no login, RBAC or verified user attribution. Do not expose publicly.")
            statuses = list(WORKFLOW_STATUSES)
            if inc.status in {Status.RESOLVED, Status.FALSE_POSITIVE}:
                statuses = [inc.status, Status.INVESTIGATING]
            elif inc.status == Status.INVESTIGATING:
                statuses = [Status.INVESTIGATING, Status.RESOLVED, Status.FALSE_POSITIVE]
            if inc.status not in statuses:
                statuses.insert(0, inc.status)  # backward-compatible 'Analyzed'
            with st.form(f"case-edit-{inc.incident_id}"):
                actor = st.text_input("Your analyst label", value="local-analyst",
                                      max_chars=80, help="Self-entered; not verified")
                assignee = st.text_input("Assigned to", value=inc.assignee, max_chars=80)
                new_status = st.selectbox("Case status", statuses,
                                          index=statuses.index(inc.status),
                                          format_func=lambda x: x.value)
                note = st.text_area("Reason / investigation note", max_chars=2000,
                                    placeholder="Describe evidence checked and why this decision was made.")
                st.caption("A reason is required to mark a case Resolved or False Positive.")
                submitted = st.form_submit_button("Save investigation update", type="primary",
                                                  use_container_width=True)
                if submitted:
                    try:
                        db.update_incident_workflow(inc.incident_id, status=new_status,
                                                    assignee=assignee, actor=actor, note=note)
                    except ValueError as exc:
                        st.error(str(exc))
                    else:
                        st.toast("Investigation saved to local audit log.")
                        st.rerun(scope="fragment")


@st.fragment
def investigation_workbench() -> None:
    incidents = db.get_incidents()
    all_findings = {f.finding_id: f for f in db.get_findings()}

    if not incidents:
        st.info("No incidents found. To build a self-contained investigation demo, run `python -m mock_data.generate` in WSL2.")
        if os.environ.get("CLOUDSENTINEL_DEMO") == "1":
            if st.button("Generate synthetic investigation cases"):
                from mock_data.generate import seed
                seed(db)
                st.rerun(scope="fragment")
        return

    new_count = sum(inc.status == Status.NEW for inc in incidents)
    active_count = sum(inc.status == Status.INVESTIGATING for inc in incidents)
    done_count = sum(inc.status in {Status.RESOLVED, Status.FALSE_POSITIVE} for inc in incidents)
    priority_count = sum(score_incident(inc, _linked(inc, all_findings)).priority in
                         {Severity.CRITICAL, Severity.HIGH} for inc in incidents
                         if inc.status not in {Status.RESOLVED, Status.FALSE_POSITIVE})
    cols = st.columns(4)
    for col, label, number in zip(cols,
                                  ("Total cases", "New", "Investigating", "Open high priority"),
                                  (len(incidents), new_count, active_count, priority_count)):
        col.metric(label, number)
    st.caption(f"{done_count} case(s) closed  ·  Automated correlation is advisory  ·  Local SQLite workspace")

    fa, fb, fc = st.columns([1.6, 1.5, 2.0])
    with fa:
        filter_status = st.multiselect("Case status", [x.value for x in Status],
                                        key="inc_filter_status")
    with fb:
        filter_sev = st.multiselect("Source severity", [x.value for x in Severity],
                                     key="inc_filter_severity")
    with fc:
        needle = st.text_input("Find case", placeholder="Title, resource or case ID",
                               key="inc_filter_query").lower().strip()
    filtered = [i for i in incidents
                if (not filter_status or i.status.value in filter_status)
                and (not filter_sev or i.severity.value in filter_sev)
                and (not needle or needle in (i.title + " " + i.linked_entity + " " + i.incident_id).lower())]
    st.caption(f"Showing {len(filtered)} of {len(incidents)} case(s)")
    if not filtered:
        st.info("No cases match the current filters.")
        return

    case_rows = []
    for inc in filtered:
        linked = _linked(inc, all_findings)
        case_rows.append({
            "Case ID": inc.incident_id[:10], "Case": inc.title[:74],
            "Triage": score_incident(inc, linked).score,
            "Severity": inc.severity.value, "Status": inc.status.value,
            "Assignee": inc.assignee or "Unassigned", "Findings": len(linked),
            "Demo": "Yes" if _is_demo(linked) else "No",
        })
    with st.container(border=True):
        st.dataframe(case_rows, hide_index=True, use_container_width=True)
    choices = {i.incident_id: i for i in filtered}
    selected = st.selectbox("Inspect case", list(choices),
                            format_func=lambda case_id: f"{choices[case_id].title[:85]}  ·  {case_id[:10]}",
                            key="inc_selected_case")
    if selected:
        _case_detail(choices[selected], all_findings)


investigation_workbench()
