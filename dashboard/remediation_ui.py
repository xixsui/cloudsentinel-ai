"""Four-step engineer-led CSPM finding workbench. No automatic AWS changes."""
from __future__ import annotations

import json
import streamlit as st

from ai_module.analyzer import AIAnalyzer
from ai_module.posture import assess_finding
from ai_module.remediation_tracker import RemediationTracker, STATES
from ai_module.database import Database
from ai_module.models import Finding


def render_finding_workbench(db: Database, finding: Finding, *, ai_ready: bool, prefix: str) -> None:
    """Called from a Streamlit fragment (only this finding refreshes)."""
    assessment = assess_finding(finding)
    tracker = RemediationTracker(db.db_path)
    case = tracker.get(finding.finding_id)
    analysis = db.get_analysis(finding.finding_id)
    overview, security, advisor, tracking = st.tabs([
        "Overview & Evidence", "Weakness & ATT&CK", "AI Remediation", "Remediation Tracking",
    ])
    with overview:
        if finding.raw_evidence.get("synthetic_demo"):
            st.info("SYNTHETIC DEMO finding — no real cloud environment was scanned.")
        else:
            st.caption("Historical scan evidence. It is not a live view of the AWS resource.")
        st.write(finding.description or "No check description supplied.")
        c1, c2 = st.columns(2)
        with c1:
            st.caption(f"Account: {finding.account_id or 'unknown'} · Region: {finding.region or 'unknown'}")
        with c2:
            st.caption(f"Check ID: {finding.check_id or 'unknown'} · Recorded (UTC): {finding.timestamp.isoformat()}")
        with st.expander("Original Prowler evidence and compliance references"):
            st.json(finding.raw_evidence)
            if finding.compliance:
                st.write("Compliance references supplied by scanner:")
                st.write(", ".join(finding.compliance[:30]))
    with security:
        st.markdown("#### Security weakness")
        st.write(f"**Category:** {assessment.category}")
        if assessment.weakness_id:
            st.markdown(f"**Potential CWE:** [{assessment.weakness_id} — {assessment.weakness_name}]({assessment.cwe_url})")
            st.caption("Candidate weakness classification. An engineer must review applicability; this is not a CVE.")
        else:
            st.caption("CWE: no defensible mapping for this check alone. CVE: not established.")
        st.markdown("#### MITRE ATT&CK — potential attacker technique")
        if assessment.technique_id:
            st.markdown(f"**[{assessment.technique_id} — {assessment.technique_name}]({assessment.attack_url})** · {assessment.technique_tactic}")
        else:
            st.info("No supported ATT&CK technique mapping from this configuration finding alone.")
        st.write(assessment.conditions)
        st.caption(f"Rule rationale: {assessment.mapping_basis}")
        st.warning("Exposure ≠ exploitation ≠ observed attack. No malicious activity or numerical attack probability is inferred from Prowler alone.", icon="⚠️")
    with advisor:
        st.markdown("#### Engineer-reviewed remediation")
        st.caption("The following baseline steps come from local reviewed rules, not an AI response.")
        for number, step in enumerate(assessment.remediation, 1):
            st.write(f"{number}. {step}")
        st.markdown("**Verification checklist**")
        st.write(assessment.verification)
        original = finding.raw_evidence.get("remediation_refs") or []
        if original:
            st.caption("Original scanner remediation references:")
            for u in original:
                if isinstance(u, str) and u.startswith("https://"):
                    st.write(u)
        st.divider()
        st.markdown("#### AI Remediation Advisor")
        st.caption("The LLM can make mistakes. Review recommendations and do not execute unverified commands. An explicit click may send finding metadata to your selected AI provider.")
        if analysis:
            st.write("**AI explanation:**", analysis.explanation)
            if analysis.attack_scenario:
                st.write("**Potential scenario (not an observed attack):**", analysis.attack_scenario)
            st.write(f"**Suggested priority:** {analysis.risk_priority.value} — {analysis.risk_justification}")
            if analysis.mitigation_steps:
                st.write("**AI proposed steps (review before applying):**")
                for i, step in enumerate(analysis.mitigation_steps, 1):
                    st.write(f"{i}. {step}")
            st.caption(f"Provider model: {analysis.model_used or 'unknown'} · Validate before use")
        elif not ai_ready:
            st.info("AI provider not configured. You can still inspect deterministic recommendations and track remediation. Configure a provider key in Settings to generate AI guidance.")
        if st.button("Regenerate AI guidance" if analysis else "Generate AI guidance",
                     key=f"{prefix}_advisor_{finding.finding_id}", disabled=not ai_ready):
            with st.spinner("Requesting advisory analysis…"):
                try:
                    AIAnalyzer(db).analyze_finding(finding, use_cache=False)
                except Exception as exc:
                    st.error(f"AI provider failed: {type(exc).__name__}. Check provider configuration and network access.")
                else:
                    st.rerun(scope="fragment")
    with tracking:
        st.markdown("#### Remediation progress")
        st.write(f"**Status:** {case['state']}  ·  **Assigned engineer:** {case['assignee'] or 'Unassigned'}")
        if case.get("verified_scan_id"):
            st.success("Verified by a newer independent Prowler PASS for this exact finding ID.")
            st.caption(case.get("verification_evidence", ""))
        else:
            st.caption("A manual fix claim is not independently verified. Use Pending Verification and run a new scan after the fix.")
        options = [state for state in STATES if state != "Verified"]
        if case["state"] == "Verified":
            options = ["In Progress"]
        with st.form(key=f"{prefix}_remediation_form_{finding.finding_id}"):
            actor = st.text_input("Engineer label (local, not authenticated)", value="local-engineer", max_chars=80)
            assignee = st.text_input("Assigned to", value=case["assignee"], max_chars=80)
            state = st.selectbox("Update state", options, index=options.index(case["state"]) if case["state"] in options else 0)
            note = st.text_area("Remediation or review note", max_chars=2000,
                                placeholder="What change did you perform? Which setting? Record evidence and approvals.")
            submitted = st.form_submit_button("Save remediation update", type="primary")
        if submitted:
            try:
                tracker.update(finding.finding_id, state=state, assignee=assignee, actor=actor, note=note)
            except ValueError as exc:
                st.error(str(exc))
            else:
                st.toast("Remediation update saved locally")
                st.rerun(scope="fragment")
        with st.expander("Remediation audit trail", expanded=False):
            history = tracker.activity(finding.finding_id)
            if not history:
                st.caption("No engineer updates recorded yet.")
            for h in history:
                st.write(f"**{h['action']}** · {h['actor']} · {h['occurred_at']}")
                st.caption(f"{h['previous_state']} → {h['new_state']} · {h['note']}")
        st.download_button("Export finding & remediation summary (JSON)",
            data=json.dumps({"finding_id": finding.finding_id, "check_id": finding.check_id,
                "resource": finding.resource, "scan_timestamp": finding.timestamp.isoformat(),
                "misconfiguration": finding.title, "cwe_candidate": assessment.weakness_id,
                "potential_attack_technique": assessment.technique_id, "attack_observed": False,
                "current_state": case, "audit_log": tracker.activity(finding.finding_id),
                "warning": "Historical/security-sensitive data; no evidence of actual compromise."}, indent=2),
            file_name=f"cloudsentinel-remediation-{finding.finding_id}.json", mime="application/json",
            key=f"{prefix}_export_{finding.finding_id}")
