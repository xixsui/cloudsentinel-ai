"""CSPM remediation case queue — no AWS mutation."""
from __future__ import annotations
import sys
from pathlib import Path
import streamlit as st
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
from ai_module.remediation_tracker import RemediationTracker
from ai_module.models import FindingType
from dashboard.common import get_db
from dashboard.theme import apply_theme, page_title, render_sidebar
from config import user_settings

st.set_page_config(page_title="Remediation Tracker | CloudSentinel AI", layout="wide")
apply_theme()
db = get_db()
settings = user_settings.load()
sources = db.distinct_values("source") or []
render_sidebar(source_status={"Prowler": "ok" if "prowler" in sources else "warning", "Wazuh": "optional", "VPC Flow": "optional"},
               provider_label=settings.get("active_provider", "gemini").capitalize())
page_title("Remediation Tracker", subtitle="Engineer-controlled changes, historical scan evidence, and verified outcomes.", icon="ti-clipboard-check")
st.info("This page tracks engineer decisions locally. No AWS configuration is changed. Only a fresh matching Prowler PASS can mark a case Verified.")
tracker = RemediationTracker(db.db_path)
all_findings = {f.finding_id:f for f in db.get_findings(finding_type=FindingType.MISCONFIG)}
cases = tracker.list_cases()
col1,col2,col3,col4 = st.columns(4)
for col, title, states in [(col1,"Active",{"Open","In Progress"}), (col2,"Pending verification",{"Pending Verification"}),
                           (col3,"Verified",{"Verified"}), (col4,"Accepted / False positive",{"Accepted Risk","False Positive"})]:
    col.metric(title, sum(1 for c in cases if c['state'] in states))
needle = st.text_input("Search tracked findings", placeholder="Find by check name or resource")
filter_state = st.multiselect("Status", ["Open","In Progress","Pending Verification","Verified","Accepted Risk","False Positive"])
items = []
for c in cases:
    f=all_findings.get(c['finding_id'])
    if not f:
        continue
    if filter_state and c['state'] not in filter_state:
        continue
    if needle and needle.lower() not in (f.title + " " + f.resource + " " + f.check_id).lower():
        continue
    items.append({"Finding":f.title,"Severity":f.severity.value,"Check":f.check_id,
                  "Resource":f.resource,"Engineer":c['assignee'] or "Unassigned", "Status":c['state'],
                  "Updated":c['updated_at'],"Finding ID":f.finding_id})
if items:
    st.dataframe(items,use_container_width=True,hide_index=True)
else:
    st.info("No tracked items yet. Open Misconfigurations, expand a finding, and use the Remediation Tracking tab to begin.")
st.page_link("pages/1_Misconfigurations.py",label="Go to Misconfigurations →",icon="🔎")
st.caption("Historical findings remain visible even after a case is marked Verified; the scan ledger and verification state are separate from source observations.")
