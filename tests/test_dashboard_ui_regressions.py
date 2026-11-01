"""Regressions for Overview visuals and AI-inspector fragment isolation.

Plot construction is pure; no cloud account, Streamlit session, or browser needed.
"""
from __future__ import annotations

import ast
from pathlib import Path

from dashboard.overview_charts import CHART_HEIGHT, severity_chart, sources_chart, type_chart

ROOT = Path(__file__).resolve().parents[1]


def test_overview_cards_have_same_plot_height_and_transparent_background():
    charts = (
        severity_chart({"High": 4, "Critical": 2}),
        type_chart({"misconfig": 5, "threat": 1}),
        sources_chart({"prowler": 5, "wazuh": 1})[0],
    )
    for fig in charts:
        assert fig.layout.height == CHART_HEIGHT
        assert fig.layout.paper_bgcolor == "rgba(0,0,0,0)"
        assert fig.layout.plot_bgcolor == "rgba(0,0,0,0)"


def test_severity_has_deterministic_order_and_semantic_colours():
    fig = severity_chart({"Medium": 5, "Critical": 1, "Low": 3, "High": 2})
    bar = fig.data[0]
    assert list(bar.y) == ["Critical", "High", "Medium", "Low"]
    assert list(bar.x) == [1, 2, 5, 3]
    assert len(set(bar.marker.color)) == 4
    assert fig.layout.yaxis.autorange == "reversed"


def test_sources_limit_and_accessible_hover_preserve_original_names():
    counts = {f"wazuh-long-source-{i}-original": i + 1 for i in range(9)}
    fig, omitted = sources_chart(counts)
    assert omitted == 3
    assert list(fig.data[0].x) == [9, 8, 7, 6, 5, 4]
    assert len(fig.data[0].customdata) == 6
    assert all(len(label) <= 24 for label in fig.data[0].y)
    assert fig.data[0].customdata[0] == "wazuh-long-source-8-original"


def test_type_donut_shows_only_real_categories_and_total():
    fig = type_chart({"misconfig": 8, "threat": 2, "correlated": 0})
    assert list(fig.data[0].values) == [8, 2]
    assert list(fig.data[0].labels) == ["Misconfig", "Threat"]
    assert fig.layout.annotations[0].text == "10"


def test_streamlit_chart_cards_use_native_container_instead_of_html_wrappers():
    app = (ROOT / "dashboard/app.py").read_text(encoding="utf-8")
    charts_section = app.split("# Security summary charts", 1)[1].split("# AWS Inventory + Top Risks", 1)[0]
    assert charts_section.count("with st.container(border=True)") == 3
    assert "card_open(" not in charts_section
    assert "card_close(" not in charts_section


def test_ai_actions_use_fragment_only_reruns():
    """v0.5 delegates misconfig UI to a workbench INSIDE the existing fragment."""
    module = ast.parse((ROOT / "dashboard/findings_browser.py").read_text(encoding="utf-8"))
    funcs = {node.name: node for node in module.body if isinstance(node, ast.FunctionDef)}
    for name in ("_render_finding_expander", "_render_finding_card"):
        fragment = funcs[name]
        assert any(isinstance(deco, ast.Attribute) and deco.attr == "fragment"
                   for deco in fragment.decorator_list)
    details = (ROOT / "dashboard/findings_browser.py").read_text(encoding="utf-8")
    workbench = (ROOT / "dashboard/remediation_ui.py").read_text(encoding="utf-8")
    assert "render_finding_workbench(db, f" in details
    assert 'st.rerun(scope="fragment")' in workbench
    assert 'disabled=not ai_ready' in workbench


def test_scan_center_shows_persistent_scan_status():
    scanner = (ROOT / "dashboard/pages/5_Scan_Center.py").read_text(encoding="utf-8")
    assert 'st.session_state["last_scan_job_id"] = job_id' in scanner
    assert 'st.success(f"' in scanner
    assert 'st.success("Demo findings generated."' not in scanner
