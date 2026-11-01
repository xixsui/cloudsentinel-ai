"""
Shared helpers for the Streamlit dashboard.

Most visual primitives now live in `theme.py` — this file keeps the DB handle
and a couple of legacy helpers used by the findings browser.
"""

from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ai_module.database import Database  # noqa: E402

# Re-export from theme.py so older code keeps working
from dashboard.theme import (  # noqa: E402, F401
    SEVERITY_COLORS,
    severity_chip as severity_badge,
)

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]

STATUS_COLORS = {
    "New": "#64748b",
    "Analyzed": "#3b82f6",
    "Investigating": "#06b6d4",
    "Resolved": "#16a34a",
    "False Positive": "#9333ea",
}


@st.cache_resource
def get_db() -> Database:
    return Database()


def status_badge(status: str) -> str:
    color = STATUS_COLORS.get(status, "#64748b")
    return (
        f"<span style='background:{color}1f;color:{color};padding:2px 9px;"
        f"border-radius:999px;font-size:0.72rem;font-weight:600;"
        f"text-transform:uppercase;letter-spacing:0.01em;'>{status}</span>"
    )


def page_header(title: str, subtitle: str = "") -> None:
    """Legacy helper — pages now use top_nav + their own h1."""
    st.markdown(f"<h1>{title}</h1>", unsafe_allow_html=True)
    if subtitle:
        st.markdown(f"<p style='opacity:0.65;margin:0 0 1rem;'>{subtitle}</p>",
                    unsafe_allow_html=True)


def severity_sort_key(sev: str) -> int:
    try:
        return SEVERITY_ORDER.index(sev)
    except ValueError:
        return len(SEVERITY_ORDER)
