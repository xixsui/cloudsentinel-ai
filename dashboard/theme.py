"""
Global theme + reusable UI primitives.

Professional SOC console aesthetic — text + outline icons, no emoji, tight
spacing, neutral palette with semantic colour accents only for severity and
status. Sidebar-based navigation (Streamlit native), customised below.
"""

from __future__ import annotations

from typing import Optional

import streamlit as st


# ---------------------------------------------------------------------------
# Design tokens
# ---------------------------------------------------------------------------
from dashboard.palette import SEVERITY_COLORS

SEVERITY_BG = {
    "Critical": "rgba(251,113,133,0.14)",
    "High":     "rgba(251,146,60,0.13)",
    "Medium":   "rgba(251,191,36,0.13)",
    "Low":      "rgba(96,165,250,0.13)",
    "Informational": "rgba(148,163,184,0.12)",
}

STATUS_COLORS = {
    "ok":      "#34D399",
    "warning": "#FBBF24",
    "error":   "#FB7185",
    "neutral": "#94A3B8",
}

# Tabler outline icon names per nav target. NO emoji.
NAV_ICONS = {
    "Home":              "ti-dashboard",
    "Misconfigurations": "ti-shield-search",
    "Threat Alerts":     "ti-alert-triangle",
    "Incidents":         "ti-affiliate",
    "Settings":          "ti-settings",
}


# ---------------------------------------------------------------------------
# Global CSS (kept lean; pure aesthetic — no behavioural changes)
# ---------------------------------------------------------------------------
_CSS = """
<!-- Tabler outline icon webfont -->
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@2.47.0/tabler-icons.min.css">

<style>
/* ===== Layout density ===== */
.block-container {
    padding-top: 1.25rem !important;
    padding-bottom: 2rem !important;
    max-width: 1400px;
}
#MainMenu { visibility: hidden; }
footer { visibility: hidden; }
[data-testid="stAppDeployButton"] { display: none; }
[data-testid="stDecoration"] { display: none; }

/* ===== Sidebar polish ===== */
section[data-testid="stSidebar"] {
    background: #0F192B;
    border-right: 1px solid rgba(148,163,184,0.14);
}
section[data-testid="stSidebar"] > div:first-child {
    padding-top: 1rem;
}
section[data-testid="stSidebar"] .stRadio label {
    font-size: 0.86rem;
}
/* Make built-in page nav links denser + monoish */
[data-testid="stSidebarNav"] a {
    padding: 5px 12px !important;
    font-size: 0.86rem !important;
    font-weight: 500;
    border-radius: 4px !important;
}
[data-testid="stSidebarNav"] a[aria-current="page"] {
    background: rgba(59,130,246,0.20) !important;
    color: #93C5FD !important;
}

/* ===== Typography ===== */
h1, h2, h3, h4 {
    letter-spacing: -0.01em;
    font-weight: 500;
}
h1 { font-size: 1.55rem; margin: 0 0 0.25rem; }
h2 { font-size: 1.20rem; margin: 0.5rem 0 0.5rem; }
h3 { font-size: 1.00rem; margin: 0.4rem 0 0.4rem; }

/* ===== Metrics ===== */
[data-testid="stMetricValue"] {
    font-size: 1.55rem;
    font-weight: 500;
    letter-spacing: -0.01em;
}
[data-testid="stMetricLabel"] {
    font-size: 0.74rem;
    opacity: 0.65;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

/* ===== Bordered containers ===== */
[data-testid="stVerticalBlockBorderWrapper"] {
    border-radius: 8px;
}

/* ===== Tabs (flatter) ===== */
.stTabs [data-baseweb="tab-list"] {
    gap: 2px;
    border-bottom: 1px solid rgba(128,128,128,0.15);
}
.stTabs [data-baseweb="tab"] {
    background: transparent !important;
    padding: 0.45rem 0.85rem !important;
    font-size: 0.86rem;
    font-weight: 500;
}

/* ===== Buttons (subtle, professional) ===== */
.stButton button {
    font-size: 0.84rem;
    font-weight: 500;
    border-radius: 5px;
    transition: background 0.12s ease;
}
.stButton button[kind="primary"] {
    background: #2563EB;
    border: 1px solid #60A5FA;
}
.stButton button[kind="primary"]:hover {
    background: #1D4ED8;
}

/* ===== Data tables ===== */
.stDataFrame {
    font-size: 0.84rem;
}

/* ===== Code / mono ===== */
code {
    font-family: 'JetBrains Mono','Fira Code','SF Mono','Consolas',monospace !important;
    font-size: 0.80rem;
    padding: 1px 5px;
    border-radius: 3px;
    background: rgba(128,128,128,0.10);
}

/* ===== Caption ===== */
[data-testid="stCaptionContainer"] {
    opacity: 0.6;
    font-size: 0.78rem;
}

/* ===== Sidebar brand header ===== */
.soc-brand {
    display: flex;
    align-items: center;
    gap: 9px;
    padding: 0 0 14px;
    border-bottom: 1px solid rgba(148,163,184,0.14);
    margin-bottom: 14px;
}
.soc-brand-mark {
    width: 28px; height: 28px;
    background: #2563EB;
    border-radius: 5px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: white;
    font-size: 16px;
}
.soc-brand-name {
    font-size: 0.92rem;
    font-weight: 600;
    line-height: 1.1;
    letter-spacing: -0.01em;
}
.soc-brand-sub {
    font-size: 0.70rem;
    opacity: 0.55;
    line-height: 1.2;
    margin-top: 1px;
}

/* ===== Status indicators in sidebar ===== */
.soc-side-status {
    margin-top: 18px;
    padding: 10px 12px;
    background: rgba(148,163,184,0.07);
    border-radius: 6px;
    font-size: 0.78rem;
}
.soc-side-status-title {
    font-size: 0.68rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    opacity: 0.55;
    margin-bottom: 6px;
}
.soc-side-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 3px 0;
    font-size: 0.78rem;
}

/* ===== Status pills ===== */
.soc-pill {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 2px 8px;
    border-radius: 999px;
    font-size: 0.72rem;
    font-weight: 500;
    border: 1px solid rgba(148,163,184,0.25);
    background: rgba(148,163,184,0.07);
    white-space: nowrap;
}
.soc-pill-dot {
    width: 6px; height: 6px;
    border-radius: 50%;
    flex-shrink: 0;
}

/* ===== Severity chips ===== */
.soc-sev {
    display: inline-block;
    padding: 1px 8px;
    border-radius: 3px;
    font-size: 0.70rem;
    font-weight: 600;
    letter-spacing: 0.02em;
    text-transform: uppercase;
    line-height: 1.5;
}

/* ===== Section card ===== */
.soc-card {
    border: 1px solid rgba(148,163,184,0.20);
    border-radius: 8px;
    padding: 0.85rem 1rem;
    margin-bottom: 0.5rem;
}
.soc-card-title {
    font-size: 0.74rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    opacity: 0.6;
    margin-bottom: 0.5rem;
    display: flex;
    align-items: center;
    gap: 5px;
}

/* ===== Posture score ===== */
.soc-score {
    text-align: center;
    padding: 0.3rem 0 0.6rem;
}
.soc-score-num {
    font-size: 2.6rem;
    font-weight: 600;
    line-height: 1;
    letter-spacing: -0.02em;
}
.soc-score-label {
    font-size: 0.66rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    opacity: 0.55;
    margin-top: 6px;
}

/* ===== Page header ===== */
.soc-page-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 0.75rem;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid rgba(148,163,184,0.14);
}
.soc-page-title {
    display: flex;
    align-items: baseline;
    gap: 10px;
}
.soc-page-title h1 {
    margin: 0;
}
.soc-page-subtitle {
    font-size: 0.82rem;
    opacity: 0.6;
}

/* ===== Tabler icons inline sizing ===== */
.ti {
    vertical-align: -2px;
    font-size: 1.05em;
}
</style>
"""


# All pages inherit the app's default dark palette from .streamlit/config.toml.
# This extra styling keeps the navigation and custom HTML coherent with native widgets.
_DARK_EXTRA = """
<style>
:root { color-scheme: dark; }
body, [data-testid="stAppViewContainer"] { background-color: #0B1220; color: #E5EDF7; }
[data-testid="stHeader"] { background-color: rgba(11,18,32,0.92); }
section[data-testid="stSidebar"] { background: #0F192B; border-right: 1px solid #23314B; }
[data-testid="stSidebarNav"] { padding-top: 0.4rem; }
[data-testid="stSidebarNav"] a { color: #C2D0E5; border-radius: 8px !important; }
[data-testid="stSidebarNav"] a:hover { background: #1E2D45; color: #fff; }
[data-testid="stSidebarNav"] a[aria-current="page"] { background: #223956 !important; color: #93C5FD !important; }
[data-testid="stMetric"] { background: linear-gradient(160deg,#17243A,#121E30); border:1px solid #263854; border-radius: 12px; padding: 14px 16px; min-height: 96px; }
[data-testid="stMetricLabel"] { color: #A5B7D1; font-weight: 600; }
[data-testid="stMetricValue"] { color: #EEF5FF; font-size: 1.55rem; font-weight: 650; }
[data-testid="stVerticalBlockBorderWrapper"] { border:1px solid #283753; border-radius: 12px; background: #121E30; }
[data-testid="stExpander"] { border-color: #30415A; border-radius: 10px; }
[data-testid="stAlert"] { border-radius: 10px; }
[data-testid="stDataFrame"] { border: 1px solid #2A3C56; border-radius: 10px; }
.stButton button { border-radius: 8px; min-height: 2.45rem; }
.stButton button[kind="primary"] { background: #2563EB; border: 1px solid #3B82F6; color: #fff; font-weight: 650; }
.stButton button[kind="primary"]:hover { background: #1D4ED8; border-color: #93C5FD; }
.soc-brand { border-bottom-color: #243550; padding: 4px 0 16px; }
.soc-brand-mark { background: linear-gradient(135deg, #2563EB, #0891B2); border-radius: 9px; width: 35px; height: 35px; }
.soc-brand-name { color: #F2F7FF; font-size: 1rem; font-weight: 720; }
.soc-brand-sub { color: #B1C2DA; opacity: 1; }
.soc-side-status { background: #17253B; border: 1px solid #293955; padding: 12px; border-radius: 10px; }
.soc-side-status-title { opacity: 1; color:#A6B9D3; }
.soc-pill { background: #16273D; border-color: #354864; color: #CDDCEF; }
.soc-card { background:#121F33; border:1px solid #253754; border-radius: 11px; padding: 1rem; }
.soc-card-title { color: #CBD9EE; }
.soc-page-header { border-bottom-color: #263954; padding: 12px 0 18px; }
.soc-page-title h1 { font-size: 1.75rem; font-weight: 730; letter-spacing: -0.035em; color: #EEF5FF; }
.soc-page-subtitle { opacity: 1; color: #99AEC9; font-size: 0.85rem; }
.cs-eyebrow { color: #90A7C4; font-size: .69rem; letter-spacing: .18em; font-weight: 750; margin: 0 0 .85rem 0; }
.cs-eyebrow-dot { display: inline-block; width: 6px; height: 6px; margin: 0 4px 1px 9px; border-radius: 50%; background:#34D399; box-shadow: 0 0 9px #34D39988; }
.cs-hero { border: 1px solid #2A4163; border-radius: 14px; background:linear-gradient(110deg,#1B3154,#142339 72%); padding:20px 24px; margin-bottom: 20px; }
.cs-hero-title { font-size: 1.2rem; font-weight: 700; margin-bottom: 6px; color:#F2F7FF; }
.cs-hero-sub { font-size:.86rem; color:#B3C7E1; max-width: 720px; }
.cs-hero-chip { font-size: .7rem; padding: 5px 9px; background: #163D40; border:1px solid #146B65; color:#86EFAC; border-radius: 20px; font-weight: 650; }
</style>
"""


def apply_theme() -> None:
    """Inject the global CSS. Call once at the top of every page."""
    st.markdown(_CSS + _DARK_EXTRA, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Sidebar — brand, status pills, version footer
# ---------------------------------------------------------------------------
def render_sidebar(
    *, source_status: Optional[dict] = None,
    last_sync: Optional[str] = None,
    provider_label: Optional[str] = None,
) -> None:
    """Render the brand header + system status block in the sidebar.

    Streamlit auto-renders page navigation links above this; we render extra
    context below them.
    """
    with st.sidebar:
        st.markdown(
            '<div class="soc-brand">'
            '<div class="soc-brand-mark"><i class="ti ti-shield-half-filled"></i></div>'
            '<div>'
            '<div class="soc-brand-name">CloudSentinel AI</div>'
            '<div class="soc-brand-sub">Decision-support console</div>'
            '</div></div>',
            unsafe_allow_html=True,
        )

        if source_status:
            rows = []
            for name, state in source_status.items():
                colour = STATUS_COLORS.get(state, STATUS_COLORS["neutral"])
                rows.append(
                    f'<div class="soc-side-row"><span>{name}</span>'
                    f'<span class="soc-pill"><span class="soc-pill-dot" '
                    f'style="background:{colour}"></span>{state}</span></div>'
                )
            st.markdown(
                '<div class="soc-side-status">'
                '<div class="soc-side-status-title">Data in Workspace</div>'
                + "".join(rows) + "</div>",
                unsafe_allow_html=True,
            )

        if provider_label or last_sync:
            extras = []
            if provider_label:
                extras.append(
                    f'<div class="soc-side-row"><span>AI Backend</span>'
                    f'<span style="font-weight:500">{provider_label}</span></div>'
                )
            if last_sync:
                extras.append(
                    f'<div class="soc-side-row"><span>Last sync</span>'
                    f'<span style="font-weight:500">{last_sync}</span></div>'
                )
            st.markdown(
                '<div class="soc-side-status">'
                '<div class="soc-side-status-title">System</div>'
                + "".join(extras) + "</div>",
                unsafe_allow_html=True,
            )


# ---------------------------------------------------------------------------
# Page header (replaces the big h1 + caption pattern)
# ---------------------------------------------------------------------------
def page_title(
    title: str, *, subtitle: str = "",
    icon: Optional[str] = None,
    right_widget: Optional[str] = None,
) -> None:
    """
    Render the page's top section: icon + title on the left, optional widget on the right.
    `icon` is a tabler class name (e.g. "ti-dashboard"). No emoji.
    """
    icon_html = (
        f'<i class="ti {icon}" style="font-size:1.6rem;opacity:0.7"></i>'
        if icon else ""
    )
    subtitle_html = (
        f'<span class="soc-page-subtitle">{subtitle}</span>'
        if subtitle else ""
    )
    right_html = right_widget or ""

    st.markdown(
        f'<div class="soc-page-header">'
        f'<div class="soc-page-title">{icon_html}<h1>{title}</h1>{subtitle_html}</div>'
        f'<div>{right_html}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Reusable UI primitives
# ---------------------------------------------------------------------------
def severity_chip(severity: str) -> str:
    """HTML for a severity chip (SOC-style flat square pill)."""
    color = SEVERITY_COLORS.get(severity, "#5F5E5A")
    bg = SEVERITY_BG.get(severity, "rgba(95,94,90,0.10)")
    return (
        f'<span class="soc-sev" style="color:{color};background:{bg};">'
        f'{severity}</span>'
    )


def status_pill(label: str, status: str = "neutral") -> str:
    color = STATUS_COLORS.get(status, STATUS_COLORS["neutral"])
    return (
        f'<span class="soc-pill">'
        f'<span class="soc-pill-dot" style="background:{color}"></span>'
        f'{label}</span>'
    )


def icon(name: str, *, size: str = "1em") -> str:
    """Tabler outline icon as inline HTML."""
    return f'<i class="ti {name}" style="font-size:{size}"></i>'


def card_open(title: str, *, icon_name: Optional[str] = None) -> None:
    """Start a styled section card. Pair with card_close()."""
    icon_html = (
        f'<i class="ti {icon_name}" style="font-size:0.95em;opacity:0.8;"></i>'
        if icon_name else ""
    )
    st.markdown(
        f'<div class="soc-card">'
        f'<div class="soc-card-title">{icon_html}{title}</div>',
        unsafe_allow_html=True,
    )


def card_close() -> None:
    st.markdown("</div>", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Time-range selector
# ---------------------------------------------------------------------------
TIME_RANGES = {
    "Last 15 minutes": "15m",
    "Last 1 hour": "1h",
    "Last 4 hours": "4h",
    "Last 24 hours": "24h",
    "Last 7 days": "7d",
    "Last 30 days": "30d",
    "All time": None,
}


def time_range_selector(key: str = "global_time_range") -> Optional[str]:
    if key not in st.session_state:
        st.session_state[key] = "Last 24 hours"
    label = st.selectbox(
        "Time range",
        list(TIME_RANGES.keys()),
        index=list(TIME_RANGES.keys()).index(st.session_state[key]),
        key=f"{key}_select",
        label_visibility="collapsed",
    )
    st.session_state[key] = label
    return TIME_RANGES[label]
