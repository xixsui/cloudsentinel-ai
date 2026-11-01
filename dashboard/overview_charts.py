"""Accessible, dark-theme Plotly figures for the Overview page.

Figures are kept independent from Streamlit layout so they can be validated
without rendering a browser. Native ``st.container(border=True)`` owns their
actual UI cards; HTML strings cannot be used to wrap Streamlit widgets.
"""
from __future__ import annotations

import plotly.graph_objects as go

from dashboard.palette import SEVERITY_COLORS

SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Informational")
TYPE_LABELS = {"misconfig": "Misconfig", "threat": "Threat", "correlated": "Incident"}
TYPE_COLORS = ("#60A5FA", "#FB923C", "#34D399", "#A78BFA")
TEXT_COLOR = "#CBD5E1"
GRID_COLOR = "rgba(148,163,184,0.13)"
CHART_HEIGHT = 246


def _base(fig: go.Figure, height: int = CHART_HEIGHT) -> go.Figure:
    fig.update_layout(
        height=height,
        autosize=True,
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=TEXT_COLOR, size=12),
        margin=dict(t=15, b=14, l=5, r=18),
        hoverlabel=dict(bgcolor="#1E293B", font_color="#E2E8F0"),
        dragmode=False,
    )
    return fig


def severity_chart(counts: dict[str, int]) -> go.Figure:
    labels = [name for name in SEVERITY_ORDER if counts.get(name, 0) > 0]
    labels.extend(sorted(name for name, n in counts.items()
                         if name not in SEVERITY_ORDER and n > 0))
    values = [counts[name] for name in labels]
    fig = go.Figure(go.Bar(
        x=values, y=labels, orientation="h",
        marker_color=[SEVERITY_COLORS.get(name, "#94A3B8") for name in labels],
        text=values, textposition="outside", cliponaxis=False,
        hovertemplate="%{y}: %{x:,} findings<extra></extra>",
    ))
    _base(fig)
    fig.update_layout(margin=dict(t=12, b=15, l=10, r=34), showlegend=False)
    fig.update_yaxes(autorange="reversed", showgrid=False, fixedrange=True, title=None)
    fig.update_xaxes(showgrid=True, gridcolor=GRID_COLOR, rangemode="tozero",
                     zeroline=False, fixedrange=True, title=None, tickformat="d")
    return fig


def type_chart(counts: dict[str, int]) -> go.Figure:
    items = [(TYPE_LABELS.get(t, t.replace("_", " ").title()), int(v))
             for t, v in counts.items() if v > 0]
    labels = [name for name, _ in items]
    values = [count for _, count in items]
    fig = go.Figure(go.Pie(
        labels=labels, values=values, hole=0.68,
        marker=dict(colors=list(TYPE_COLORS)[:len(labels)]),
        sort=False,
        textinfo="percent", textposition="inside",
        hovertemplate="%{label}: %{value:,} (%{percent})<extra></extra>",
    ))
    _base(fig)
    fig.update_layout(
        margin=dict(t=5, b=35, l=5, r=5),
        showlegend=True,
        legend=dict(orientation="h", x=0.5, xanchor="center", y=-0.08,
                    yanchor="top", font=dict(size=10), title=None),
        annotations=[dict(text=f"{sum(values):,}", showarrow=False, x=0.5, y=0.52,
                          font=dict(size=24, color="#F1F5F9"))],
    )
    return fig


def sources_chart(counts: dict[str, int], limit: int = 6) -> tuple[go.Figure, int]:
    ordered = sorted(((name, int(value)) for name, value in counts.items() if value > 0),
                     key=lambda item: (-item[1], item[0]))
    chosen = ordered[:limit]
    names = [name for name, _ in chosen]
    # Shorter axis labels keep the chart usable when the sidebar is expanded.
    display_names = [name if len(name) <= 24 else name[:21] + "..." for name in names]
    fig = go.Figure(go.Bar(
        x=[v for _, v in chosen], y=display_names, orientation="h",
        marker_color="#38BDF8", text=[v for _, v in chosen],
        textposition="outside", cliponaxis=False,
        customdata=names,
        hovertemplate="%{customdata}: %{x:,} findings<extra></extra>",
    ))
    _base(fig)
    fig.update_layout(margin=dict(t=12, b=15, l=10, r=33), showlegend=False)
    fig.update_yaxes(autorange="reversed", showgrid=False, fixedrange=True, title=None)
    fig.update_xaxes(showgrid=True, gridcolor=GRID_COLOR, rangemode="tozero",
                     zeroline=False, fixedrange=True, title=None, tickformat="d")
    return fig, max(0, len(ordered) - len(chosen))
