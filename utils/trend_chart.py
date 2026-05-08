# utils/trend_chart.py
# ═════════════════════════════════════════════════════════════════
# Scam Trend Charts using Plotly
# Category breakdown + confidence distribution
# Uses live data from history engine when available
# ═════════════════════════════════════════════════════════════════

import plotly.graph_objects as go
from plotly.subplots import make_subplots
from typing import Dict, List, Any, Optional


# ── Colour map per category ───────────────────────────────────────
CATEGORY_COLORS = {
    "internship_fee":     "#7b2ff7",
    "job_fee":            "#9b59b6",
    "scholarship_fee":    "#3498db",
    "otp_fraud":          "#ff2d55",
    "lottery_prize":      "#f39c12",
    "parttime_job":       "#e67e22",
    "bank_impersonation": "#e74c3c",
    "gov_scheme_fraud":   "#1abc9c",
    "unknown_scam":       "#95a5a6",
    "suspicious":         "#f39c12",
    "safe":               "#00c853",
}

CATEGORY_LABELS = {
    "internship_fee":     "Fake Internship",
    "job_fee":            "Fake Job",
    "scholarship_fee":    "Scholarship Fraud",
    "otp_fraud":          "OTP Fraud",
    "lottery_prize":      "Prize/Lottery",
    "parttime_job":       "Part-Time Scam",
    "bank_impersonation": "Bank Impersonation",
    "gov_scheme_fraud":   "Govt Scheme Fraud",
    "unknown_scam":       "Other Scam",
    "suspicious":         "Suspicious",
    "safe":               "Safe",
}

# ── Fallback data for demo when DB is empty ───────────────────────
DEMO_CATEGORY_DATA = {
    "internship_fee":     42,
    "otp_fraud":          28,
    "lottery_prize":      19,
    "scholarship_fee":    15,
    "job_fee":            12,
    "bank_impersonation": 10,
    "gov_scheme_fraud":    8,
    "parttime_job":        7,
}


def build_category_donut(
    data: Optional[Dict[str, int]] = None
) -> go.Figure:
    """
    Build donut chart of scam categories.

    Args:
        data: dict {category: count}. Uses demo data if None.

    Returns:
        Plotly Figure
    """
    if not data:
        data = DEMO_CATEGORY_DATA

    labels  = [CATEGORY_LABELS.get(k, k) for k in data]
    values  = list(data.values())
    colors  = [CATEGORY_COLORS.get(k, "#95a5a6") for k in data]

    fig = go.Figure(go.Pie(
        labels          = labels,
        values          = values,
        hole            = 0.55,
        marker          = dict(colors=colors, line=dict(color="#0a0f1e", width=2)),
        textinfo        = "percent",
        textfont        = dict(size=11, color="white"),
        hovertemplate   = "<b>%{label}</b><br>Count: %{value}<br>Share: %{percent}<extra></extra>",
    ))

    total = sum(values)
    fig.add_annotation(
        text       = f"<b>{total}</b><br><span style='font-size:10px'>total scans</span>",
        x=0.5, y=0.5,
        showarrow  = False,
        font       = dict(size=16, color="#00d4ff"),
    )

    fig.update_layout(
        paper_bgcolor = "#0a0f1e",
        plot_bgcolor  = "#0a0f1e",
        showlegend    = True,
        legend        = dict(
            font       = dict(color="#8892b0", size=10),
            bgcolor    = "#111827",
            bordercolor= "#1e2d40",
            borderwidth= 1,
        ),
        margin = dict(l=10, r=10, t=40, b=10),
        title  = dict(
            text = "Scam Category Distribution",
            font = dict(size=13, color="#8892b0"),
            x    = 0.5,
        ),
        height = 380,
    )

    return fig


def build_confidence_histogram(
    scores: Optional[List[float]] = None
) -> go.Figure:
    """
    Build histogram of confidence scores across all scans.

    Args:
        scores: List of confidence scores 0-100. Uses demo if None.

    Returns:
        Plotly Figure
    """
    if not scores:
        # Demo distribution
        import random
        random.seed(42)
        scam_scores = [random.gauss(82, 10) for _ in range(60)]
        safe_scores = [random.gauss(18, 12) for _ in range(30)]
        scores      = [max(0, min(100, s)) for s in scam_scores + safe_scores]

    # Split into ranges
    scam_scores       = [s for s in scores if s >= 70]
    suspicious_scores = [s for s in scores if 40 <= s < 70]
    safe_scores       = [s for s in scores if s < 40]

    fig = go.Figure()

    fig.add_trace(go.Histogram(
        x        = scam_scores,
        name     = "SCAM",
        marker   = dict(color="#ff2d55", line=dict(color="#0a0f1e", width=1)),
        xbins    = dict(start=0, end=100, size=5),
        opacity  = 0.85,
    ))
    fig.add_trace(go.Histogram(
        x        = suspicious_scores,
        name     = "SUSPICIOUS",
        marker   = dict(color="#f39c12", line=dict(color="#0a0f1e", width=1)),
        xbins    = dict(start=0, end=100, size=5),
        opacity  = 0.85,
    ))
    fig.add_trace(go.Histogram(
        x        = safe_scores,
        name     = "SAFE",
        marker   = dict(color="#00c853", line=dict(color="#0a0f1e", width=1)),
        xbins    = dict(start=0, end=100, size=5),
        opacity  = 0.85,
    ))

    # Threshold lines
    for x, color, label in [
        (70, "#ff2d55",  "SCAM threshold"),
        (40, "#f39c12",  "SUSPICIOUS threshold"),
    ]:
        fig.add_vline(
            x            = x,
            line_dash    = "dash",
            line_color   = color,
            line_width   = 1.5,
            annotation_text      = label,
            annotation_position  = "top right",
            annotation_font      = dict(color=color, size=10),
        )

    fig.update_layout(
        paper_bgcolor = "#0a0f1e",
        plot_bgcolor  = "#111827",
        barmode       = "overlay",
        height        = 320,
        margin        = dict(l=40, r=20, t=40, b=40),
        title         = dict(
            text = "Confidence Score Distribution",
            font = dict(size=13, color="#8892b0"),
            x    = 0.5,
        ),
        xaxis = dict(
            title      = "Confidence Score",
            color      = "#8892b0",
            gridcolor  = "#1e2d40",
            range      = [0, 100],
        ),
        yaxis = dict(
            title     = "Count",
            color     = "#8892b0",
            gridcolor = "#1e2d40",
        ),
        legend = dict(
            font        = dict(color="#8892b0"),
            bgcolor     = "#111827",
            bordercolor = "#1e2d40",
            borderwidth = 1,
        ),
    )

    return fig


def build_engine_radar(breakdown: Dict[str, Any]) -> go.Figure:
    """
    Build radar chart showing all 4 engine scores for one result.

    Args:
        breakdown: breakdown dict from scorer.calculate()

    Returns:
        Plotly Figure
    """
    engines = ["Rules Engine", "Domain Check", "Semantic AI", "FAISS History"]
    scores  = [
        breakdown.get("rules",   {}).get("score", 0),
        breakdown.get("domain",  {}).get("score", 0),
        breakdown.get("ml",      {}).get("score", 0),
        breakdown.get("history", {}).get("score", 0),
    ]
    # Close the polygon
    engines_closed = engines + [engines[0]]
    scores_closed  = scores  + [scores[0]]

    fig = go.Figure(go.Scatterpolar(
        r       = scores_closed,
        theta   = engines_closed,
        fill    = "toself",
        line    = dict(color="#00d4ff", width=2),
        marker  = dict(color="#00d4ff", size=6),
        fillcolor = "rgba(0,212,255,0.15)",
        name    = "Engine Scores",
        hovertemplate = "<b>%{theta}</b><br>Score: %{r:.0f}/100<extra></extra>",
    ))

    # Threshold reference ring at 70
    import math
    theta_ring = [i * (360 / 100) for i in range(101)]
    fig.add_trace(go.Scatterpolar(
        r        = [70] * 101,
        theta    = theta_ring,
        mode     = "lines",
        line     = dict(color="#ff2d55", width=1, dash="dash"),
        name     = "SCAM threshold (70)",
        hoverinfo = "skip",
    ))

    fig.update_layout(
        polar = dict(
            bgcolor   = "#111827",
            radialaxis = dict(
                visible  = True,
                range    = [0, 100],
                tickfont = dict(color="#8892b0", size=9),
                gridcolor = "#1e2d40",
                linecolor = "#1e2d40",
            ),
            angularaxis = dict(
                tickfont  = dict(color="#e8eaf6", size=10),
                gridcolor = "#1e2d40",
                linecolor = "#1e2d40",
            ),
        ),
        paper_bgcolor = "#0a0f1e",
        height        = 320,
        margin        = dict(l=40, r=40, t=50, b=20),
        title         = dict(
            text = "Engine Score Radar",
            font = dict(size=13, color="#8892b0"),
            x    = 0.5,
        ),
        showlegend = True,
        legend     = dict(
            font        = dict(color="#8892b0", size=10),
            bgcolor     = "#111827",
            bordercolor = "#1e2d40",
            borderwidth = 1,
        ),
    )

    return fig


def render_trends_tab(st_container=None) -> None:
    """
    Render full trends tab in Streamlit.

    Args:
        st_container: Optional Streamlit container.
    """
    import streamlit as st
    target = st_container or st

    target.markdown("### 📊 Scam Trend Analysis")

    # Try to get live data
    cat_data  = None
    score_list = None

    try:
        from core.history_engine import UnifiedHistoryEngine
        engine   = UnifiedHistoryEngine()
        stats    = engine.get_stats()
        clusters = engine.get_scam_clusters()

        if stats["total_reports"] > 0:
            cat_data = {
                c["category_display"]: c["count"]
                for c in clusters
            } if clusters else None

    except Exception:
        pass

    col1, col2 = target.columns(2)

    with col1:
        fig_donut = build_category_donut(cat_data)
        st.plotly_chart(fig_donut, use_container_width=True)

    with col2:
        fig_hist = build_confidence_histogram(score_list)
        st.plotly_chart(fig_hist, use_container_width=True)


if __name__ == "__main__":
    # Test charts
    fig1 = build_category_donut()
    fig1.show()

    fig2 = build_confidence_histogram()
    fig2.show()

    fig3 = build_engine_radar({
        "rules":   {"score": 88},
        "domain":  {"score": 65},
        "ml":      {"score": 78},
        "history": {"score": 55},
    })
    fig3.show()