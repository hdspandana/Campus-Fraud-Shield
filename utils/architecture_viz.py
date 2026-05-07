# utils/architecture_viz.py
# ═════════════════════════════════════════════════════════════════
# Interactive Plotly Architecture Diagram
# Shows 4-engine pipeline for judges
# ═════════════════════════════════════════════════════════════════

import plotly.graph_objects as go
from typing import Optional


def build_architecture_diagram() -> go.Figure:
    """
    Build interactive Plotly diagram of the 4-engine pipeline.

    Returns:
        Plotly Figure object ready for st.plotly_chart()
    """
    fig = go.Figure()

    # ── Node positions (x, y) ─────────────────────────────────────
    nodes = {
        # Input
        "input":   (0.5, 0.92, "📱 Input Message", "#1e3a5f", "#00d4ff"),

        # 4 engines
        "rules":   (0.1,  0.60, "⚖️ Rules Engine\n35% weight", "#2d1b69", "#7b2ff7"),
        "domain":  (0.37, 0.60, "🌐 Domain Check\n30% weight", "#1a3a1a", "#00c853"),
        "ml":      (0.63, 0.60, "🤖 Semantic AI\n20% weight", "#1a2a3a", "#00d4ff"),
        "history": (0.90, 0.60, "📚 FAISS History\n15% weight", "#3a1a1a", "#ff6b35"),

        # Scorer
        "scorer":  (0.5,  0.32, "🧮 Weighted Scorer\n0.35×Rules + 0.30×Domain\n+ 0.20×ML + 0.15×History", "#2a1a0a", "#f39c12"),

        # Outputs
        "scam":    (0.15, 0.08, "🚨 SCAM", "#4a0000", "#ff2d55"),
        "suspicious": (0.50, 0.08, "⚠️ SUSPICIOUS", "#3a2a00", "#f39c12"),
        "safe":    (0.85, 0.08, "✅ SAFE", "#003a00", "#00c853"),
    }

    # ── Draw edges ────────────────────────────────────────────────
    edges = [
        # Input → engines
        ("input",   "rules"),
        ("input",   "domain"),
        ("input",   "ml"),
        ("input",   "history"),
        # Engines → scorer
        ("rules",   "scorer"),
        ("domain",  "scorer"),
        ("ml",      "scorer"),
        ("history", "scorer"),
        # Scorer → verdicts
        ("scorer",  "scam"),
        ("scorer",  "suspicious"),
        ("scorer",  "safe"),
    ]

    for src, dst in edges:
        x0, y0 = nodes[src][0], nodes[src][1]
        x1, y1 = nodes[dst][0], nodes[dst][1]

        fig.add_trace(go.Scatter(
            x=[x0, x1, None],
            y=[y0, y1, None],
            mode="lines",
            line=dict(color="#1e2d40", width=2),
            hoverinfo="skip",
            showlegend=False,
        ))

    # ── Draw nodes ────────────────────────────────────────────────
    for key, (x, y, label, bg, border) in nodes.items():
        fig.add_trace(go.Scatter(
            x=[x],
            y=[y],
            mode="markers+text",
            marker=dict(
                size=60 if key in ("input", "scorer") else 48,
                color=bg,
                line=dict(color=border, width=2.5),
                symbol="square",
            ),
            text=[label],
            textposition="middle center",
            textfont=dict(
                size=9 if "\n" in label else 10,
                color="#e8eaf6",
                family="monospace",
            ),
            hovertemplate=f"<b>{label.replace(chr(10), ' ')}</b><extra></extra>",
            showlegend=False,
        ))

    # ── Weight annotation bar ─────────────────────────────────────
    weights = [
        (0.10, "35%", "#7b2ff7"),
        (0.37, "30%", "#00c853"),
        (0.63, "20%", "#00d4ff"),
        (0.90, "15%", "#ff6b35"),
    ]
    for x, pct, color in weights:
        fig.add_annotation(
            x=x, y=0.47,
            text=f"<b>{pct}</b>",
            showarrow=False,
            font=dict(size=11, color=color),
            bgcolor="#0a0f1e",
            bordercolor=color,
            borderwidth=1,
            borderpad=3,
        )

    # ── Formula annotation ────────────────────────────────────────
    fig.add_annotation(
        x=0.5, y=0.20,
        text="<b>Final = 0.35×Rules + 0.30×Domain + 0.20×ML + 0.15×History</b>",
        showarrow=False,
        font=dict(size=10, color="#8892b0", family="monospace"),
        bgcolor="#0d1117",
        bordercolor="#1e2d40",
        borderwidth=1,
        borderpad=5,
    )

    fig.update_layout(
        paper_bgcolor="#0a0f1e",
        plot_bgcolor ="#0a0f1e",
        height=480,
        margin=dict(l=10, r=10, t=40, b=10),
        title=dict(
            text="Campus Fraud Shield — 4-Engine Detection Pipeline",
            font=dict(size=13, color="#8892b0"),
            x=0.5,
        ),
        xaxis=dict(visible=False, range=[-0.05, 1.05]),
        yaxis=dict(visible=False, range=[-0.05, 1.05]),
    )

    return fig


def render_architecture(st_container=None) -> None:
    """
    Render architecture diagram in Streamlit.

    Args:
        st_container: Optional Streamlit container.
                      If None uses st directly.
    """
    import streamlit as st
    target = st_container or st

    fig = build_architecture_diagram()
    target.plotly_chart(fig, use_container_width=True)

    target.markdown(
        """
        <div style="display:flex;gap:1.5rem;justify-content:center;
        flex-wrap:wrap;margin-top:0.5rem;">
        <span style="color:#7b2ff7;">■ Rules Engine (35%)</span>
        <span style="color:#00c853;">■ Domain Check (30%)</span>
        <span style="color:#00d4ff;">■ Semantic AI (20%)</span>
        <span style="color:#ff6b35;">■ FAISS History (15%)</span>
        </div>
        """,
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    fig = build_architecture_diagram()
    fig.show()