# admin/dashboard.py
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from config import ADMIN_PASSWORD
from core.history_engine import load_reported_scams, get_history_stats


def render_admin_dashboard():
    """Renders the admin dashboard page."""

    st.markdown("## 🔐 Admin Dashboard")

    # ── Login ─────────────────────────────────────────────────────────────
    if "admin_logged_in" not in st.session_state:
        st.session_state.admin_logged_in = False

    if not st.session_state.admin_logged_in:
        st.markdown("### Login")
        pwd = st.text_input("Admin Password", type="password")
        if st.button("Login", use_container_width=True):
            if pwd == ADMIN_PASSWORD:
                st.session_state.admin_logged_in = True
                st.rerun()
            else:
                st.error("❌ Incorrect password")
        return

    # ── Logout ────────────────────────────────────────────────────────────
    if st.button("🚪 Logout", key="admin_logout"):
        st.session_state.admin_logged_in = False
        st.rerun()

    # ── Stats ─────────────────────────────────────────────────────────────
    stats = get_history_stats()
    reports = load_reported_scams()

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("📊 Total Reports", stats["total"])
    c2.metric("🚫 Scams",         stats["scams"])
    c3.metric("⚠️ Suspicious",    stats["suspicious"])
    c4.metric("✅ Safe",          stats["safe"])

    if not reports:
        st.info("No reports yet. Students haven't reported any scams.")
        return

    df = pd.DataFrame(reports)

    # ── Chart 1: Label Distribution ───────────────────────────────────────
    st.markdown("### 📊 Report Distribution")
    label_counts = df["label"].value_counts().reset_index()
    label_counts.columns = ["label", "count"]

    fig1 = px.pie(
        label_counts, names="label", values="count",
        color="label",
        color_discrete_map={
            "Scam":       "#ef4444",
            "Suspicious": "#f59e0b",
            "Safe":       "#22c55e",
        },
        hole=0.4,
    )
    fig1.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor ="rgba(0,0,0,0)",
        font=dict(family="Inter"),
    )
    st.plotly_chart(fig1, use_container_width=True)

    # ── Chart 2: Scam Types ───────────────────────────────────────────────
    if "scam_type" in df.columns:
        st.markdown("### 🎭 Scam Type Breakdown")
        type_counts = df[df["label"] == "Scam"]["scam_type"].value_counts().reset_index()
        type_counts.columns = ["type", "count"]

        fig2 = px.bar(
            type_counts, x="type", y="count",
            color="count",
            color_continuous_scale="Reds",
        )
        fig2.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor ="rgba(0,0,0,0)",
            font=dict(family="Inter"),
            showlegend=False,
        )
        st.plotly_chart(fig2, use_container_width=True)

    # ── Recent Reports Table ──────────────────────────────────────────────
    st.markdown("### 📋 Recent Reports")
    display_cols = ["id", "label", "score", "scam_type", "source", "timestamp"]
    available    = [c for c in display_cols if c in df.columns]

    st.dataframe(
        df[available].tail(20).sort_values("id", ascending=False),
        use_container_width=True,
    )

    # ── Download ──────────────────────────────────────────────────────────
    csv = df.to_csv(index=False)
    st.download_button(
        "📥 Download All Reports (CSV)",
        csv, "cfs_reports.csv", "text/csv",
        use_container_width=True,
    )