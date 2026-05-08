# utils/mobile_css.py
# ═════════════════════════════════════════════════════════════════
# Mobile-Responsive CSS for Campus Fraud Shield
# Injected via st.markdown() in app.py
# ═════════════════════════════════════════════════════════════════

MOBILE_CSS = """
<style>
/* ── Mobile Base ──────────────────────────────────────────────── */
@media screen and (max-width: 768px) {

    /* Hero title smaller on mobile */
    .hero-title {
        font-size: 1.8rem !important;
    }
    .hero-subtitle {
        font-size: 0.9rem !important;
    }

    /* Stack engine cards vertically */
    .engine-card {
        margin-bottom: 0.5rem;
    }
    .engine-score {
        font-size: 1.2rem !important;
    }

    /* Badge smaller */
    .badge-scam,
    .badge-suspicious,
    .badge-safe {
        font-size: 1.4rem !important;
        padding: 0.4rem 1.2rem !important;
    }

    /* Formula box scrollable */
    .formula-box {
        font-size: 0.75rem !important;
        overflow-x: auto;
    }

    /* Action steps full width */
    .action-step {
        flex-direction: column;
        gap: 0.4rem;
    }

    /* Metric cards */
    [data-testid="metric-container"] {
        padding: 0.4rem !important;
    }
    [data-testid="metric-container"] label {
        font-size: 0.75rem !important;
    }

    /* Buttons full width */
    .stButton > button {
        width: 100% !important;
        font-size: 0.85rem !important;
        padding: 0.5rem !important;
    }

    /* Text area */
    .stTextArea textarea {
        font-size: 0.85rem !important;
        height: 120px !important;
    }

    /* Reduce padding overall */
    .block-container {
        padding: 1rem 0.75rem !important;
    }

    /* Sim banner */
    .sim-banner {
        font-size: 0.78rem !important;
    }

    /* Override / conflict banners */
    .override-banner,
    .conflict-banner {
        font-size: 0.82rem !important;
    }
}

/* ── Tablet ───────────────────────────────────────────────────── */
@media screen and (min-width: 769px) and (max-width: 1024px) {

    .hero-title {
        font-size: 2.2rem !important;
    }

    .engine-score {
        font-size: 1.4rem !important;
    }

    .badge-scam,
    .badge-suspicious,
    .badge-safe {
        font-size: 1.8rem !important;
    }
}

/* ── PWA / standalone mode ────────────────────────────────────── */
@media (display-mode: standalone) {
    .block-container {
        padding-top: 2rem !important;
    }
}

/* ── Touch targets ────────────────────────────────────────────── */
@media (hover: none) and (pointer: coarse) {
    .stButton > button {
        min-height: 48px !important;
    }
    .stTextArea textarea {
        min-height: 100px !important;
    }
}
</style>
"""


def inject_mobile_css() -> None:
    """Inject mobile responsive CSS into Streamlit app."""
    import streamlit as st
    st.markdown(MOBILE_CSS, unsafe_allow_html=True)


if __name__ == "__main__":
    print("Mobile CSS module loaded.")
    print(f"CSS length: {len(MOBILE_CSS)} characters")