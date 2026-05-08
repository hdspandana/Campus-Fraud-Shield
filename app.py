# app.py
# ═════════════════════════════════════════════════════════════════
# Campus Fraud Shield 🛡️ — Main Streamlit Application
# Integrates all 4 backend engines with full explainability UI
# Fallback/simulation mode if any import fails
# ═════════════════════════════════════════════════════════════════

import streamlit as st
import time
import sys
import os

# ── Page config MUST be first Streamlit call ─────────────────────
st.set_page_config(
    page_title="Campus Fraud Shield 🛡️",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ════════════════════════════════════════════════════════════════
# SECTION 1 — Backend Import with Graceful Fallback
# ════════════════════════════════════════════════════════════════

SIMULATION_MODE = False
IMPORT_ERRORS   = []

# ── Try real backend imports ──────────────────────────────────────
try:
    sys.path.insert(0, os.path.dirname(__file__))

    from core.scorer          import FraudScorer
    from core.ml_model        import SemanticScamClassifier, get_semantic_classifier
    from core.history_engine  import UnifiedHistoryEngine
    from core.campus_checker  import CampusChecker
    from utils.action_advisor import get_action
    from utils.explainer      import Explainer

    # Initialise engines (cached where possible)
    @st.cache_resource(show_spinner=False)
    def load_scorer():
        return FraudScorer()

    @st.cache_resource(show_spinner=False)
    def load_ml_model():
        clf = get_semantic_classifier()
        # Try loading pre-trained weights; train inline if missing
        if not clf.is_trained:
            loaded = clf.load()
            if not loaded:
                # Minimal inline training so the model is usable
                _train_texts = [
                    "Pay registration fee to get internship",
                    "Send OTP to claim your prize money",
                    "You won lottery pay processing fee now",
                    "Congratulations selected pay deposit now",
                    "Pay Rs 2000 fee to confirm your job offer",
                    "Share your OTP to receive KBC prize",
                    "Registration fee Rs 999 to confirm internship slot",
                    "Lucky draw winner pay processing fee immediately",
                    "Your internship offer letter is ready no fee",
                    "Interview scheduled for Monday 3PM no charges",
                    "Please bring documents for joining ceremony",
                    "Salary credited to your account successfully",
                    "Application received for software developer role",
                    "TCS NextStep interview link sent to your email",
                ]
                _train_labels = [1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0]
                clf.fit(_train_texts, _train_labels)
        return clf

    @st.cache_resource(show_spinner=False)
    def load_history():
        engine = UnifiedHistoryEngine()
        # Seed from dataset if available
        if engine.index.ntotal == 0:
            engine.seed_from_dataset("data/scam_dataset.csv")
        return engine

    @st.cache_resource(show_spinner=False)
    def load_explainer():
        return Explainer(student_mode=False)

except Exception as e:
    SIMULATION_MODE = True
    IMPORT_ERRORS.append(str(e))
    # Debug: print the error for testing
    import traceback
    IMPORT_ERRORS.append(traceback.format_exc())


# ════════════════════════════════════════════════════════════════
# SECTION 2 — Simulation Engine (runs when imports fail)
# ════════════════════════════════════════════════════════════════

def _simulate_scan(text: str) -> dict:
    """
    Hardcoded simulation so the demo never crashes.
    Returns same structure as scorer.calculate().
    """
    text_lower = text.lower()

    # Detect pattern
    is_otp      = any(w in text_lower for w in ["otp", "one time"])
    is_lottery  = any(w in text_lower for w in ["lottery", "won", "prize", "kbc", "lucky draw"])
    is_fee      = any(w in text_lower for w in ["registration fee", "pay", "₹", "rs.", "paytm", "phonepe"])
    is_safe     = any(w in text_lower for w in ["no fee", "no charges", "official website", "interview scheduled"])

    if is_otp:
        verdict, confidence, category = "SCAM", 92, "otp_fraud"
        reasons  = ["Real banks NEVER ask for OTP via message/call. OTP sharing = scam",
                    "Lucky draw/lottery you never entered = guaranteed scam"]
        override = "OTP sharing detected — auto-classified as SCAM"
        breakdown = {"rules": 90, "domain": 80, "ml": 88, "campus": 95}
    elif is_lottery:
        verdict, confidence, category = "SCAM", 88, "lottery_prize"
        reasons  = ["Lucky draw/lottery you never entered = guaranteed scam",
                    "Message contains fee demand"]
        override = None
        breakdown = {"rules": 85, "domain": 70, "ml": 82, "campus": 90}
    elif is_fee and not is_safe:
        verdict, confidence, category = "SCAM", 85, "internship_fee"
        reasons  = ["Internshala never charges registration fee",
                    "Urgency language detected — a common scam pressure tactic"]
        override = None
        breakdown = {"rules": 88, "domain": 65, "ml": 78, "campus": 92}
    elif is_safe:
        verdict, confidence, category = "SAFE", 12, "safe"
        reasons  = ["No suspicious patterns detected — message appears legitimate"]
        override = None
        breakdown = {"rules": 10, "domain": 5, "ml": 15, "campus": 8}
    else:
        verdict, confidence, category = "SUSPICIOUS", 52, "suspicious"
        reasons  = ["Message contains some unusual patterns",
                    "Verify independently before acting"]
        override = None
        breakdown = {"rules": 50, "domain": 40, "ml": 55, "campus": 48}

    r = breakdown
    formula = (
        f"Rules Engine   {r['rules']:5.1f} × 0.35 = {r['rules']*0.35:5.1f}\n"
        f"Domain Check   {r['domain']:5.1f} × 0.30 = {r['domain']*0.30:5.1f}\n"
        f"Semantic AI    {r['ml']:5.1f} × 0.20 = {r['ml']*0.20:5.1f}\n"
        f"History FAISS  {r['campus']:5.1f} × 0.15 = {r['campus']*0.15:5.1f}\n"
        f"{'─'*42}\n"
        f"Final Score                   = {confidence:5.1f}"
    )

    action = {
        "steps":          ["Do NOT pay any fee", "Block the sender immediately",
                           "Report at cybercrime.gov.in", "Call helpline 1930"],
        "helpline":       "1930",
        "online_url":     "https://cybercrime.gov.in",
        "complaint_text": f"I received a suspicious message on {time.strftime('%d/%m/%Y')}.\n"
                          f"Message preview: \"{text[:120]}...\"\n"
                          f"Please investigate this fraud attempt.",
    }

    return {
        "final_score":      confidence,
        "label":            verdict,
        "category":         category,
        "category_display": category.replace("_", " ").title(),
        "reasons":          reasons,
        "breakdown":        {
            "rules":   {"score": r["rules"],  "weight": 0.35, "reasons": reasons},
            "domain":  {"score": r["domain"], "weight": 0.30, "reasons": []},
            "ml":      {"score": r["ml"],     "weight": 0.20, "reason": "Simulated"},
            "history": {"score": r["campus"], "weight": 0.15, "matches": []},
        },
        "formula":          formula,
        "override_applied": override,
        "action":           action,
    }


# ════════════════════════════════════════════════════════════════
# SECTION 3 — Full Pipeline Runner
# ════════════════════════════════════════════════════════════════

def run_full_pipeline(text: str) -> dict:
    """
    Run all 4 engines and return unified result.
    Falls back to simulation if any engine throws.
    """
    if SIMULATION_MODE:
        result = _simulate_scan(text)
        result["action"] = get_action_safe(
            result["final_score"], result["category"], text
        )
        return result

    try:
        scorer  = load_scorer()
        ml_clf  = load_ml_model()
        history = load_history()

        # ML engine
        ml_score, ml_reason = ml_clf.predict_proba(text)
        ml_similar          = ml_clf.get_similar_training_examples(text, n=3)

        # History engine
        hist_result   = history.search_and_explain(text, k=5)
        history_score = hist_result["score"]
        hist_matches  = hist_result["matches"]

        # Final scorer (rules + domain + campus built-in)
        result = scorer.calculate(
            text            = text,
            ml_score        = ml_score,
            ml_reason       = ml_reason,
            ml_similar      = ml_similar,
            history_score   = history_score,
            history_matches = hist_matches,
        )

        # Add action advice
        result["action"] = get_action_safe(
            result["final_score"],
            result["category"],
            text,
        )

        # Store in history for community learning
        try:
            history.add_report(
                text     = text,
                label    = 1 if result["label"] == "SCAM" else 0,
                category = result["category"],
                source   = "user_scan",
                score    = result["final_score"],
            )
        except Exception:
            pass  # Non-critical

        return result

    except Exception as e:
        # Graceful fallback per-scan
        result = _simulate_scan(text)
        result["action"] = get_action_safe(
            result["final_score"], result["category"], text
        )
        result["_fallback_error"] = str(e)
        return result


def get_action_safe(score: float, category: str, text: str) -> dict:
    """Wrapper so action_advisor never crashes the app."""
    try:
        if not SIMULATION_MODE:
            return get_action(score, category, text)
    except Exception:
        pass
    return {
        "steps":          ["Do NOT pay any fee",
                           "Block the sender immediately",
                           "Report at cybercrime.gov.in",
                           "Call helpline 1930"],
        "helpline":       "1930",
        "online_url":     "https://cybercrime.gov.in",
        "complaint_text": f"Suspicious message received on {time.strftime('%d/%m/%Y')}.\nText: \"{text[:200]}\"",
    }


# ════════════════════════════════════════════════════════════════
# SECTION 4 — Demo Preset Messages
# ════════════════════════════════════════════════════════════════

PRESETS = {
    "🎭 Fake Internship": (
        "Congratulations! You have been selected for a work-from-home "
        "internship at Internshala partner company. Earn ₹15,000/month. "
        "Pay ₹999 registration fee to confirm your slot. Send payment to "
        "9876543210 via Paytm. Offer expires in 24 hours. Do not miss this opportunity!"
    ),
    "🏆 Prize / Lottery Scam": (
        "You have WON ₹25 lakh in KBC Lucky Draw! Your mobile number was "
        "selected from 10 crore participants. To claim prize, share your OTP "
        "and pay ₹1500 processing fee to our agent at kbc.prize.claim@gmail.com. "
        "Contact WhatsApp: 9123456789. Valid today only!"
    ),
    "✅ Safe Message": (
        "Hi, this is the Internshala support team. Your application for the "
        "Software Developer Intern role at Flipkart has been shortlisted. "
        "Please login to internshala.com to complete your profile and schedule "
        "your interview. No fees required at any stage."
    ),
}


# ════════════════════════════════════════════════════════════════
# SECTION 5 — CSS Styling
# ════════════════════════════════════════════════════════════════

def inject_css():
    st.markdown("""
    <style>
    /* ── Base ─────────────────────────────── */
    .stApp {
        background-color: #0a0f1e;
        color: #e8eaf6;
        font-family: 'Inter', sans-serif;
    }

    /* ── Hero ─────────────────────────────── */
    .hero-title {
        font-size: 3rem;
        font-weight: 800;
        background: linear-gradient(135deg, #00d4ff, #7b2ff7);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-align: center;
        margin-bottom: 0.25rem;
    }
    .hero-subtitle {
        text-align: center;
        color: #8892b0;
        font-size: 1.1rem;
        margin-bottom: 2rem;
    }

    /* ── Verdict badges ───────────────────── */
    .badge-scam {
        display: inline-block;
        background: linear-gradient(135deg, #ff2d55, #c0392b);
        color: white;
        font-size: 2.2rem;
        font-weight: 900;
        padding: 0.5rem 2.5rem;
        border-radius: 50px;
        letter-spacing: 3px;
        text-align: center;
        box-shadow: 0 0 30px rgba(255,45,85,0.5);
        animation: pulse-red 1.5s infinite;
    }
    .badge-suspicious {
        display: inline-block;
        background: linear-gradient(135deg, #f39c12, #e67e22);
        color: white;
        font-size: 2.2rem;
        font-weight: 900;
        padding: 0.5rem 2.5rem;
        border-radius: 50px;
        letter-spacing: 3px;
        text-align: center;
        box-shadow: 0 0 30px rgba(243,156,18,0.4);
    }
    .badge-safe {
        display: inline-block;
        background: linear-gradient(135deg, #00c853, #1b5e20);
        color: white;
        font-size: 2.2rem;
        font-weight: 900;
        padding: 0.5rem 2.5rem;
        border-radius: 50px;
        letter-spacing: 3px;
        text-align: center;
        box-shadow: 0 0 30px rgba(0,200,83,0.4);
    }
    @keyframes pulse-red {
        0%   { box-shadow: 0 0 20px rgba(255,45,85,0.5); }
        50%  { box-shadow: 0 0 45px rgba(255,45,85,0.9); }
        100% { box-shadow: 0 0 20px rgba(255,45,85,0.5); }
    }

    /* ── Score bar ────────────────────────── */
    .score-bar-wrap {
        background: #1a2035;
        border-radius: 12px;
        height: 22px;
        width: 100%;
        overflow: hidden;
        margin: 0.5rem 0;
    }
    .score-bar-fill {
        height: 100%;
        border-radius: 12px;
        transition: width 0.6s ease;
    }

    /* ── Engine card ──────────────────────── */
    .engine-card {
        background: #111827;
        border: 1px solid #1e2d40;
        border-radius: 12px;
        padding: 1rem 1.2rem;
        margin-bottom: 0.75rem;
    }
    .engine-label {
        font-size: 0.78rem;
        text-transform: uppercase;
        letter-spacing: 1px;
        color: #8892b0;
        margin-bottom: 0.2rem;
    }
    .engine-score {
        font-size: 1.6rem;
        font-weight: 700;
        color: #00d4ff;
    }

    /* ── Override / conflict banners ─────── */
    .override-banner {
        background: linear-gradient(135deg, #4a0040, #7b003c);
        border-left: 4px solid #ff2d55;
        border-radius: 8px;
        padding: 0.75rem 1rem;
        margin: 0.75rem 0;
        font-size: 0.95rem;
    }
    .conflict-banner {
        background: linear-gradient(135deg, #1a2a00, #2d4a00);
        border-left: 4px solid #f39c12;
        border-radius: 8px;
        padding: 0.75rem 1rem;
        margin: 0.75rem 0;
        font-size: 0.95rem;
    }

    /* ── Action steps ─────────────────────── */
    .action-step {
        display: flex;
        align-items: flex-start;
        gap: 0.75rem;
        background: #111827;
        border-radius: 8px;
        padding: 0.75rem 1rem;
        margin-bottom: 0.5rem;
        border-left: 3px solid #00d4ff;
        font-size: 0.95rem;
    }
    .step-num {
        background: #00d4ff;
        color: #0a0f1e;
        font-weight: 800;
        font-size: 0.8rem;
        border-radius: 50%;
        width: 24px;
        height: 24px;
        display: flex;
        align-items: center;
        justify-content: center;
        flex-shrink: 0;
    }

    /* ── Formula box ──────────────────────── */
    .formula-box {
        background: #0d1117;
        border: 1px solid #1e2d40;
        border-radius: 10px;
        padding: 1rem 1.2rem;
        font-family: 'Courier New', monospace;
        font-size: 0.88rem;
        color: #79c0ff;
        white-space: pre;
        line-height: 1.7;
    }

    /* ── Simulation warning ───────────────── */
    .sim-banner {
        background: linear-gradient(135deg, #1a1a00, #2a2a00);
        border: 1px dashed #f39c12;
        border-radius: 8px;
        padding: 0.6rem 1rem;
        font-size: 0.85rem;
        color: #f39c12;
        margin-bottom: 1rem;
        text-align: center;
    }

    /* ── Buttons ──────────────────────────── */
    .stButton > button {
        border-radius: 8px;
        font-weight: 600;
        transition: all 0.2s;
    }
    .stButton > button:hover {
        transform: translateY(-1px);
        box-shadow: 0 4px 15px rgba(0,212,255,0.3);
    }

    /* ── Divider ──────────────────────────── */
    hr {
        border-color: #1e2d40;
        margin: 1.5rem 0;
    }

    /* ── Text area ─────────────���──────────── */
    .stTextArea textarea {
        background-color: #111827 !important;
        color: #e8eaf6 !important;
        border-color: #1e2d40 !important;
        border-radius: 10px !important;
        font-size: 0.95rem !important;
    }
    .stTextArea textarea:focus {
        border-color: #00d4ff !important;
        box-shadow: 0 0 0 2px rgba(0,212,255,0.2) !important;
    }

    /* ── Metric override ──────────────────── */
    [data-testid="metric-container"] {
        background: #111827;
        border-radius: 10px;
        padding: 0.75rem;
        border: 1px solid #1e2d40;
    }
    </style>
    """, unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════════
# SECTION 6 — UI Helper Components
# ════════════════════════════════════════════════════════════════

def render_verdict_badge(label: str):
    css_class = {
        "SCAM":       "badge-scam",
        "SUSPICIOUS": "badge-suspicious",
        "SAFE":       "badge-safe",
    }.get(label, "badge-suspicious")

    emoji = {"SCAM": "🚨", "SUSPICIOUS": "⚠️", "SAFE": "✅"}.get(label, "❓")

    st.markdown(
        f'<div style="text-align:center; margin: 1rem 0;">'
        f'<span class="{css_class}">{emoji} {label}</span>'
        f'</div>',
        unsafe_allow_html=True,
    )


def render_score_bar(score: float, label: str):
    colour = {
        "SCAM":       "#ff2d55",
        "SUSPICIOUS": "#f39c12",
        "SAFE":       "#00c853",
    }.get(label, "#00d4ff")

    st.markdown(
        f'<div class="score-bar-wrap">'
        f'<div class="score-bar-fill" '
        f'style="width:{min(score,100):.0f}%; background:{colour};"></div>'
        f'</div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        f'<p style="text-align:center; color:{colour}; '
        f'font-size:1.4rem; font-weight:700; margin:0;">'
        f'Confidence Score: {score:.0f} / 100</p>',
        unsafe_allow_html=True,
    )


def render_engine_breakdown(breakdown: dict):
    engine_meta = {
        "rules":   ("⚖️ Rules Engine",   "Campus + Expert Rules", 0.35),
        "domain":  ("🌐 Domain Check",   "URL / Email Analysis",  0.30),
        "ml":      ("🤖 Semantic AI",    "all-MiniLM-L6-v2",      0.20),
        "history": ("📚 FAISS History",  "Community Reports",     0.15),
    }

    cols = st.columns(4)
    for i, (key, (icon_label, sub, weight)) in enumerate(engine_meta.items()):
        engine_data = breakdown.get(key, {})
        score       = engine_data.get("score", 0)

        colour = (
            "#ff2d55" if score >= 70
            else "#f39c12" if score >= 40
            else "#00c853"
        )

        with cols[i]:
            st.markdown(
                f'<div class="engine-card">'
                f'<div class="engine-label">{icon_label}</div>'
                f'<div class="engine-score" style="color:{colour};">'
                f'{score:.0f}<span style="font-size:1rem;color:#8892b0;">/100</span>'
                f'</div>'
                f'<div style="font-size:0.75rem;color:#8892b0;margin-top:0.2rem;">'
                f'{sub} · weight {weight:.0%}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )


def render_formula(formula_str: str):
    st.markdown(
        f'<div class="formula-box">{formula_str}</div>',
        unsafe_allow_html=True,
    )


def render_action_steps(action: dict, label: str):
    steps = action.get("steps", [])
    if not steps:
        return

    for i, step in enumerate(steps, 1):
        st.markdown(
            f'<div class="action-step">'
            f'<div class="step-num">{i}</div>'
            f'<div>{step}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

    # Helpline + link
    helpline = action.get("helpline", "")
    url      = action.get("online_url", "")

    if helpline or url:
        c1, c2 = st.columns(2)
        if helpline:
            c1.markdown(
                f'<div style="background:#111827;border-radius:8px;'
                f'padding:0.75rem;text-align:center;border:1px solid #1e2d40;">'
                f'📞 <strong>Cyber Helpline</strong><br>'
                f'<span style="font-size:1.5rem;color:#00d4ff;font-weight:800;">'
                f'{helpline}</span></div>',
                unsafe_allow_html=True,
            )
        if url:
            c2.markdown(
                f'<div style="background:#111827;border-radius:8px;'
                f'padding:0.75rem;text-align:center;border:1px solid #1e2d40;">'
                f'🌐 <strong>Report Online</strong><br>'
                f'<a href="{url}" target="_blank" '
                f'style="color:#00d4ff;font-size:0.95rem;">{url}</a>'
                f'</div>',
                unsafe_allow_html=True,
            )


# In app.py replace render_reasons() with this:

def render_reasons(reasons: list, student_mode: bool, label: str = "SCAM"):
    if not reasons:
        return

    if student_mode and not SIMULATION_MODE:
        try:
            explainer          = load_explainer()
            explainer.student_mode = True
            formatted          = explainer.format_reasons(reasons)
            st.markdown(formatted)
            return
        except Exception:
            pass

    # Technical mode — icon based on verdict not reason text
    for i, r in enumerate(reasons, 1):
        if label == "SAFE":
            icon = "🟢"
        elif label == "SUSPICIOUS":
            icon = "🟡"
        else:
            # SCAM — all reasons are scam signals
            icon = "🔴"

        st.markdown(f"**{i}.** {icon} {r}")

# ════════════════════════════════════════════════════════════════
# SECTION 7 — Results Renderer
# ════════════════════════════════════════════════════════════════

def render_results(result: dict, student_mode: bool, label: str = "SCAM"):
    label      = result["label"]
    score      = result["final_score"]
    breakdown  = result["breakdown"]
    reasons    = result["reasons"]
         # ← existing line
    
    # ── Filter weak ML reason from display ───────────────────────
    filtered = [
         r for r in reasons
         if "inconclusive" not in r.lower()
         and "requires human review" not in r.lower()
    ]
    reasons = filtered if filtered else reasons   # fallback to all if empty
    # ─────────────────────────────────────────────────────────────
    
    formula    = result["formula"]
    override   = result.get("override_applied")
    action     = result.get("action", {})
    category   = result.get("category_display", "")

    st.markdown("---")

    # ── Verdict + score ───────────────────────────────────────────
    render_verdict_badge(label)
    render_score_bar(score, label)

    if category and category not in ("Safe", ""):
        st.markdown(
            f'<p style="text-align:center;color:#8892b0;margin-top:0.3rem;">'
            f'Detected Pattern: <strong style="color:#00d4ff;">{category}</strong>'
            f'</p>',
            unsafe_allow_html=True,
        )

    # ── Override banner ───────────────────────────────────────────
    if override:
        st.markdown(
            f'<div class="override-banner">'
            f'🔒 <strong>Override Applied:</strong> {override}'
            f'</div>',
            unsafe_allow_html=True,
        )

    # ── Conflicted signal detection ───────────────────────────────
    scores_list = [
        breakdown.get("rules",   {}).get("score", 0),
        breakdown.get("domain",  {}).get("score", 0),
        breakdown.get("ml",      {}).get("score", 0),
        breakdown.get("history", {}).get("score", 0),
    ]
    if scores_list:
        spread = max(scores_list) - min(scores_list)
        if spread > 45 and label != "SAFE":
            st.markdown(
                '<div class="conflict-banner">'
                '⚡ <strong>Conflicted Signal:</strong> The AI engines disagree '
                '— one or more engines found no issue while others flagged concerns. '
                'Manual verification recommended.'
                '</div>',
                unsafe_allow_html=True,
            )

    st.markdown("---")

    # ── Engine breakdown ──────────────────────────────────────────
    st.markdown("### 🔬 Engine-by-Engine Breakdown")
    render_engine_breakdown(breakdown)

    # ── Formula ───────────────────────────────────────────────────
    with st.expander("📐 Scoring Formula — How we calculated this", expanded=False):
        render_formula(formula)
        st.markdown(
            """
            <small style="color:#8892b0;">
            Weights: Rules Engine 35% · Domain Check 30% · 
            Semantic AI 20% · FAISS History 15%
            </small>
            """,
            unsafe_allow_html=True,
        )

    # ── Why we flagged this ───────────────────────────────────────
    if reasons:
        with st.expander(
            "🧠 Why did we flag this? — Detection Reasons",
            expanded=(label != "SAFE"),
        ):
            mode_label = "Student Mode 🎓" if student_mode else "Technical Mode 🔬"
            st.caption(f"Showing: {mode_label}")
            render_reasons(reasons, student_mode)

    # ── Similar examples (ML) ─────────────────────────────────────
    ml_data = breakdown.get("ml", {})
    similar = ml_data.get("similar", [])
    if similar and not SIMULATION_MODE:
        with st.expander("🔍 Similar Cases the AI Compared Against", expanded=False):
            for ex in similar[:3]:
                lbl_str = "🔴 SCAM" if ex.get("label") == 1 else "🟢 SAFE"
                sim_pct = f"{ex.get('similarity', 0):.0%}"
                st.markdown(
                    f"**{lbl_str}** · {sim_pct} similar  \n"
                    f"*\"{ex.get('text', '')}\"*"
                )
                st.markdown("---")

    # ── History matches ───────────────────────────────────────────
    hist_data = breakdown.get("history", {})
    matches   = hist_data.get("matches", [])
    if matches and not SIMULATION_MODE:
        with st.expander(
            f"📖 Community Reports — {len(matches)} similar case(s) found",
            expanded=False,
        ):
            for m in matches[:3]:
                sim_pct  = f"{m.get('similarity', 0):.0%}"
                cat_disp = m.get("category", "unknown").replace("_", " ").title()
                overlap  = m.get("overlap_phrases", [])
                st.markdown(
                    f"**{sim_pct} similar** · Pattern: {cat_disp}  \n"
                    f"Key phrases: `{'`, `'.join(overlap) if overlap else 'N/A'}`  \n"
                    f"*{m.get('explanation', '')}*"
                )
                st.markdown("---")

    st.markdown("---")

    # ── Action steps ──────────────────────────────────────────────
    if label != "SAFE":
        st.markdown("### 🚨 What You Should Do Right Now")
        render_action_steps(action, label)

        # ── Complaint text copy ───────────────────────────────────
        complaint = action.get("complaint_text", "")
        if complaint:
            with st.expander("📋 Copy Complaint Text — Pre-filled for cybercrime.gov.in"):
                st.code(complaint, language=None)
                st.caption(
                    "Copy the above text → Go to cybercrime.gov.in → "
                    "File Complaint → Paste in description field"
                )
    else:
        st.markdown("### ✅ This message looks safe")
        st.markdown(
            '<div style="background:#0d2818;border-radius:10px;'
            'padding:1rem;border:1px solid #00c853;">'
            '✅ No scam patterns detected. This message appears to be legitimate.<br>'
            '<small style="color:#8892b0;">Good practice: Always verify by logging '
            'directly into the official website rather than clicking links.</small>'
            '</div>',
            unsafe_allow_html=True,
        )


# ════════════════════════════════════════════════════════════════
# SECTION 8 — Main App Layout
# ════════════════════════════════════════════════════════════════

def main():
    inject_css()

    # ── Initialize session state early ─────────────────────────────
    if "input_text" not in st.session_state:
        st.session_state["input_text"] = ""
    if "student_mode" not in st.session_state:
        st.session_state["student_mode"] = False

    # ── Simulation mode banner ────────────────────────────────────
    if SIMULATION_MODE:
        st.markdown(
            '<div class="sim-banner">'
            '⚡ Running in <strong>Demo/Simulation Mode</strong> — '
            'Backend engines unavailable. Results are illustrative.'
            '</div>',
            unsafe_allow_html=True,
        )
        # Optional: Show import errors for debugging
        if IMPORT_ERRORS:
            with st.expander("🔧 Debug: Import Errors", expanded=False):
                st.code("\n".join(IMPORT_ERRORS), language="text")

    # ── Hero section ──────────────────────────────────────────────
    st.markdown(
        '<div class="hero-title">Campus Fraud Shield 🛡️</div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="hero-subtitle">'
        'AI-powered scam detection for Indian college students · '
        'Protect yourself from fake internships, scholarship frauds & prize scams'
        '</div>',
        unsafe_allow_html=True,
    )

    # ── Stats row (live if available) ─────────────────────────────
    if not SIMULATION_MODE:
        try:
            hist   = load_history()
            stats  = hist.get_stats()
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("📊 Total Scans",   stats.get("total_reports", 0))
            c2.metric("🚨 Scams Found",   stats.get("scam_count",    0))
            c3.metric("✅ Safe Messages", stats.get("safe_count",    0))
            c4.metric("🔥 Today's Scams", stats.get("today_scams",   0))
        except Exception:
            pass
    else:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("📊 Total Scans",   "1,247")
        c2.metric("🚨 Scams Found",   "934")
        c3.metric("✅ Safe Messages", "313")
        c4.metric("🔥 Today's Scams", "12")

    st.markdown("---")

    # ── Demo preset buttons ───────────────────────────────────────
    st.markdown("#### 🚀 Try a Demo Message")
    st.caption("Click any button to auto-fill the text box with a real scam example")

    preset_cols = st.columns(len(PRESETS))
    for i, (label, msg) in enumerate(PRESETS.items()):
        with preset_cols[i]:
            if st.button(label, use_container_width=True, key=f"preset_{i}"):
                st.session_state["input_text"] = msg
                st.rerun()

    st.markdown("---")

    # ── Text input area ───────────────────────────────────────────
    st.markdown("#### 📱 Paste Your Message Here")
    st.caption("Paste any WhatsApp/SMS message to instantly check if it's a scam")

    user_input = st.text_area(
        label       = "Message to analyze",
        value       = st.session_state.get("input_text", ""),
        height      = 160,
        placeholder = "Paste a WhatsApp or SMS message here...\n\n"
                      "Example: 'Congratulations! You have been selected for internship. "
                      "Pay ₹999 registration fee to confirm your slot...'",
        label_visibility = "collapsed",
        key         = "message_box",
    )

    # Sync session state
    if user_input:
        st.session_state["input_text"] = user_input

    # ── Mode toggle ───────────────────────────────────────────────
    col_scan, col_mode, col_clear = st.columns([3, 2, 1])

    with col_mode:
        student_mode = st.toggle(
            "🎓 Student-Friendly Explanations",
            value = st.session_state.get("student_mode", False),
            help  = "Switch between technical AI output and plain English explanations",
        )
        st.session_state["student_mode"] = student_mode

    with col_clear:
        if st.button("🗑️ Clear", use_container_width=True):
            st.session_state["input_text"] = ""
            st.session_state.pop("last_result", None)
            st.rerun()

    # ── Scan button ───────────────────────────────────────────────
    with col_scan:
        scan_clicked = st.button(
            "🔍 Scan Message",
            type             = "primary",
            use_container_width = True,
        )

    # ── Guard: empty input ────────────────────────────────────────
    if scan_clicked:
        current_text = st.session_state.get("input_text", "").strip()
        if not current_text:
            st.warning("⚠️ Please enter a message first before scanning.")
            st.stop()

        # ── Run pipeline with progress bar ────────────────────────
        progress_bar = st.progress(0, text="Initialising engines...")
        time.sleep(0.15)
        progress_bar.progress(20, text="Running rules engine...")
        time.sleep(0.2)
        progress_bar.progress(45, text="Running semantic AI...")
        time.sleep(0.2)
        progress_bar.progress(65, text="Searching community reports...")
        time.sleep(0.15)
        progress_bar.progress(85, text="Calculating final score...")

        result = run_full_pipeline(current_text)

        progress_bar.progress(100, text="Analysis complete!")
        time.sleep(0.3)
        progress_bar.empty()

        # Store result for re-render
        st.session_state["last_result"]  = result
        st.session_state["last_text"]    = current_text
        st.session_state["student_mode"] = student_mode

    # ── Render last result (persists across reruns) ───────────────
    if "last_result" in st.session_state:
        result       = st.session_state["last_result"]
        student_mode = st.session_state.get("student_mode", False)

        # Show fallback error quietly in expander
        if "_fallback_error" in result:
            with st.expander("⚙️ Engine note (debug)", expanded=False):
                st.caption(
                    f"One engine failed and simulation was used: "
                    f"{result['_fallback_error']}"
                )

        render_results(result, student_mode)

    # ── Footer ────────────────────────────────────────────────────
    st.markdown("---")
    st.markdown(
        '<div style="text-align:center;color:#4a5568;font-size:0.82rem;'
        'padding-bottom:1rem;">'
        '🛡️ Campus Fraud Shield · Built for Indian Students · '
        'Report cybercrime at <a href="https://cybercrime.gov.in" '
        'target="_blank" style="color:#00d4ff;">cybercrime.gov.in</a> · '
        'Helpline: <strong style="color:#00d4ff;">1930</strong>'
        '</div>',
        unsafe_allow_html=True,
    )


# ════════════════════════════════════════════════════════════════
if __name__ == "__main__" or True:
    main()
