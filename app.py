import streamlit as st
import os
from datetime import datetime
from rules import run_rules
from scorer import calculate_final_score, decide, get_score_color
from trusted import check_trusted
from domain_check import check_domain
from model import get_ml_score
 
# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Campus Fraud Shield",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed",
)
 
# ─────────────────────────────────────────────────────────────────────────────
# CSS — single block, loaded once
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
 
*, html, body { font-family: 'Inter', sans-serif; box-sizing: border-box; }
.block-container { padding-top: 1rem !important; max-width: 780px !important; }
footer, #MainMenu, header { visibility: hidden; }
 
/* ── Hero ── */
.hero {
    background: linear-gradient(135deg,#1e1b4b,#4338ca,#1e1b4b);
    border-radius: 20px; padding: 36px 28px; text-align: center;
    margin-bottom: 28px; border: 1px solid #4338ca55;
    box-shadow: 0 8px 32px #6366f122;
}
.hero h1 { color:#fff; font-size:2rem; margin:0 0 6px; font-weight:700; letter-spacing:-0.5px; }
.hero p  { color:#a5b4fc; margin:0; font-size:0.95rem; }
 
/* ── Stat cards ── */
.stat-card {
    background:#fff; border:1px solid #e2e8f0;
    border-radius:12px; padding:16px 12px; text-align:center;
    box-shadow:0 2px 8px #0000000a;
}
.stat-num   { font-size:2rem; font-weight:700; line-height:1; }
.stat-label { font-size:0.72rem; color:#64748b; margin-top:4px; text-transform:uppercase; letter-spacing:.5px; }
 
/* ── Demo section ── */
.demo-header {
    display:flex; align-items:center; gap:10px;
    padding:10px 16px; border-radius:10px; margin:14px 0 8px;
    border-left:4px solid; font-weight:600; font-size:0.92rem;
}
.case-preview {
    background:#f0f9ff; border:1px solid #bae6fd;
    border-left:4px solid #0ea5e9; border-radius:10px;
    padding:12px 16px; margin:10px 0 6px;
    color:#0c4a6e; font-size:0.875rem; line-height:1.6;
}
 
/* ── Result card ── */
.result-card {
    border-radius:18px; padding:32px 24px; text-align:center;
    margin:16px 0; box-shadow:0 4px 20px #00000010;
}
.result-safe       { background:#f0fdf4; border:2px solid #22c55e; }
.result-suspicious { background:#fffbeb; border:2px solid #f59e0b; }
.result-scam       { background:#fff1f2; border:2px solid #ef4444; }
 
.result-icon  { font-size:3.5rem; line-height:1; margin-bottom:8px; }
.result-label { font-size:1.9rem; font-weight:700; margin:0; }
.result-score { font-size:2.8rem; font-weight:700; margin:4px 0; line-height:1; }
.result-score span { font-size:1rem; font-weight:400; }
 
.type-badge {
    display:inline-block; padding:5px 16px; border-radius:20px;
    font-size:0.82rem; font-weight:600; margin-top:10px; border:1px solid;
}
 
/* ── Score bar ── */
.bar-wrap  { background:#e2e8f0; border-radius:999px; height:12px; overflow:hidden; margin:14px 0 4px; }
.bar-fill  { height:100%; border-radius:999px; transition:width .4s ease; }
.bar-labels{ display:flex; justify-content:space-between; font-size:0.72rem; color:#94a3b8; }
 
/* ── Pills / cards ── */
.reason-pill {
    background:#f8fafc; border-left:4px solid #94a3b8;
    border-radius:0 10px 10px 0; padding:9px 14px;
    margin:5px 0; font-size:0.875rem; color:#1e293b; line-height:1.4;
}
.tip-card {
    background:#f8fafc; border:1px solid #e2e8f0; border-radius:10px;
    padding:10px 14px; margin:4px 0; font-size:0.83rem; color:#334155; line-height:1.5;
}
.action-card {
    border-radius:12px; padding:14px 18px;
    font-weight:600; font-size:0.93rem; margin-top:4px; border:1px solid;
}
.ml-card {
    background:#faf5ff; border:1px solid #c4b5fd; border-radius:10px;
    padding:11px 15px; margin:10px 0; font-size:0.875rem; color:#5b21b6;
}
.trusted-card {
    background:#f0fdf4; border:1px solid #86efac; border-radius:10px;
    padding:11px 15px; margin:10px 0; font-size:0.875rem; color:#15803d;
}
.breakdown-card {
    background:#f8fafc; border:1px solid #e2e8f0; border-radius:10px;
    padding:16px; font-family:monospace; font-size:0.85rem;
    color:#1e293b; white-space:pre; line-height:1.8; margin-top:10px;
}
 
/* ── Buttons ── */
div[data-testid="stButton"] > button {
    border-radius:10px; font-weight:600; font-size:0.9rem;
    transition:all .15s ease;
}
div[data-testid="stButton"] > button:hover {
    transform:translateY(-1px); box-shadow:0 4px 14px #6366f133;
}
 
/* ── Text area ── */
textarea {
    border-radius:12px !important; font-size:0.9rem !important;
    border:1.5px solid #e2e8f0 !important;
}
textarea:focus { border-color:#6366f1 !important; box-shadow:0 0 0 3px #6366f122 !important; }
 
/* ── Expander ── */
details { border:1px solid #e2e8f0 !important; border-radius:10px !important; }
 
hr { border:none; border-top:1px solid #e2e8f0; margin:20px 0; }
</style>
""", unsafe_allow_html=True)
 
 
# ─────────────────────────────────────────────────────────────────────────────
# SESSION STATE  (init once)
# ─────────────────────────────────────────────────────────────────────────────
_defaults = {
    "total": 0, "scams": 0, "safe": 0,
    "selected_text": "",        # text chosen from demo or typed
    "result": None,             # last analysis dict
    "analyzed_text": "",        # what was last analyzed
    "show_result": False,       # flag to render result section
}
for k, v in _defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v
 
 
# ─────────────────────────────────────────────────────────────────────────────
# STATIC DATA
# ─────────────────────────────────────────────────────────────────────────────
DEMO_CATEGORIES = [
    {
        "label": "💸 Payment Scam", "color": "#f59e0b", "bg": "#fffbeb",
        "cases": [
            "URGENT! Pay ₹999 registration fee via GPay to 9876543210 to confirm your Google internship. Limited slots!!!",
            "Congratulations! You won ₹50,000 in lucky draw. Pay ₹299 processing fee on PhonePe to claim your prize now!",
            "Your Amazon order is on hold. Scan QR and pay ₹49 customs fee within 2 hours or parcel will be returned.",
            "Work from home confirmed! Pay ₹500 refundable deposit via UPI to activate your employee account today.",
            "Dear student, pay ₹199 via Paytm to release your NPTEL certificate. Valid today only. Urgent!!!",
        ],
    },
    {
        "label": "🔐 Phishing", "color": "#3b82f6", "bg": "#eff6ff",
        "cases": [
            "Your SBI account is BLOCKED! Verify Aadhar + OTP at http://sbi-secure-login.tk/verify immediately.",
            "HDFC Alert: Suspicious login detected. Update KYC now at hdfc-kyc-update.xyz or account suspended in 24 hrs.",
            "Your UPI PIN has expired. Re-enter PIN and bank account at bit.ly/upi-renew to continue transactions.",
            "Your PAN card is linked to illegal activity. Call 9988776655 and share Aadhar OTP to avoid arrest.",
            "Google Account: Unusual sign-in blocked. Verify password at google-security-check.ml to restore access.",
        ],
    },
    {
        "label": "🎓 Fake Job", "color": "#8b5cf6", "bg": "#faf5ff",
        "cases": [
            "Earn ₹5000/day from home! No experience needed. WhatsApp 9123456789. Only 3 slots. 100% guaranteed income!",
            "You are SELECTED for Data Entry job. Salary ₹25000/month. No interview. Send Aadhar copy to confirm.",
            "Part time: Like YouTube videos and earn ₹300 per video! DM me on Instagram to start today!",
            "Campus placement at TCS! Selected candidates must pay ₹1500 training fee before joining. Reply to confirm.",
            "Saw your resume on Naukri. WFH job ₹40k/month. Share your bank account for salary setup process.",
        ],
    },
    {
        "label": "📱 Social Scam", "color": "#10b981", "bg": "#f0fdf4",
        "cases": [
            "Instagram seller: Designer bag ₹599 only! No COD, only GPay advance. DM me to order. Limited stock!",
            "I'm stuck abroad, need urgent help. Send ₹5000 on GPay. I will return double when I come back. Trust me!",
            "FREE iPhone 15 giveaway! Follow, like, share and pay ₹199 shipping fee to claim. Winners today!",
            "Selling NEET 2025 question paper for ₹2000. 100% authentic. WhatsApp me. Strictly confidential.",
            "Bro this app gives 3x returns in 7 days! I earned ₹15000. Join with my referral: bit.ly/earn3x",
        ],
    },
    {
        "label": "✅ Safe Messages", "color": "#22c55e", "bg": "#f0fdf4",
        "cases": [
            "Hey! Internshala posted new software internships at Google. Check linkedin.com for details. Deadline Friday.",
            "Reminder: NPTEL swayam.gov.in enrollment closes April 30th. Register before the deadline!",
            "Campus placement by Infosys on May 5th. Register on unstop.com before May 3rd. Bring updated resume.",
            "Your Coursera Python certificate is ready. Download it from coursera.org under your profile section.",
            "Hackathon on dare2compete.com is open! Team of 3-4. Last date to apply is this Sunday.",
        ],
    },
]
 
SCAM_TYPES = [
    ("payment",  "💸","Payment Fraud",         "#f59e0b", ["upi","qr","scan","gpay","phonepe","paytm","₹","registration fee","processing fee","customs fee"]),
    ("job",      "🎓","Fake Internship / Job", "#8b5cf6", ["internship","job","apply","hiring","selected","offer letter","work from home","earn per day","data entry","placement"]),
    ("phishing", "🔐","Phishing Attack",       "#3b82f6", ["otp","verify","account","password","login","bank","kyc","aadhar","suspended","blocked","pan card"]),
    ("link",     "🔗","Malicious Link",        "#ef4444", ["bit.ly","tinyurl","click","free","prize","won","lucky","lottery","gift card","giveaway","referral"]),
    ("social",   "📱","Social Media Scam",     "#10b981", ["instagram","dm","seller","order","product","cod","whatsapp","telegram"]),
]
 
SAFETY_TIPS = {
    "Scam":       ["🚫 Never share OTP — not even with bank staff",
                   "🔒 Real internships NEVER charge a registration fee",
                   "📞 Verify using the company's official website number",
                   "🗑️ Delete and block the sender immediately"],
    "Suspicious": ["🔍 Google company name + 'scam' before responding",
                   "📧 Only use official .com / .org / .gov websites",
                   "🤝 Ask a senior or professor before clicking any link",
                   "⏳ Scammers create urgency — never rush your decision"],
    "Safe":       ["✅ Still verify the sender's identity through official channels",
                   "🔗 Hover over links to preview the real URL first",
                   "🛡️ Keep your UPI PIN and passwords private always"],
}
 
 
# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def get_scam_type(text: str):
    t = text.lower()
    for _, emoji, label, color, kws in SCAM_TYPES:
        if any(k in t for k in kws):
            return emoji, label, color
    return "⚠️", "Suspicious Content", "#9ca3af"
 
 
@st.cache_data(show_spinner=False, ttl=300)
def analyze(text: str) -> dict:
    """
    Cached — same input = instant result, no recompute.
    ttl=300 means cache refreshes after 5 minutes.
    """
    rule_score,   rule_r   = run_rules(text)
    domain_score, domain_r = check_domain(text)
    is_trusted,   t_reason = check_trusted(text)
    ml_score, ml_reason, ml_conf = get_ml_score(text)
 
    all_reasons    = rule_r + domain_r
    trust_discount = 30 if is_trusted else 0
    raw            = calculate_final_score(rule_score, domain_score, ml_score)
    final_score    = max(0, min(raw - trust_discount, 100))
 
    label, emoji, action = decide(final_score)
    color                = get_score_color(label)
    te, tl, tc           = get_scam_type(text)
 
    return dict(
        rule_score=rule_score, domain_score=domain_score,
        ml_score=ml_score, ml_reason=ml_reason, ml_conf=ml_conf,
        final_score=final_score, label=label, emoji=emoji,
        action=action, color=color,
        type_emoji=te, type_label=tl, type_color=tc,
        all_reasons=all_reasons,
        is_trusted=is_trusted, trusted_reason=t_reason,
        trust_discount=trust_discount,
    )
 
 
def render_result(r: dict, input_text: str):
    label = r["label"]
    color = r["color"]
    fs    = r["final_score"]
    emoji = r["emoji"]
 
    # ── Update stats (once per unique text) ──────────────────────────────────
    if input_text != st.session_state.analyzed_text:
        st.session_state.total += 1
        if label == "Scam":   st.session_state.scams += 1
        elif label == "Safe": st.session_state.safe  += 1
        st.session_state.analyzed_text = input_text
 
    # ── Result card ───────────────────────────────────────────────────────────
    cls = {"Safe":"result-safe","Suspicious":"result-suspicious","Scam":"result-scam"}[label]
    tc, tl, tcol = r["type_emoji"], r["type_label"], r["type_color"]
    st.markdown(f"""
    <div class='result-card {cls}'>
        <div class='result-icon'>{emoji}</div>
        <p class='result-label' style='color:{color};'>{label}</p>
        <p class='result-score' style='color:{color};'>
            {fs}<span>/100</span>
        </p>
        <span class='type-badge'
              style='background:{tcol}18;color:{tcol};border-color:{tcol}55;'>
            {tc} {tl}
        </span>
    </div>""", unsafe_allow_html=True)
 
    # ── Score bar ─────────────────────────────────────────────────────────────
    st.markdown(f"""
    <div class='bar-wrap'>
        <div class='bar-fill'
             style='width:{fs}%;background:linear-gradient(90deg,{color}66,{color});'></div>
    </div>
    <div class='bar-labels'>
        <span>0 — Safe</span><span>50 — Suspicious</span><span>100 — Scam</span>
    </div>""", unsafe_allow_html=True)
 
    st.markdown("<br>", unsafe_allow_html=True)
 
    # ── Score breakdown ───────────────────────────────────────────────────────
    with st.expander("📊 Score Breakdown"):
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("📝 Rules",  f"{r['rule_score']}/100")
        col2.metric("🌐 Domain", f"{r['domain_score']}/100")
        col3.metric("🤖 ML",     f"{r['ml_score']}/100")
        col4.metric("🎯 Final",  f"{fs}/100")
        st.markdown(f"""<div class='breakdown-card'>
Rule Score   {r['rule_score']:>3}  ×  50%  =  {int(r['rule_score']*0.50):>3}
Domain Score {r['domain_score']:>3}  ×  30%  =  {int(r['domain_score']*0.30):>3}
ML Score     {r['ml_score']:>3}  ×  20%  =  {int(r['ml_score']*0.20):>3}
Trust Bonus                     = -{r['trust_discount']:>3}
───────────────────────────────────────────
Final Score                     =  {fs} / 100</div>""", unsafe_allow_html=True)
 
    # ── ML + Trusted badges ───────────────────────────────────────────────────
    if r["ml_reason"]:
        st.markdown(f"""<div class='ml-card'>
            🤖 <strong>ML Model</strong> &nbsp;·&nbsp; {r['ml_reason']}
        </div>""", unsafe_allow_html=True)
 
    if r["is_trusted"]:
        st.markdown(f"""<div class='trusted-card'>
            ✅ <strong>Trusted Platform Detected</strong> &nbsp;·&nbsp; {r['trusted_reason']}
        </div>""", unsafe_allow_html=True)
 
    # ── Reasons ───────────────────────────────────────────────────────────────
    st.markdown("### 🔎 Why this score?")
    reasons = r["all_reasons"]
    if reasons:
        for rr in reasons:
            st.markdown(
                f"<div class='reason-pill' style='border-color:{color};'>{rr}</div>",
                unsafe_allow_html=True)
    else:
        st.markdown(
            "<div class='reason-pill' style='border-color:#22c55e;'>"
            "✅ No suspicious patterns detected in this message.</div>",
            unsafe_allow_html=True)
 
    # ── Action ────────────────────────────────────────────────────────────────
    st.markdown("### 💡 Recommended Action")
    abg = {"Scam":"#fff1f2","Suspicious":"#fffbeb","Safe":"#f0fdf4"}[label]
    st.markdown(
        f"<div class='action-card' style='background:{abg};color:{color};border-color:{color}55;'>"
        f"{emoji}&nbsp; {r['action']}</div>",
        unsafe_allow_html=True)
 
    # ── Safety tips ───────────────────────────────────────────────────────────
    st.markdown("### 🧠 Campus Safety Tips")
    tips   = SAFETY_TIPS[label]
    tcols  = st.columns(2)
    for i, tip in enumerate(tips):
        with tcols[i % 2]:
            st.markdown(f"<div class='tip-card'>{tip}</div>", unsafe_allow_html=True)
 
    # ── Report ────────────────────────────────────────────────────────────────
    st.markdown("<hr>", unsafe_allow_html=True)
    if label in ["Scam", "Suspicious"]:
        st.markdown("##### 🚩 Help protect other students")
        if st.button("🚩 Report This Scam to Campus Shield",
                     use_container_width=True, key="report_btn"):
            try:
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                with open("reported_scams.txt", "a", encoding="utf-8") as f:
                    f.write(f"\n{'='*55}\n")
                    f.write(f"Reported At  : {ts}\n")
                    f.write(f"Label        : {label} ({fs}/100)\n")
                    f.write(f"Scam Type    : {tl}\n")
                    f.write(f"Rule / Domain / ML : {r['rule_score']} / {r['domain_score']} / {r['ml_score']}\n")
                    f.write(f"Message      :\n{input_text.strip()}\n")
                    f.write("Reasons      :\n" +
                            "\n".join(f"  · {x}" for x in reasons) + "\n")
                st.success("✅ Reported! This helps protect other students.")
                st.balloons()
            except Exception as e:
                st.error(f"Save failed: {e}")
 
    if os.path.exists("reported_scams.txt"):
        with st.expander("📂 View Scam Reports Log"):
            with open("reported_scams.txt", "r", encoding="utf-8") as f:
                st.code(f.read() or "No reports yet.", language="text")
 
    # ── Footer ────────────────────────────────────────────────────────────────
    st.markdown("""
    <div style='text-align:center;color:#94a3b8;font-size:0.78rem;
                padding:20px 0 8px;border-top:1px solid #e2e8f0;margin-top:20px;'>
        🛡️ <strong style='color:#6366f1;'>Campus Fraud Shield</strong>
        — Built to protect students · Always verify before you click, pay or share
    </div>""", unsafe_allow_html=True)
 
 
# ─────────────────────────────────────────────────────────────────────────────
# MAIN UI
# ─────────────────────────────────────────────────────────────────────────────
 
# ── Hero ──────────────────────────────────────────────────────────────────────
st.markdown("""
<div class='hero'>
    <h1>🛡️ Campus Fraud Shield</h1>
    <p>Paste any suspicious message, link or offer — get instant AI-powered risk analysis</p>
</div>""", unsafe_allow_html=True)
 
# ── Stats row ─────────────────────────────────────────────────────────────────
s1, s2, s3 = st.columns(3)
with s1:
    st.markdown(f"""<div class='stat-card'>
        <div class='stat-num' style='color:#6366f1;'>{st.session_state.total}</div>
        <div class='stat-label'>Total Analyzed</div></div>""", unsafe_allow_html=True)
with s2:
    st.markdown(f"""<div class='stat-card'>
        <div class='stat-num' style='color:#ef4444;'>{st.session_state.scams}</div>
        <div class='stat-label'>Scams Caught</div></div>""", unsafe_allow_html=True)
with s3:
    st.markdown(f"""<div class='stat-card'>
        <div class='stat-num' style='color:#22c55e;'>{st.session_state.safe}</div>
        <div class='stat-label'>Safe Messages</div></div>""", unsafe_allow_html=True)
 
st.markdown("<br>", unsafe_allow_html=True)
 
# ── Demo Mode ─────────────────────────────────────────────────────────────────
st.markdown("### 🎮 Demo Mode")
st.caption("Click any Case button → message auto-fills below → results appear instantly")
 
for cat in DEMO_CATEGORIES:
    clr = cat["color"]
    bg  = cat["bg"]
 
    # Category header
    st.markdown(
        f"<div class='demo-header' style='background:{bg};border-color:{clr};color:{clr};'>"
        f"{cat['label']}</div>",
        unsafe_allow_html=True)
 
    # Case buttons
    btns = st.columns(len(cat["cases"]))
    for i, case_text in enumerate(cat["cases"]):
        with btns[i]:
            if st.button(f"Case {i+1}",
                         key=f"{cat['label']}_{i}",
                         use_container_width=True):
                # Just update selected_text — NO rerun needed
                st.session_state.selected_text = case_text
                st.session_state.result        = None  # force re-analysis
 
    # Show preview if a case from THIS category is selected
    if st.session_state.selected_text in cat["cases"]:
        st.markdown(
            f"<div class='case-preview'>"
            f"<strong>📋 Selected message:</strong><br>"
            f"{st.session_state.selected_text}</div>",
            unsafe_allow_html=True)
 
st.markdown("<hr>", unsafe_allow_html=True)
 
# ── Manual input ──────────────────────────────────────────────────────────────
st.markdown("### 📋 Or Paste Your Own Message")
 
user_typed = st.text_area(
    label="msg", label_visibility="collapsed",
    value=st.session_state.selected_text,
    height=145,
    placeholder='e.g.  "Earn ₹5000 now!! Click bit.ly/xyz and share your OTP."',
    key="textarea",
)
 
# Sync: if user edits the box manually, use that
active_text = user_typed.strip() or st.session_state.selected_text.strip()
 
a_col, c_col = st.columns([5, 1])
with a_col:
    run_btn = st.button("🔍 Analyze Now", use_container_width=True)
with c_col:
    clear_btn = st.button("🗑️ Clear", use_container_width=True)
 
if clear_btn:
    st.session_state.selected_text = ""
    st.session_state.result        = None
    st.session_state.analyzed_text = ""
    st.rerun()   # only rerun on clear — not on every action
 
# ── Run analysis ──────────────────────────────────────────────────────────────
#
#  THREE cases that trigger analysis:
#  1. User clicked Analyze button
#  2. A demo case was clicked (selected_text changed, result is None)
#  3. A previous result exists — just re-render it without re-computing
#
need_analyze = (
    run_btn
    or (
        st.session_state.selected_text != ""
        and st.session_state.result is None
    )
)
 
if need_analyze:
    if not active_text:
        st.warning("⚠️ Please paste a message or pick a demo case first.")
    else:
        with st.spinner("Scanning for threats..."):
            # analyze() is cached — same input = zero recompute
            result = analyze(active_text)
        st.session_state.result = result
        render_result(result, active_text)
 
elif st.session_state.result is not None:
    # Re-render without re-running analysis
    render_result(st.session_state.result, st.session_state.analyzed_text)
 