import streamlit as st
import os
from datetime import datetime
from rules import run_rules
from scorer import calculate_final_score, decide, get_score_color
from trusted import check_trusted
from domain_check import check_domain
from model import get_ml_score
from ocr_qr import process_upload

# ── Sidebar state initialization ─────────────────────────────────────────────
if "sidebar_open" not in st.session_state:
    st.session_state.sidebar_open = True

 
# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Campus Fraud Shield",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="expanded",
)
 
# ─────────────────────────────────────────────────────────────────────────────
# CSS
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
*, html, body { font-family:'Inter',sans-serif; box-sizing:border-box; }
.block-container { padding-top:1rem !important; max-width:800px !important; }
footer, #MainMenu, header { visibility:hidden; }
 
/* ── Sidebar ── */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg,#1e1b4b 0%,#1e293b 100%);
    border-right: 1px solid #334155;
}
section[data-testid="stSidebar"] * { color:#e2e8f0 !important; }
.sb-title {
    font-size:1.1rem; font-weight:700; color:#a5b4fc !important;
    margin:0 0 4px; letter-spacing:-0.3px;
}
.sb-section {
    background:#ffffff14; border:1px solid #ffffff18;
    border-radius:10px; padding:12px 14px; margin:10px 0;
}
.sb-section-title {
    font-size:0.78rem; text-transform:uppercase; letter-spacing:.8px;
    color:#94a3b8 !important; font-weight:600; margin-bottom:8px;
}
.sb-item {
    display:flex; align-items:flex-start; gap:8px;
    padding:5px 0; border-bottom:1px solid #ffffff10; font-size:0.82rem;
}
.sb-item:last-child { border-bottom:none; }
.sb-item-icon { flex-shrink:0; margin-top:1px; }
.sb-item-text { line-height:1.4; }
.sb-item-num  { font-weight:700; color:#fbbf24 !important; font-size:0.88rem; }
.sb-badge {
    display:inline-block; background:#ef444422; border:1px solid #ef444455;
    border-radius:6px; padding:2px 8px; font-size:0.75rem; color:#fca5a5 !important;
    margin-top:3px;
}
.sb-safe-badge {
    display:inline-block; background:#22c55e22; border:1px solid #22c55e55;
    border-radius:6px; padding:2px 8px; font-size:0.75rem; color:#86efac !important;
}
 
/* ── Hero ── */
.hero {
    background:linear-gradient(135deg,#1e1b4b,#4338ca,#1e1b4b);
    border-radius:20px; padding:32px 24px; text-align:center;
    margin-bottom:24px; border:1px solid #4338ca55;
    box-shadow:0 8px 32px #6366f122;
}
.hero h1 { color:#fff; font-size:1.9rem; margin:0 0 6px; font-weight:700; }
.hero p  { color:#a5b4fc; margin:0; font-size:0.9rem; }
 
/* ── Stat cards ── */
.stat-card {
    background:#fff; border:1px solid #e2e8f0; border-radius:12px;
    padding:14px 10px; text-align:center; box-shadow:0 2px 8px #0000000a;
}
.stat-num   { font-size:1.8rem; font-weight:700; line-height:1; }
.stat-label { font-size:0.7rem; color:#64748b; margin-top:4px;
              text-transform:uppercase; letter-spacing:.5px; }
 
/* ── Tabs ── */
div[data-testid="stTabs"] button {
    font-weight:600 !important; font-size:0.88rem !important;
    border-radius:10px 10px 0 0 !important;
}
div[data-testid="stTabs"] button[aria-selected="true"] {
    color:#6366f1 !important; border-bottom:2px solid #6366f1 !important;
}
 
/* ── Upload zone ── */
.upload-zone {
    background:#f8fafc; border:2px dashed #cbd5e1; border-radius:14px;
    padding:28px; text-align:center; margin:12px 0; cursor:pointer;
    transition:border-color .2s, background .2s;
}
.upload-zone:hover { border-color:#6366f1; background:#eff6ff; }
.upload-zone h3 { color:#334155; font-size:1rem; margin:8px 0 4px; }
.upload-zone p  { color:#94a3b8; font-size:0.82rem; margin:0; }
 
/* ── Extracted text box ── */
.extracted-box {
    background:#f0f9ff; border:1px solid #bae6fd;
    border-left:4px solid #0ea5e9; border-radius:10px;
    padding:14px 16px; margin:12px 0;
    color:#0c4a6e; font-size:0.875rem; line-height:1.6;
    max-height:160px; overflow-y:auto;
}
.extracted-label {
    font-size:0.75rem; font-weight:600; text-transform:uppercase;
    letter-spacing:.5px; color:#0369a1; margin-bottom:6px;
}
 
/* ── Demo ── */
.demo-header {
    display:flex; align-items:center; gap:10px; padding:10px 16px;
    border-radius:10px; margin:12px 0 8px; border-left:4px solid;
    font-weight:600; font-size:0.9rem;
}
.case-preview {
    background:#f0f9ff; border:1px solid #bae6fd;
    border-left:4px solid #0ea5e9; border-radius:10px;
    padding:12px 16px; margin:10px 0 6px;
    color:#0c4a6e; font-size:0.875rem; line-height:1.6;
}
 
/* ── Result ── */
.result-card { border-radius:18px; padding:28px 22px; text-align:center; margin:14px 0; box-shadow:0 4px 20px #00000010; }
.result-safe       { background:#f0fdf4; border:2px solid #22c55e; }
.result-suspicious { background:#fffbeb; border:2px solid #f59e0b; }
.result-scam       { background:#fff1f2; border:2px solid #ef4444; }
.result-icon  { font-size:3rem; line-height:1; margin-bottom:6px; }
.result-label { font-size:1.8rem; font-weight:700; margin:0; }
.result-score { font-size:2.6rem; font-weight:700; margin:4px 0; line-height:1; }
.result-score span { font-size:1rem; font-weight:400; }
.type-badge {
    display:inline-block; padding:5px 14px; border-radius:20px;
    font-size:0.8rem; font-weight:600; margin-top:8px; border:1px solid;
}
 
/* ── Score bar ── */
.bar-wrap   { background:#e2e8f0; border-radius:999px; height:12px; overflow:hidden; margin:12px 0 4px; }
.bar-fill   { height:100%; border-radius:999px; }
.bar-labels { display:flex; justify-content:space-between; font-size:0.72rem; color:#94a3b8; }
 
/* ── Pills / cards ── */
.reason-pill {
    background:#f8fafc; border-left:4px solid; border-radius:0 10px 10px 0;
    padding:9px 14px; margin:5px 0; font-size:0.875rem; color:#1e293b; line-height:1.4;
}
.tip-card {
    background:#f8fafc; border:1px solid #e2e8f0; border-radius:10px;
    padding:10px 14px; margin:4px 0; font-size:0.83rem; color:#334155;
}
.action-card { border-radius:12px; padding:14px 18px; font-weight:600; font-size:0.93rem; margin-top:4px; border:1px solid; }
.ml-card     { background:#faf5ff; border:1px solid #c4b5fd; border-radius:10px; padding:11px 15px; margin:10px 0; font-size:0.875rem; color:#5b21b6; }
.trusted-card{ background:#f0fdf4; border:1px solid #86efac; border-radius:10px; padding:11px 15px; margin:10px 0; font-size:0.875rem; color:#15803d; }
.breakdown-card {
    background:#f8fafc; border:1px solid #e2e8f0; border-radius:10px;
    padding:16px; font-family:monospace; font-size:0.84rem;
    color:#1e293b; white-space:pre; line-height:1.8; margin-top:10px;
}
 
/* ── History ── */
.hist-card {
    background:#fff; border:1px solid #e2e8f0; border-radius:14px;
    padding:14px 16px; margin:10px 0; box-shadow:0 2px 10px #0000000a;
}
.hist-top  { display:flex; align-items:center; justify-content:space-between; gap:10px; }
.hist-badge{ display:inline-flex; align-items:center; gap:6px; padding:4px 12px; border-radius:20px; font-size:0.8rem; font-weight:700; border:1px solid; }
.hist-score{ font-size:1.4rem; font-weight:700; }
.hist-type { font-size:0.76rem; color:#64748b; margin-top:2px; }
.hist-msg  { margin-top:10px; padding-top:10px; border-top:1px solid #f1f5f9; font-size:0.84rem; color:#374151; line-height:1.5; display:-webkit-box; -webkit-line-clamp:2; -webkit-box-orient:vertical; overflow:hidden; }
.hist-meta { font-size:0.74rem; color:#94a3b8; margin-top:5px; }
.hist-empty{ text-align:center; padding:48px 24px; color:#94a3b8; }
.hist-empty div { font-size:3rem; margin-bottom:12px; }
 
/* ── Buttons ── */
div[data-testid="stButton"] > button {
    border-radius:10px; font-weight:600; font-size:0.88rem; transition:all .15s;
}
div[data-testid="stButton"] > button:hover { transform:translateY(-1px); box-shadow:0 4px 14px #6366f133; }
textarea { border-radius:12px !important; font-size:0.9rem !important; border:1.5px solid #e2e8f0 !important; }
textarea:focus { border-color:#6366f1 !important; box-shadow:0 0 0 3px #6366f122 !important; }
details { border:1px solid #e2e8f0 !important; border-radius:10px !important; }
hr { border:none; border-top:1px solid #e2e8f0; margin:18px 0; }
</style>
""", unsafe_allow_html=True)
 
 
# ─────────────────────────────────────────────────────────────────────────────
# SESSION STATE
# ─────────────────────────────────────────────────────────────────────────────
for k, v in {
    "total":0,"scams":0,"safe":0,
    "selected_text":"","result":None,"analyzed_text":"",
    "history":[],
}.items():
    if k not in st.session_state:
        st.session_state[k] = v
 
 
# ─────────────────────────────────────────────────────────────────────────────
# SIDEBAR — Safety Resources
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("<p class='sb-title'>🛡️ Campus Fraud Shield</p>", unsafe_allow_html=True)
    st.markdown("<p style='font-size:0.75rem;color:#64748b;margin-top:-4px;'>Your campus safety companion</p>", unsafe_allow_html=True)
 
    st.markdown("<hr style='border-color:#334155;margin:10px 0;'>", unsafe_allow_html=True)
 
    # ── Emergency Helplines ───────────────────────────────────────────────────
    st.markdown("""
    <div class='sb-section'>
        <div class='sb-section-title'>🆘 Emergency Helplines</div>
        <div class='sb-item'>
            <span class='sb-item-icon'>🚔</span>
            <div class='sb-item-text'>
                <b>Cyber Crime</b><br>
                <span class='sb-item-num'>1930</span>
                <span class='sb-badge'>24/7</span><br>
                <span style='font-size:0.75rem;'>National Cyber Crime Helpline</span>
            </div>
        </div>
        <div class='sb-item'>
            <span class='sb-item-icon'>👮</span>
            <div class='sb-item-text'>
                <b>Police</b><br>
                <span class='sb-item-num'>100</span>
                <span class='sb-badge'>Emergency</span>
            </div>
        </div>
        <div class='sb-item'>
            <span class='sb-item-icon'>👩‍⚖️</span>
            <div class='sb-item-text'>
                <b>Women Helpline</b><br>
                <span class='sb-item-num'>1091</span>
            </div>
        </div>
        <div class='sb-item'>
            <span class='sb-item-icon'>🏦</span>
            <div class='sb-item-text'>
                <b>Bank Fraud</b><br>
                <span class='sb-item-num'>155260</span><br>
                <span style='font-size:0.75rem;'>RBI Fraud Reporting</span>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
 
    # ── Report Portals ────────────────────────────────────────────────────────
    st.markdown("""
    <div class='sb-section'>
        <div class='sb-section-title'>🌐 Official Report Portals</div>
        <div class='sb-item'>
            <span class='sb-item-icon'>💻</span>
            <div class='sb-item-text'>
                <b>Cyber Crime Portal</b><br>
                <span style='font-size:0.78rem;color:#93c5fd;'>cybercrime.gov.in</span>
            </div>
        </div>
        <div class='sb-item'>
            <span class='sb-item-icon'>📱</span>
            <div class='sb-item-text'>
                <b>Report Spam SMS/Call</b><br>
                <span style='font-size:0.78rem;color:#93c5fd;'>sancharsaathi.gov.in</span>
            </div>
        </div>
        <div class='sb-item'>
            <span class='sb-item-icon'>🏛️</span>
            <div class='sb-item-text'>
                <b>Consumer Forum</b><br>
                <span style='font-size:0.78rem;color:#93c5fd;'>consumerhelpline.gov.in</span>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
 
    # ── Campus Trusted Links ──────────────────────────────────────────────────
    st.markdown("""
    <div class='sb-section'>
        <div class='sb-section-title'>✅ Trusted Campus Platforms</div>
        <div class='sb-item'><span class='sb-item-icon'>🎓</span>
            <div class='sb-item-text'>internshala.com <span class='sb-safe-badge'>Safe</span></div>
        </div>
        <div class='sb-item'><span class='sb-item-icon'>💼</span>
            <div class='sb-item-text'>linkedin.com <span class='sb-safe-badge'>Safe</span></div>
        </div>
        <div class='sb-item'><span class='sb-item-icon'>🏆</span>
            <div class='sb-item-text'>unstop.com <span class='sb-safe-badge'>Safe</span></div>
        </div>
        <div class='sb-item'><span class='sb-item-icon'>📚</span>
            <div class='sb-item-text'>swayam.gov.in <span class='sb-safe-badge'>Safe</span></div>
        </div>
        <div class='sb-item'><span class='sb-item-icon'>📖</span>
            <div class='sb-item-text'>nptel.ac.in <span class='sb-safe-badge'>Safe</span></div>
        </div>
        <div class='sb-item'><span class='sb-item-icon'>💻</span>
            <div class='sb-item-text'>dare2compete.com <span class='sb-safe-badge'>Safe</span></div>
        </div>
        <div class='sb-item'><span class='sb-item-icon'>🔍</span>
            <div class='sb-item-text'>naukri.com <span class='sb-safe-badge'>Safe</span></div>
        </div>
    </div>
    """, unsafe_allow_html=True)
 
    # ── Golden Rules ──────────────────────────────────────────────────────────
    st.markdown("""
    <div class='sb-section'>
        <div class='sb-section-title'>🔑 Golden Rules</div>
        <div class='sb-item'><span class='sb-item-icon'>🚫</span>
            <div class='sb-item-text'>Never share OTP with anyone</div>
        </div>
        <div class='sb-item'><span class='sb-item-icon'>💰</span>
            <div class='sb-item-text'>Real jobs never ask for fees</div>
        </div>
        <div class='sb-item'><span class='sb-item-icon'>🔗</span>
            <div class='sb-item-text'>Avoid bit.ly and short links</div>
        </div>
        <div class='sb-item'><span class='sb-item-icon'>⏰</span>
            <div class='sb-item-text'>Urgency = red flag. Always.</div>
        </div>
        <div class='sb-item'><span class='sb-item-icon'>✅</span>
            <div class='sb-item-text'>Verify on official website only</div>
        </div>
    </div>
    """, unsafe_allow_html=True)
 
    st.markdown("""
    <div style='text-align:center;padding:12px 0 4px;font-size:0.72rem;color:#475569;'>
        🛡️ Campus Fraud Shield<br>Stay safe. Stay smart.
    </div>""", unsafe_allow_html=True)
 
 
# ─────────────────────────────────────────────────────────────────────────────
# STATIC DATA
# ─────────────────────────────────────────────────────────────────────────────
DEMO_CATEGORIES = [
    {"label":"💸 Payment Scam","color":"#f59e0b","bg":"#fffbeb","cases":[
        "URGENT! Pay ₹999 registration fee via GPay to 9876543210 to confirm your Google internship. Limited slots!!!",
        "Congratulations! You won ₹50,000 in lucky draw. Pay ₹299 processing fee on PhonePe to claim your prize now!",
        "Your Amazon order is on hold. Scan QR and pay ₹49 customs fee within 2 hours or parcel will be returned.",
        "Work from home confirmed! Pay ₹500 refundable deposit via UPI to activate your employee account today.",
        "Dear student, pay ₹199 via Paytm to release your NPTEL certificate. Valid today only. Urgent!!!",
    ]},
    {"label":"🔐 Phishing","color":"#3b82f6","bg":"#eff6ff","cases":[
        "Your SBI account is BLOCKED! Verify Aadhar + OTP at http://sbi-secure-login.tk/verify immediately.",
        "HDFC Alert: Suspicious login detected. Update KYC now at hdfc-kyc-update.xyz or account suspended in 24 hrs.",
        "Your UPI PIN has expired. Re-enter PIN and bank account at bit.ly/upi-renew to continue transactions.",
        "Your PAN card is linked to illegal activity. Call 9988776655 and share Aadhar OTP to avoid arrest.",
        "Google Account: Unusual sign-in blocked. Verify password at google-security-check.ml to restore access.",
    ]},
    {"label":"🎓 Fake Job","color":"#8b5cf6","bg":"#faf5ff","cases":[
        "Earn ₹5000/day from home! No experience needed. WhatsApp 9123456789. Only 3 slots. 100% guaranteed income!",
        "You are SELECTED for Data Entry job. Salary ₹25000/month. No interview. Send Aadhar copy to confirm.",
        "Part time: Like YouTube videos and earn ₹300 per video! DM me on Instagram to start today!",
        "Campus placement at TCS! Selected candidates must pay ₹1500 training fee before joining. Reply to confirm.",
        "Saw your resume on Naukri. WFH job ₹40k/month. Share your bank account for salary setup process.",
    ]},
    {"label":"📱 Social Scam","color":"#10b981","bg":"#f0fdf4","cases":[
        "Instagram seller: Designer bag ₹599 only! No COD, only GPay advance. DM me to order. Limited stock!",
        "I'm stuck abroad, need urgent help. Send ₹5000 on GPay. I will return double when I come back. Trust me!",
        "FREE iPhone 15 giveaway! Follow, like, share and pay ₹199 shipping fee to claim. Winners today!",
        "Selling NEET 2025 question paper for ₹2000. 100% authentic. WhatsApp me. Strictly confidential.",
        "Bro this app gives 3x returns in 7 days! I earned ₹15000. Join with my referral: bit.ly/earn3x",
    ]},
    {"label":"✅ Safe Messages","color":"#22c55e","bg":"#f0fdf4","cases":[
        "Hey! Internshala posted new software internships at Google. Check linkedin.com for details. Deadline Friday.",
        "Reminder: NPTEL swayam.gov.in enrollment closes April 30th. Register before the deadline!",
        "Campus placement by Infosys on May 5th. Register on unstop.com before May 3rd. Bring updated resume.",
        "Your Coursera Python certificate is ready. Download it from coursera.org under your profile section.",
        "Hackathon on dare2compete.com is open! Team of 3-4. Last date to apply is this Sunday.",
    ]},
]
 
SCAM_TYPES = [
    ("payment", "💸","Payment Fraud",         "#f59e0b",["upi","qr","scan","gpay","phonepe","paytm","₹","registration fee","processing fee","customs fee"]),
    ("job",     "🎓","Fake Internship / Job", "#8b5cf6",["internship","job","apply","hiring","selected","offer letter","work from home","earn per day","data entry","placement"]),
    ("phish",   "🔐","Phishing Attack",       "#3b82f6",["otp","verify","account","password","login","bank","kyc","aadhar","suspended","blocked","pan card"]),
    ("link",    "🔗","Malicious Link",        "#ef4444",["bit.ly","tinyurl","click","free","prize","won","lucky","lottery","gift card","giveaway","referral"]),
    ("social",  "📱","Social Media Scam",     "#10b981",["instagram","dm","seller","order","product","cod","whatsapp","telegram"]),
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
    "Safe":       ["✅ Still verify the sender's identity officially",
                   "🔗 Hover over links to preview the real URL first",
                   "🛡️ Keep your UPI PIN and passwords private always"],
}
 
LABEL_BG    = {"Safe":"#f0fdf4","Suspicious":"#fffbeb","Scam":"#fff1f2"}
LABEL_EMOJI = {"Safe":"✅","Suspicious":"⚠️","Scam":"🚫"}
 
 
# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def get_scam_type(text):
    t = text.lower()
    for _, emoji, label, color, kws in SCAM_TYPES:
        if any(k in t for k in kws):
            return emoji, label, color
    return "⚠️","Suspicious Content","#9ca3af"
 
 
@st.cache_data(show_spinner=False, ttl=300)
def analyze(text: str) -> dict:
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
 
 
def save_history(r, text, source="✍️ Text"):
    if any(h["text"] == text for h in st.session_state.history):
        return
    st.session_state.history.insert(0, {
        "text": text, "label": r["label"], "score": r["final_score"],
        "type_label": r["type_label"], "type_emoji": r["type_emoji"],
        "type_color": r["type_color"], "color": r["color"],
        "reasons": r["all_reasons"],
        "time": datetime.now().strftime("%I:%M %p"),
        "source": source, "result": r,
    })
 
 
def render_bar(fs, color):
    st.markdown(f"""
    <div class='bar-wrap'>
        <div class='bar-fill' style='width:{fs}%;background:linear-gradient(90deg,{color}66,{color});'></div>
    </div>
    <div class='bar-labels'>
        <span>0 — Safe</span><span>50 — Suspicious</span><span>100 — Scam</span>
    </div>""", unsafe_allow_html=True)
 
 
def render_result(r, input_text, source="✍️ Text"):
    label = r["label"]; color = r["color"]; fs = r["final_score"]
    emoji = r["emoji"]; tc,tl,tcol = r["type_emoji"],r["type_label"],r["type_color"]
 
    if input_text != st.session_state.analyzed_text:
        st.session_state.total += 1
        if label=="Scam":   st.session_state.scams += 1
        elif label=="Safe": st.session_state.safe  += 1
        st.session_state.analyzed_text = input_text
        save_history(r, input_text, source)
 
    cls = {"Safe":"result-safe","Suspicious":"result-suspicious","Scam":"result-scam"}[label]
    st.markdown(f"""
    <div class='result-card {cls}'>
        <div class='result-icon'>{emoji}</div>
        <p class='result-label' style='color:{color};'>{label}</p>
        <p class='result-score' style='color:{color};'>{fs}<span>/100</span></p>
        <span class='type-badge' style='background:{tcol}18;color:{tcol};border-color:{tcol}55;'>
            {tc} {tl}</span>
    </div>""", unsafe_allow_html=True)
 
    render_bar(fs, color)
    st.markdown("<br>", unsafe_allow_html=True)
 
    with st.expander("📊 Score Breakdown"):
        c1,c2,c3,c4 = st.columns(4)
        c1.metric("📝 Rules",  f"{r['rule_score']}/100")
        c2.metric("🌐 Domain", f"{r['domain_score']}/100")
        c3.metric("🤖 ML",     f"{r['ml_score']}/100")
        c4.metric("🎯 Final",  f"{fs}/100")
        st.markdown(f"""<div class='breakdown-card'>
Rule Score   {r['rule_score']:>3}  ×  50%  =  {int(r['rule_score']*0.50):>3}
Domain Score {r['domain_score']:>3}  ×  30%  =  {int(r['domain_score']*0.30):>3}
ML Score     {r['ml_score']:>3}  ×  20%  =  {int(r['ml_score']*0.20):>3}
Trust Bonus                     = -{r['trust_discount']:>3}
───────────────────────────────────────────
Final Score                     =  {fs} / 100</div>""", unsafe_allow_html=True)
 
    if r["ml_reason"]:
        st.markdown(f"<div class='ml-card'>🤖 <strong>ML Model</strong> · {r['ml_reason']}</div>",
                    unsafe_allow_html=True)
    if r["is_trusted"]:
        st.markdown(f"<div class='trusted-card'>✅ <strong>Trusted Platform</strong> · {r['trusted_reason']}</div>",
                    unsafe_allow_html=True)
 
    st.markdown("### 🔎 Why this score?")
    reasons = r["all_reasons"]
    if reasons:
        for rr in reasons:
            st.markdown(f"<div class='reason-pill' style='border-color:{color};'>{rr}</div>",
                        unsafe_allow_html=True)
    else:
        st.markdown("<div class='reason-pill' style='border-color:#22c55e;'>"
                    "✅ No suspicious patterns detected.</div>", unsafe_allow_html=True)
 
    st.markdown("### 💡 Recommended Action")
    abg = LABEL_BG[label]
    st.markdown(f"<div class='action-card' style='background:{abg};color:{color};border-color:{color}55;'>"
                f"{emoji}&nbsp; {r['action']}</div>", unsafe_allow_html=True)
 
    st.markdown("### 🧠 Campus Safety Tips")
    tcols = st.columns(2)
    for i, tip in enumerate(SAFETY_TIPS[label]):
        with tcols[i%2]:
            st.markdown(f"<div class='tip-card'>{tip}</div>", unsafe_allow_html=True)
 
    st.markdown("<hr>", unsafe_allow_html=True)
    if label in ["Scam","Suspicious"]:
        st.markdown("##### 🚩 Help protect other students")
        if st.button("🚩 Report This Scam", use_container_width=True, key=f"report_{source}"):
            try:
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                with open("reported_scams.txt","a",encoding="utf-8") as f:
                    f.write(f"\n{'='*55}\n")
                    f.write(f"Reported At : {ts}\n")
                    f.write(f"Source      : {source}\n")
                    f.write(f"Label       : {label} ({fs}/100)\n")
                    f.write(f"Scam Type   : {tl}\n")
                    f.write(f"Message     :\n{input_text.strip()}\n")
                    f.write("Reasons     :\n"+"\n".join(f"  · {x}" for x in reasons)+"\n")
                st.success("✅ Reported! Helping protect other students.")
                st.balloons()
            except Exception as e:
                st.error(f"Save failed: {e}")
 
    if os.path.exists("reported_scams.txt"):
        with st.expander("📂 Scam Reports Log"):
            with open("reported_scams.txt","r",encoding="utf-8") as f:
                st.code(f.read() or "No reports yet.", language="text")
 
    st.markdown("""<div style='text-align:center;color:#94a3b8;font-size:0.75rem;
        padding:16px 0 4px;border-top:1px solid #e2e8f0;margin-top:16px;'>
        🛡️ Campus Fraud Shield · Always verify before you click, pay or share
    </div>""", unsafe_allow_html=True)
 
 
def render_history_tab():
    history = st.session_state.history
    if not history:
        st.markdown("""<div class='hist-empty'>
            <div>🔍</div>
            <p><strong>No scans yet</strong><br>
            Go to Analyze, Image, or QR tab to get started.</p>
        </div>""", unsafe_allow_html=True)
        return
 
    total  = len(history)
    scams  = sum(1 for h in history if h["label"]=="Scam")
    suspic = sum(1 for h in history if h["label"]=="Suspicious")
    safe   = sum(1 for h in history if h["label"]=="Safe")
 
    h1,h2,h3,h4 = st.columns(4)
    with h1: st.markdown(f"""<div class='stat-card'><div class='stat-num' style='color:#6366f1;'>{total}</div><div class='stat-label'>Total Scans</div></div>""", unsafe_allow_html=True)
    with h2: st.markdown(f"""<div class='stat-card'><div class='stat-num' style='color:#ef4444;'>{scams}</div><div class='stat-label'>Scams</div></div>""", unsafe_allow_html=True)
    with h3: st.markdown(f"""<div class='stat-card'><div class='stat-num' style='color:#f59e0b;'>{suspic}</div><div class='stat-label'>Suspicious</div></div>""", unsafe_allow_html=True)
    with h4: st.markdown(f"""<div class='stat-card'><div class='stat-num' style='color:#22c55e;'>{safe}</div><div class='stat-label'>Safe</div></div>""", unsafe_allow_html=True)
 
    st.markdown("<br>", unsafe_allow_html=True)
 
    col_f1, col_f2 = st.columns([3,1])
    with col_f1:
        fltr = st.selectbox("Filter",["All","🚫 Scam","⚠️ Suspicious","✅ Safe"],
                            label_visibility="collapsed")
    with col_f2:
        if st.button("🗑️ Clear", use_container_width=True, key="clear_hist"):
            st.session_state.history=[]; st.session_state.total=0
            st.session_state.scams=0; st.session_state.safe=0
            st.session_state.analyzed_text=""; st.rerun()
 
    fmap = {"All":None,"🚫 Scam":"Scam","⚠️ Suspicious":"Suspicious","✅ Safe":"Safe"}
    filtered = [h for h in history if fmap[fltr] is None or h["label"]==fmap[fltr]]
 
    if not filtered:
        st.info(f"No {fmap[fltr]} results in history yet.")
        return
 
    st.markdown(f"**{len(filtered)} scan{'s' if len(filtered)!=1 else ''}**")
    st.markdown("<br>", unsafe_allow_html=True)
 
    for idx, h in enumerate(filtered):
        color = h["color"]; label = h["label"]
        msg_p = h["text"][:120]+("..." if len(h["text"])>120 else "")
        src_icon = {"✍️ Text":"✍️","📸 Screenshot":"📸","📷 QR Code":"📷"}.get(h.get("source","✍️ Text"),"✍️")
 
        st.markdown(f"""
        <div class='hist-card'>
            <div class='hist-top'>
                <span class='hist-badge' style='background:{color}18;color:{color};border-color:{color}55;'>
                    {LABEL_EMOJI[label]} {label}
                </span>
                <span class='hist-score' style='color:{color};'>{h['score']}<span style='font-size:0.85rem;font-weight:400;'>/100</span></span>
                <span style='flex:1;'></span>
                <span style='font-size:0.72rem;color:#94a3b8;'>{src_icon} {h['time']}</span>
            </div>
            <div class='hist-type'>{h['type_emoji']} {h['type_label']}</div>
            <div class='hist-msg'>{msg_p}</div>
            <div class='hist-meta'>{len(h['reasons'])} flag{'s' if len(h['reasons'])!=1 else ''} detected</div>
        </div>""", unsafe_allow_html=True)
 
        with st.expander(f"Details — Scan #{len(history)-history.index(h)}"):
            st.markdown("**Full message:**")
            st.info(h["text"])
            if h["reasons"]:
                st.markdown("**Detected flags:**")
                for rr in h["reasons"]:
                    st.markdown(f"<div class='reason-pill' style='border-color:{color};'>{rr}</div>",
                                unsafe_allow_html=True)
            render_bar(h["score"], color)
            if st.button("🔁 Re-analyze", key=f"re_{idx}", use_container_width=True):
                st.session_state.selected_text = h["text"]
                st.session_state.result = None
                st.rerun()
 
    st.markdown("<hr>", unsafe_allow_html=True)
    if st.button("📥 Export History", use_container_width=True):
        lines = ["Campus Fraud Shield — Session History\n"+"="*50+"\n"]
        for i,h in enumerate(history,1):
            lines.append(
                f"[{i}] {h['time']} | {h['label']} | {h['score']}/100 | {h['type_label']} | {h.get('source','Text')}\n"
                f"    {h['text'][:80]}{'...' if len(h['text'])>80 else ''}\n"
                f"    Flags: {', '.join(h['reasons'][:3]) if h['reasons'] else 'None'}\n"
            )
        st.download_button("⬇️ Download history.txt", "\n".join(lines),
                           "cfs_history.txt","text/plain", use_container_width=True)
 
 
# ─────────────────────────────────────────────────────────────────────────────
## ─────────────────────────────────────────────────────────────────────────────
# MAIN UI
# ─────────────────────────────────────────────────────────────────────────────

# ── Sidebar state init ────────────────────────────────────────────────────────
if "sidebar_open" not in st.session_state:
    st.session_state.sidebar_open = True


# ── Top bar (toggle + title) ──────────────────────────────────────────────────
with st.container():
    toggle_col, title_col = st.columns([1, 6])

    with toggle_col:
        if st.button("☰", key="sidebar_toggle", help="Toggle Safety Resources"):
            st.session_state.sidebar_open = not st.session_state.sidebar_open

    with title_col:
        st.markdown("""
        <div class='hero'>
            <h1>🛡️ Campus Fraud Shield</h1>
            <p>Paste a message · Upload a screenshot · Scan a QR code — instant risk analysis</p>
        </div>
        """, unsafe_allow_html=True)


# ── Stats ─────────────────────────────────────────────────────────────────────
s1, s2, s3 = st.columns(3)

with s1:
    st.markdown(f"""
    <div class='stat-card'>
        <div class='stat-num' style='color:#6366f1;'>{st.session_state.total}</div>
        <div class='stat-label'>Total Analyzed</div>
    </div>
    """, unsafe_allow_html=True)

with s2:
    st.markdown(f"""
    <div class='stat-card'>
        <div class='stat-num' style='color:#ef4444;'>{st.session_state.scams}</div>
        <div class='stat-label'>Scams Caught</div>
    </div>
    """, unsafe_allow_html=True)

with s3:
    st.markdown(f"""
    <div class='stat-card'>
        <div class='stat-num' style='color:#22c55e;'>{st.session_state.safe}</div>
        <div class='stat-label'>Safe Messages</div>
    </div>
    """, unsafe_allow_html=True)


st.markdown("<br>", unsafe_allow_html=True)


# ── Sidebar control (CRITICAL POSITION) ───────────────────────────────────────
if st.session_state.sidebar_open:
    with st.sidebar:
        st.markdown("## 🛡️ Safety Resources")

        st.markdown("""
        <div style='font-size:0.9rem; line-height:1.6;'>
        🔒 <strong>Stay Safe Online</strong><br><br>
        • Never share OTP or passwords<br>
        • Avoid clicking unknown links<br>
        • Check domain names carefully<br>
        • Beware of urgency messages<br>
        • Scan QR codes safely<br><br>

        ⚠️ <strong>Common Scam Signs:</strong><br>
        • “Urgent action required”<br>
        • Fake payment requests<br>
        • Suspicious links<br>
        • Unknown senders<br>
        </div>
        """, unsafe_allow_html=True)
else:
    st.markdown("""
    <style>
    [data-testid="stSidebar"] {
        display: none;
    }
    </style>
    """, unsafe_allow_html=True)


# ── Tabs ──────────────────────────────────────────────────────────────────────
hist_count = len(st.session_state.history)

tab1, tab2, tab3, tab4 = st.tabs([
    "🔍 Analyze Text",
    "📸 Screenshot (OCR)",
    "📷 QR Code",
    f"📋 History ({hist_count})",
])
#
 
# ══════════════════════════════════════════════════════════════════════════════
# TAB 1 — ANALYZE TEXT
# ══════════════════════════════════════════════════════════════════════════════
with tab1:
    st.markdown("### 🎮 Demo Mode")
    st.caption("Click any Case → message fills below → analyzed automatically")
 
    for cat in DEMO_CATEGORIES:
        clr,bg = cat["color"],cat["bg"]
        st.markdown(f"<div class='demo-header' style='background:{bg};border-color:{clr};color:{clr};'>{cat['label']}</div>",
                    unsafe_allow_html=True)
        btns = st.columns(len(cat["cases"]))
        for i,ct in enumerate(cat["cases"]):
            with btns[i]:
                if st.button(f"Case {i+1}", key=f"{cat['label']}_{i}", use_container_width=True):
                    st.session_state.selected_text = ct
                    st.session_state.result = None
        if st.session_state.selected_text in cat["cases"]:
            st.markdown(f"<div class='case-preview'><strong>📋 Selected:</strong><br>{st.session_state.selected_text}</div>",
                        unsafe_allow_html=True)
 
    st.markdown("<hr>", unsafe_allow_html=True)
    st.markdown("### 📋 Or Paste Your Own Message")
    user_typed = st.text_area("msg", label_visibility="collapsed",
                               value=st.session_state.selected_text, height=140,
                               placeholder='e.g. "Earn ₹5000 now!! Click bit.ly/xyz and share your OTP."',
                               key="textarea1")
    active_text = user_typed.strip() or st.session_state.selected_text.strip()
 
    a1,c1 = st.columns([5,1])
    with a1: run_btn   = st.button("🔍 Analyze Now", use_container_width=True, key="analyze1")
    with c1:
        if st.button("🗑️ Clear", use_container_width=True, key="clear1"):
            st.session_state.selected_text=""; st.session_state.result=None
            st.session_state.analyzed_text=""; st.rerun()
 
    need = run_btn or (st.session_state.selected_text!="" and st.session_state.result is None)
    if need:
        if not active_text:
            st.warning("⚠️ Please paste a message or pick a demo case.")
        else:
            with st.spinner("Scanning for threats..."):
                res = analyze(active_text)
            st.session_state.result = res
            render_result(res, active_text, "✍️ Text")
    elif st.session_state.result is not None:
        render_result(st.session_state.result, st.session_state.analyzed_text, "✍️ Text")
 
 
# ══════════════════════════════════════════════════════════════════════════════
# TAB 2 — SCREENSHOT OCR
# ══════════════════════════════════════════════════════════════════════════════
with tab2:
    st.markdown("### 📸 Upload Screenshot")
    st.markdown("""
    <div style='background:#faf5ff;border:1px solid #e9d5ff;border-radius:10px;
                padding:12px 16px;margin-bottom:16px;font-size:0.875rem;color:#5b21b6;'>
        📌 <strong>How it works:</strong> Upload any WhatsApp, SMS, Instagram or email screenshot
        → text is extracted automatically → analyzed for scam patterns.
    </div>""", unsafe_allow_html=True)
 
    st.markdown("""
    <div style='background:#fffbeb;border:1px solid #fde68a;border-radius:10px;
                padding:10px 14px;margin-bottom:16px;font-size:0.82rem;color:#92400e;'>
        ⚙️ <strong>Requires:</strong> <code>pip install pytesseract pillow</code>
        + Tesseract engine from <code>github.com/UB-Mannheim/tesseract/wiki</code>
    </div>""", unsafe_allow_html=True)
 
    ocr_file = st.file_uploader(
       "📸 Choose a screenshot image",
        type=["png","jpg","jpeg","webp","bmp"],
        key="ocr_upload",
    )
 
    if ocr_file:
        # Show the uploaded image
        st.image(ocr_file, caption="Uploaded screenshot", use_container_width=True)
        st.markdown("<br>", unsafe_allow_html=True)
 
        if st.button("📸 Extract Text & Analyze", use_container_width=True, key="ocr_btn"):
            with st.spinner("Extracting text from image..."):
                ocr_file.seek(0)
                ok, extracted, _ = process_upload(ocr_file, "ocr")
 
            if not ok:
                st.error(f"❌ OCR failed: {extracted}")
                st.info("Make sure pytesseract and Tesseract engine are installed.")
            else:
                st.markdown("### 📄 Extracted Text")
                st.markdown(f"""
                <div class='extracted-box'>
                    <div class='extracted-label'>📸 Text extracted from screenshot</div>
                    {extracted}
                </div>""", unsafe_allow_html=True)
 
                # Edit extracted text if needed
                edited = st.text_area("Edit if needed:", value=extracted, height=100, key="ocr_edit")
 
                with st.spinner("Analyzing extracted text..."):
                    res = analyze(edited.strip())
                render_result(res, edited.strip(), "📸 Screenshot")
    else:
        st.info("👆 Click 'Browse files' above to upload your screenshot. Supports PNG, JPG, JPEG, WebP.")
 
 
# ══════════════════════════════════════════════════════════════════════════════
# TAB 3 — QR CODE
# ══════════════════════════════════════════════════════════════════════════════
with tab3:
    st.markdown("### 📷 Upload QR Code")
    st.markdown("""
    <div style='background:#f0fdf4;border:1px solid #bbf7d0;border-radius:10px;
                padding:12px 16px;margin-bottom:16px;font-size:0.875rem;color:#14532d;'>
        📌 <strong>How it works:</strong> Upload any QR code image
        → link/text decoded automatically → analyzed for scam patterns.
        Never scan unknown QR codes directly — upload here first!
    </div>""", unsafe_allow_html=True)
 
    st.markdown("""
    <div style='background:#fffbeb;border:1px solid #fde68a;border-radius:10px;
                padding:10px 14px;margin-bottom:16px;font-size:0.82rem;color:#92400e;'>
        ⚙️ <strong>Requires:</strong> <code>pip install pyzbar opencv-python</code>
    </div>""", unsafe_allow_html=True)
 
    qr_file = st.file_uploader(
        "📷 Choose a QR code image",
        type=["png","jpg","jpeg","webp","bmp"],
        key="qr_upload",
    )
    
    if qr_file:
        col_img, col_info = st.columns([1, 1])
        with col_img:
            st.image(qr_file, caption="Uploaded QR code", use_container_width=True)
        with col_info:
            st.markdown("""
            <div style='background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;
                        padding:14px;margin-top:8px;font-size:0.82rem;color:#334155;'>
                <strong>🛡️ Safe QR Scanning Tips:</strong><br><br>
                ✅ Always check the URL before visiting<br>
                🚫 Never pay fees from unknown QR codes<br>
                🔍 Verify QR source before scanning<br>
                📱 UPI QR codes only from trusted shops
            </div>""", unsafe_allow_html=True)
 
        st.markdown("<br>", unsafe_allow_html=True)
 
        if st.button("📷 Decode QR & Analyze", use_container_width=True, key="qr_btn"):
            with st.spinner("Decoding QR code..."):
                qr_file.seek(0)
                ok, decoded, _ = process_upload(qr_file, "qr")
 
            if not ok:
                st.error(f"❌ QR decode failed: {decoded}")
                st.info("Make sure pyzbar and opencv-python are installed.")
            else:
                st.markdown("### 🔗 Decoded QR Content")
                st.markdown(f"""
                <div class='extracted-box'>
                    <div class='extracted-label'>📷 Decoded from QR code</div>
                    {decoded}
                </div>""", unsafe_allow_html=True)
 
                with st.spinner("Analyzing QR content..."):
                    res = analyze(decoded.strip())
                render_result(res, decoded.strip(), "📷 QR Code")
    else:
        st.info("👆 Click 'Browse files' above to upload your QR code image. Supports PNG, JPG, JPEG, WebP.")
 
# ══════════════════════════════════════════════════════════════════════════════
# TAB 4 — HISTORY
# ══════════════════════════════════════════════════════════════════════════════
with tab4:
    render_history_tab()