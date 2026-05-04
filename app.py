# app.py
import streamlit as st
import streamlit.components.v1 as components
import plotly.graph_objects as go
from datetime import datetime
import random
import time

from config import (
    COLOR_SAFE, COLOR_SUSPICIOUS, COLOR_SCAM,
    LABEL_SAFE, LABEL_SUSPICIOUS, LABEL_SCAM,
    HELPLINES, REPORT_PORTALS,
)
from core.preprocessor   import preprocess
from core.rules          import run_rules
from core.domain_check   import check_domain
from core.ml_model       import get_ml_score
from core.api_check      import run_api_checks
from core.history_engine import (
    check_history, save_report, get_trending_scams,
)
from core.scorer import (
    calculate_final_score, decide,
    get_score_color, get_scam_type,
)
from admin.dashboard import render_admin_dashboard

# ─────────────────────────────────────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Campus Fraud Shield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ─────────────────────────────────────────────────────────────────────────────
# 3D BACKGROUND — Neural Network + Particles (THREE.js)
# ─────────────────────────────────────────────────────────────────────────────
def render_3d_background():
    components.html("""
<!DOCTYPE html>
<html>
<head>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { overflow: hidden; background: transparent; }
  canvas {
    position: fixed;
    top: 0; left: 0;
    width: 100vw; height: 100vh;
    z-index: -1;
    pointer-events: none;
  }
</style>
</head>
<body>
<canvas id="bg"></canvas>
<script>
const canvas = document.getElementById('bg');
const ctx    = canvas.getContext('2d');

canvas.width  = window.innerWidth;
canvas.height = window.innerHeight;

window.addEventListener('resize', () => {
  canvas.width  = window.innerWidth;
  canvas.height = window.innerHeight;
  initNodes();
});

// ── Color Palette ──────────────────────────────────────────────
const COLORS = {
  bg:        '#020818',
  node1:     '#3b82f6',   // Electric blue
  node2:     '#f59e0b',   // Gold
  node3:     '#22d3ee',   // Cyan
  particle:  '#3b82f680',
  line:      '#3b82f620',
  lineBright:'#f59e0b40',
};

// ── Nodes ──────────────────────────────────────────────────────
let nodes = [];
const NODE_COUNT = 55;
const MAX_DIST   = 160;

class Node {
  constructor() { this.reset(); }
  reset() {
    this.x    = Math.random() * canvas.width;
    this.y    = Math.random() * canvas.height;
    this.vx   = (Math.random() - 0.5) * 0.5;
    this.vy   = (Math.random() - 0.5) * 0.5;
    this.r    = Math.random() * 2.5 + 1;
    this.life = Math.random() * Math.PI * 2;
    this.speed= Math.random() * 0.02 + 0.005;

    const roll = Math.random();
    if      (roll < 0.5)  this.color = COLORS.node1;
    else if (roll < 0.8)  this.color = COLORS.node2;
    else                  this.color = COLORS.node3;

    this.glow  = Math.random() > 0.7;
    this.pulse = Math.random() * Math.PI * 2;
  }
  update() {
    this.x    += this.vx;
    this.y    += this.vy;
    this.life += this.speed;
    this.pulse+= 0.03;

    if (this.x < 0 || this.x > canvas.width)  this.vx *= -1;
    if (this.y < 0 || this.y > canvas.height) this.vy *= -1;
  }
  draw() {
    const alpha  = 0.5 + 0.5 * Math.sin(this.life);
    const radius = this.r * (1 + 0.3 * Math.sin(this.pulse));

    if (this.glow) {
      const grad = ctx.createRadialGradient(
        this.x, this.y, 0,
        this.x, this.y, radius * 6
      );
      grad.addColorStop(0, this.color + 'cc');
      grad.addColorStop(1, this.color + '00');
      ctx.beginPath();
      ctx.arc(this.x, this.y, radius * 6, 0, Math.PI * 2);
      ctx.fillStyle = grad;
      ctx.fill();
    }

    ctx.beginPath();
    ctx.arc(this.x, this.y, radius, 0, Math.PI * 2);
    ctx.fillStyle = this.color +
      Math.floor(alpha * 255).toString(16).padStart(2,'0');
    ctx.fill();
  }
}

// ── Particles ─────────────────────────────────────────────────
let particles = [];
const PARTICLE_COUNT = 80;

class Particle {
  constructor() { this.reset(); }
  reset() {
    this.x     = Math.random() * canvas.width;
    this.y     = Math.random() * canvas.height;
    this.vx    = (Math.random() - 0.5) * 0.3;
    this.vy    = -Math.random() * 0.4 - 0.1;
    this.alpha = Math.random() * 0.4 + 0.1;
    this.r     = Math.random() * 1.5 + 0.3;
    this.life  = 0;
    this.maxLife = Math.random() * 200 + 100;
    const roll = Math.random();
    this.color = roll < 0.6 ? COLORS.node1 :
                 roll < 0.85 ? COLORS.node2 : COLORS.node3;
  }
  update() {
    this.x    += this.vx;
    this.y    += this.vy;
    this.life++;
    if (this.life > this.maxLife ||
        this.y < 0 || this.x < 0 ||
        this.x > canvas.width) {
      this.reset();
    }
  }
  draw() {
    const progress = this.life / this.maxLife;
    const alpha    = this.alpha * (1 - progress);
    ctx.beginPath();
    ctx.arc(this.x, this.y, this.r, 0, Math.PI * 2);
    ctx.fillStyle = this.color +
      Math.floor(alpha * 255).toString(16).padStart(2,'0');
    ctx.fill();
  }
}

// ── Data streams (vertical lines) ─────────────────────────────
let streams = [];
const STREAM_COUNT = 12;

class Stream {
  constructor() { this.reset(); }
  reset() {
    this.x      = Math.random() * canvas.width;
    this.y      = -Math.random() * canvas.height;
    this.speed  = Math.random() * 1.5 + 0.5;
    this.length = Math.random() * 80 + 40;
    this.alpha  = Math.random() * 0.15 + 0.05;
    this.color  = Math.random() > 0.5 ? COLORS.node1 : COLORS.node2;
  }
  update() {
    this.y += this.speed;
    if (this.y > canvas.height + this.length) this.reset();
  }
  draw() {
    const grad = ctx.createLinearGradient(
      this.x, this.y - this.length,
      this.x, this.y
    );
    grad.addColorStop(0, this.color + '00');
    grad.addColorStop(1, this.color +
      Math.floor(this.alpha * 255).toString(16).padStart(2,'0'));
    ctx.beginPath();
    ctx.moveTo(this.x, this.y - this.length);
    ctx.lineTo(this.x, this.y);
    ctx.strokeStyle = grad;
    ctx.lineWidth   = 1;
    ctx.stroke();
  }
}

// ── Hexagon grid (subtle) ─────────────────────────────────────
function drawHexGrid() {
  const size   = 40;
  const w      = size * 2;
  const h      = Math.sqrt(3) * size;
  const cols   = Math.ceil(canvas.width  / w) + 2;
  const rows   = Math.ceil(canvas.height / h) + 2;

  ctx.strokeStyle = '#3b82f608';
  ctx.lineWidth   = 0.5;

  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < cols; c++) {
      const x = c * w * 0.75 - size;
      const y = r * h + (c % 2 === 0 ? 0 : h / 2) - h;
      drawHex(x, y, size);
    }
  }
}

function drawHex(cx, cy, size) {
  ctx.beginPath();
  for (let i = 0; i < 6; i++) {
    const angle = (Math.PI / 3) * i - Math.PI / 6;
    const x = cx + size * Math.cos(angle);
    const y = cy + size * Math.sin(angle);
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  }
  ctx.closePath();
  ctx.stroke();
}

// ── Corner glows ──────────────────────────────────────────────
let glowTime = 0;
function drawCornerGlows() {
  glowTime += 0.005;

  // Top-left: Blue
  const g1 = ctx.createRadialGradient(0, 0, 0, 0, 0, 400);
  g1.addColorStop(0, `rgba(59,130,246,${0.08 + 0.04 * Math.sin(glowTime)})`);
  g1.addColorStop(1, 'transparent');
  ctx.fillStyle = g1;
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  // Bottom-right: Gold
  const g2 = ctx.createRadialGradient(
    canvas.width, canvas.height, 0,
    canvas.width, canvas.height, 400
  );
  g2.addColorStop(0, `rgba(245,158,11,${0.06 + 0.03 * Math.sin(glowTime + 1)})`);
  g2.addColorStop(1, 'transparent');
  ctx.fillStyle = g2;
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  // Top-right: Cyan
  const g3 = ctx.createRadialGradient(
    canvas.width, 0, 0,
    canvas.width, 0, 300
  );
  g3.addColorStop(0, `rgba(34,211,238,${0.05 + 0.02 * Math.sin(glowTime + 2)})`);
  g3.addColorStop(1, 'transparent');
  ctx.fillStyle = g3;
  ctx.fillRect(0, 0, canvas.width, canvas.height);
}

// ── Init ──────────────────────────────────────────────────────
function initNodes() {
  nodes     = Array.from({length: NODE_COUNT},     () => new Node());
  particles = Array.from({length: PARTICLE_COUNT}, () => new Particle());
  streams   = Array.from({length: STREAM_COUNT},   () => new Stream());
}

initNodes();

// ── Draw connections between nodes ────────────────────────────
function drawConnections() {
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      const dx   = nodes[i].x - nodes[j].x;
      const dy   = nodes[i].y - nodes[j].y;
      const dist = Math.sqrt(dx*dx + dy*dy);

      if (dist < MAX_DIST) {
        const alpha = 1 - dist / MAX_DIST;
        const isBright = nodes[i].glow || nodes[j].glow;

        ctx.beginPath();
        ctx.moveTo(nodes[i].x, nodes[i].y);
        ctx.lineTo(nodes[j].x, nodes[j].y);
        ctx.strokeStyle = isBright
          ? COLORS.lineBright.slice(0,7) +
            Math.floor(alpha * 60).toString(16).padStart(2,'0')
          : COLORS.line.slice(0,7) +
            Math.floor(alpha * 40).toString(16).padStart(2,'0');
        ctx.lineWidth = isBright ? 0.8 : 0.4;
        ctx.stroke();
      }
    }
  }
}

// ── Main loop ─────────────────────────────────────────────────
function animate() {
  ctx.clearRect(0, 0, canvas.width, canvas.height);

  // Background
  ctx.fillStyle = COLORS.bg;
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  // Layers
  drawHexGrid();
  drawCornerGlows();
  streams.forEach(s => { s.update(); s.draw(); });
  drawConnections();
  nodes.forEach(n => { n.update(); n.draw(); });
  particles.forEach(p => { p.update(); p.draw(); });

  requestAnimationFrame(animate);
}

animate();
</script>
</body>
</html>
""", height=0, scrolling=False)


# ─────────────────────────────────────────────────────────────────────────────
# CSS
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=Space+Grotesk:wght@400;500;600;700;800&display=swap');

*, html, body {
    font-family: 'Space Grotesk', 'Inter', sans-serif;
    box-sizing: border-box;
}

/* ── Dark Background ── */
.stApp {
    background: #020818 !important;
}

/* Fix Streamlit iframe for 3D background */
iframe {
    position: fixed !important;
    top: 0 !important;
    left: 0 !important;
    width: 100vw !important;
    height: 100vh !important;
    z-index: 0 !important;
    pointer-events: none !important;
    border: none !important;
}

.block-container {
    padding-top: 1.5rem !important;
    max-width: 940px !important;
    position: relative;
    z-index: 1;
}

footer, #MainMenu, header { visibility: hidden; }

/* ── Animations ── */
@keyframes floatUp {
    0%   { opacity: 0; transform: translateY(24px); }
    100% { opacity: 1; transform: translateY(0); }
}
@keyframes glowPulse {
    0%,100% { box-shadow: 0 0 20px rgba(59,130,246,0.3); }
    50%      { box-shadow: 0 0 40px rgba(59,130,246,0.6),
                           0 0 60px rgba(245,158,11,0.2); }
}
@keyframes borderFlow {
    0%   { border-color: rgba(59,130,246,0.5); }
    33%  { border-color: rgba(245,158,11,0.5); }
    66%  { border-color: rgba(34,211,238,0.5); }
    100% { border-color: rgba(59,130,246,0.5); }
}
@keyframes fadeIn {
    from { opacity: 0; }
    to   { opacity: 1; }
}
@keyframes pulse {
    0%,100% { transform: scale(1); }
    50%      { transform: scale(1.08); }
}
@keyframes shimmer {
    0%   { background-position: -200% center; }
    100% { background-position:  200% center; }
}
@keyframes scanDown {
    0%   { transform: translateY(-100%); opacity: 0.6; }
    100% { transform: translateY(500%);  opacity: 0; }
}
@keyframes confMeter {
    from { width: 0%; }
    to   { width: var(--conf-width); }
}
@keyframes stepAppear {
    from { opacity: 0; transform: translateX(-16px); }
    to   { opacity: 1; transform: translateX(0); }
}
@keyframes numberCount {
    from { opacity: 0; transform: scale(0.5); }
    to   { opacity: 1; transform: scale(1); }
}
@keyframes typewriter {
    from { width: 0; }
    to   { width: 100%; }
}

/* ── Hero ── */
.hero {
    position: relative;
    background: linear-gradient(135deg,
        rgba(59,130,246,0.12) 0%,
        rgba(10,12,30,0.97)   45%,
        rgba(245,158,11,0.08) 100%
    );
    border: 1px solid rgba(59,130,246,0.35);
    border-radius: 28px;
    padding: 52px 32px 44px;
    text-align: center;
    margin-bottom: 28px;
    backdrop-filter: blur(24px);
    overflow: hidden;
    animation: floatUp 0.8s ease, glowPulse 4s ease infinite;
}
.hero::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg,
        transparent,
        rgba(59,130,246,0.9),
        rgba(245,158,11,0.9),
        rgba(34,211,238,0.9),
        transparent
    );
    background-size: 200% auto;
    animation: shimmer 3s linear infinite;
}
.hero::after {
    content: '';
    position: absolute;
    top: -50%; left: 15%;
    width: 70%; height: 200%;
    background: linear-gradient(
        transparent 0%,
        rgba(59,130,246,0.03) 50%,
        transparent 100%
    );
    animation: scanDown 5s ease-in-out infinite;
    pointer-events: none;
}
.hero-icon {
    font-size: 4rem;
    display: block;
    margin-bottom: 14px;
    animation: pulse 3s ease infinite;
    filter: drop-shadow(0 0 24px rgba(59,130,246,0.9))
            drop-shadow(0 0 48px rgba(245,158,11,0.4));
}
.hero h1 {
    font-size: 2.8rem;
    font-weight: 900;
    margin: 0 0 10px;
    background: linear-gradient(135deg,
        #ffffff 0%, #93c5fd 40%,
        #fbbf24 70%, #67e8f9 100%
    );
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    letter-spacing: -0.8px;
    animation: floatUp 0.9s ease;
}
.hero p {
    color: rgba(180,195,230,0.8);
    font-size: 1.02rem;
    margin: 0;
    font-weight: 400;
    animation: floatUp 1s ease;
}
.hero-badge {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    background: rgba(59,130,246,0.15);
    border: 1px solid rgba(59,130,246,0.35);
    border-radius: 999px;
    padding: 6px 18px;
    font-size: 0.78rem;
    color: #93c5fd;
    margin-bottom: 20px;
    font-weight: 600;
    letter-spacing: 0.4px;
    animation: floatUp 1.1s ease;
}

/* ── Stat Cards ── */
.stat-card {
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 18px;
    padding: 22px 14px;
    text-align: center;
    backdrop-filter: blur(14px);
    transition: all 0.3s ease;
    animation: floatUp 0.7s ease;
    position: relative;
    overflow: hidden;
}
.stat-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 1px;
    background: linear-gradient(90deg,
        transparent, rgba(59,130,246,0.5), transparent);
}
.stat-card:hover {
    background: rgba(59,130,246,0.08);
    border-color: rgba(59,130,246,0.35);
    transform: translateY(-4px);
    box-shadow: 0 12px 40px rgba(59,130,246,0.15);
}
.stat-num {
    font-size: 2.4rem;
    font-weight: 900;
    line-height: 1;
    font-family: 'Space Grotesk', sans-serif;
}
.stat-label {
    font-size: 0.68rem;
    color: rgba(150,165,200,0.7);
    margin-top: 6px;
    text-transform: uppercase;
    letter-spacing: 1.2px;
    font-weight: 600;
}

/* ── Sidebar ── */
section[data-testid="stSidebar"] {
    background: rgba(2,8,24,0.98) !important;
    border-right: 1px solid rgba(59,130,246,0.2) !important;
    backdrop-filter: blur(24px);
}
section[data-testid="stSidebar"] * { color: #c8d4f0 !important; }
.sb-title {
    font-size: 1rem; font-weight: 800;
    color: #93c5fd !important;
    letter-spacing: -0.2px;
}
.sb-section {
    background: rgba(59,130,246,0.06);
    border: 1px solid rgba(59,130,246,0.15);
    border-radius: 14px;
    padding: 14px; margin: 10px 0;
}
.sb-section-title {
    font-size: 0.68rem;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    color: rgba(34,211,238,0.8) !important;
    font-weight: 700; margin-bottom: 10px;
}
.sb-item {
    display: flex; align-items: flex-start;
    gap: 8px; padding: 6px 0;
    border-bottom: 1px solid rgba(255,255,255,0.04);
    font-size: 0.82rem; color: #c8d4f0 !important;
}
.sb-item:last-child { border-bottom: none; }
.sb-num { font-weight: 900; color: #fbbf24 !important; font-size: 1rem; }
.sb-badge {
    display: inline-block;
    background: rgba(239,68,68,0.18);
    border: 1px solid rgba(239,68,68,0.35);
    border-radius: 6px; padding: 1px 7px;
    font-size: 0.7rem; color: #fca5a5 !important;
}
.sb-safe {
    display: inline-block;
    background: rgba(34,197,94,0.12);
    border: 1px solid rgba(34,197,94,0.3);
    border-radius: 6px; padding: 1px 7px;
    font-size: 0.7rem; color: #86efac !important;
}

/* ── Search Area ── */
.search-wrap {
    background: rgba(59,130,246,0.06);
    border: 1.5px solid rgba(59,130,246,0.3);
    border-radius: 22px;
    padding: 28px 24px 20px;
    margin: 20px 0;
    backdrop-filter: blur(20px);
    animation: borderFlow 6s ease infinite;
    position: relative;
    overflow: hidden;
}
.search-wrap::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 1px;
    background: linear-gradient(90deg,
        transparent, rgba(59,130,246,0.6),
        rgba(245,158,11,0.6), transparent);
    background-size: 200% auto;
    animation: shimmer 4s linear infinite;
}
.search-label {
    color: rgba(147,197,253,0.85);
    font-size: 0.8rem; font-weight: 700;
    text-transform: uppercase; letter-spacing: 1.2px;
    margin-bottom: 12px; display: block;
}

/* ── Textarea ── */
textarea {
    background: rgba(2,8,24,0.85) !important;
    border: 1.5px solid rgba(59,130,246,0.3) !important;
    border-radius: 14px !important;
    color: #e8eeff !important;
    font-size: 0.95rem !important;
    font-family: 'Space Grotesk', sans-serif !important;
    caret-color: #3b82f6 !important;
}
textarea:focus {
    border-color: rgba(59,130,246,0.7) !important;
    box-shadow: 0 0 0 3px rgba(59,130,246,0.12) !important;
}
textarea::placeholder { color: rgba(150,165,200,0.4) !important; }

/* ── Example Tags ── */
.tags-wrap {
    display: flex; flex-wrap: wrap;
    gap: 8px; margin-top: 16px;
}
.tag-label {
    font-size: 0.68rem; font-weight: 700;
    color: rgba(150,165,200,0.5);
    text-transform: uppercase; letter-spacing: 1px;
    margin-bottom: 8px; display: block;
}

/* ── Buttons ── */
div[data-testid="stButton"] > button {
    border-radius: 12px !important;
    font-weight: 700 !important;
    font-size: 0.88rem !important;
    transition: all 0.25s ease !important;
    font-family: 'Space Grotesk', sans-serif !important;
}

/* Analyze button — special styling */
div[data-testid="stButton"] > button[kind="primary"],
div[data-testid="stButton"]:first-child > button {
    background: linear-gradient(135deg,
        rgba(59,130,246,0.9), rgba(37,99,235,0.9)) !important;
    border: 1px solid rgba(59,130,246,0.7) !important;
    color: #ffffff !important;
    box-shadow: 0 4px 20px rgba(59,130,246,0.4) !important;
}
div[data-testid="stButton"] > button:hover {
    transform: translateY(-2px) !important;
    box-shadow: 0 8px 28px rgba(59,130,246,0.5) !important;
}

/* Report button */
.report-btn > div[data-testid="stButton"] > button {
    background: linear-gradient(135deg,
        rgba(239,68,68,0.85), rgba(185,28,28,0.85)) !important;
    border: 1px solid rgba(239,68,68,0.6) !important;
    color: #ffffff !important;
    box-shadow: 0 4px 20px rgba(239,68,68,0.35) !important;
    animation: glowPulse 2s ease infinite !important;
}

/* ── Tabs ── */
div[data-testid="stTabs"] button {
    color: rgba(150,165,200,0.6) !important;
    font-weight: 600 !important;
    font-size: 0.88rem !important;
    font-family: 'Space Grotesk', sans-serif !important;
    background: transparent !important;
    border: none !important;
    padding: 10px 16px !important;
}
div[data-testid="stTabs"] button[aria-selected="true"] {
    color: #93c5fd !important;
    border-bottom: 2px solid #3b82f6 !important;
    background: rgba(59,130,246,0.08) !important;
}
div[data-testid="stTabs"] button:hover {
    color: #93c5fd !important;
    background: rgba(59,130,246,0.06) !important;
}

/* ── Result Card ── */
.result-card {
    border-radius: 24px;
    padding: 40px 28px;
    text-align: center;
    margin: 20px 0;
    animation: floatUp 0.5s ease;
    backdrop-filter: blur(24px);
    position: relative; overflow: hidden;
}
.result-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0; height: 2px;
    background: linear-gradient(90deg,
        transparent, var(--result-color), transparent);
    background-size: 200% auto;
    animation: shimmer 3s linear infinite;
}
.result-safe {
    background: linear-gradient(135deg,
        rgba(34,197,94,0.12), rgba(2,8,24,0.97));
    border: 1.5px solid rgba(34,197,94,0.45);
    box-shadow: 0 0 60px rgba(34,197,94,0.12),
                inset 0 0 60px rgba(34,197,94,0.04);
    --result-color: rgba(34,197,94,0.8);
}
.result-suspicious {
    background: linear-gradient(135deg,
        rgba(245,158,11,0.12), rgba(2,8,24,0.97));
    border: 1.5px solid rgba(245,158,11,0.45);
    box-shadow: 0 0 60px rgba(245,158,11,0.12),
                inset 0 0 60px rgba(245,158,11,0.04);
    --result-color: rgba(245,158,11,0.8);
}
.result-scam {
    background: linear-gradient(135deg,
        rgba(239,68,68,0.15), rgba(2,8,24,0.97));
    border: 1.5px solid rgba(239,68,68,0.55);
    box-shadow: 0 0 60px rgba(239,68,68,0.18),
                inset 0 0 60px rgba(239,68,68,0.06);
    --result-color: rgba(239,68,68,0.8);
}
.result-icon {
    font-size: 4.5rem; display: block;
    margin-bottom: 10px;
    animation: pulse 2s ease infinite;
}
.result-label {
    font-size: 2.4rem; font-weight: 900;
    margin: 0; letter-spacing: -0.8px;
}
.result-score {
    font-size: 4rem; font-weight: 900;
    margin: 8px 0; line-height: 1;
    font-family: 'Space Grotesk', sans-serif;
    animation: numberCount 0.6s ease;
}
.result-score span {
    font-size: 1.3rem; font-weight: 400; opacity: 0.55;
}
.type-badge {
    display: inline-block;
    padding: 7px 20px; border-radius: 999px;
    font-size: 0.88rem; font-weight: 700;
    margin-top: 12px; border: 1px solid;
    backdrop-filter: blur(8px);
    letter-spacing: 0.2px;
}

/* ── Confidence Meter ── */
.conf-wrap {
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 16px;
    padding: 18px 20px;
    margin: 14px 0;
    backdrop-filter: blur(12px);
}
.conf-title {
    font-size: 0.72rem; font-weight: 700;
    text-transform: uppercase; letter-spacing: 1.2px;
    color: rgba(150,165,200,0.65); margin-bottom: 10px;
}
.conf-bar-bg {
    background: rgba(255,255,255,0.06);
    border-radius: 999px; height: 8px;
    overflow: hidden; margin: 6px 0 3px;
    border: 1px solid rgba(255,255,255,0.05);
}
.conf-bar-fill {
    height: 100%; border-radius: 999px;
    animation: confMeter 1.2s cubic-bezier(0.4,0,0.2,1) forwards;
    background: linear-gradient(90deg, var(--bar-start), var(--bar-end));
}
.conf-row {
    display: flex; justify-content: space-between;
    align-items: center; margin-bottom: 10px;
}
.conf-label { font-size: 0.82rem; color: rgba(200,212,240,0.85); }
.conf-value {
    font-size: 0.88rem; font-weight: 800;
    font-family: 'Space Grotesk', sans-serif;
}

/* ── Step-by-step Explainer ── */
.steps-wrap {
    background: rgba(255,255,255,0.03);
    border: 1px solid rgba(255,255,255,0.07);
    border-radius: 18px;
    padding: 20px; margin: 16px 0;
    backdrop-filter: blur(14px);
}
.step-row {
    display: flex; align-items: center;
    gap: 14px; padding: 10px 0;
    border-bottom: 1px solid rgba(255,255,255,0.04);
    animation: stepAppear 0.4s ease forwards;
    opacity: 0;
}
.step-row:last-child { border-bottom: none; }
.step-num {
    width: 28px; height: 28px;
    border-radius: 50%;
    display: flex; align-items: center;
    justify-content: center;
    font-size: 0.72rem; font-weight: 800;
    flex-shrink: 0;
}
.step-label {
    font-size: 0.85rem; color: rgba(200,212,240,0.8);
    flex: 1;
}
.step-result {
    font-size: 0.82rem; font-weight: 700;
    text-align: right; white-space: nowrap;
}
.step-bar {
    height: 3px; border-radius: 999px;
    margin-top: 4px;
    animation: confMeter 1s ease forwards;
}

/* ── Score Bar ── */
.bar-wrap {
    background: rgba(255,255,255,0.05);
    border-radius: 999px; height: 10px;
    overflow: hidden; margin: 16px 0 4px;
    border: 1px solid rgba(255,255,255,0.05);
}
.bar-fill {
    height: 100%; border-radius: 999px;
    transition: width 1.2s cubic-bezier(0.4,0,0.2,1);
}
.bar-labels {
    display: flex; justify-content: space-between;
    font-size: 0.68rem; color: rgba(150,165,200,0.5);
    margin-top: 4px;
}

/* ── Reason Pills ── */
.reason-pill {
    background: rgba(255,255,255,0.03);
    border: 1px solid rgba(255,255,255,0.07);
    border-left: 3px solid;
    border-radius: 0 12px 12px 0;
    padding: 10px 16px; margin: 5px 0;
    font-size: 0.875rem; color: #c8d4f0;
    line-height: 1.5; animation: fadeIn 0.4s ease;
    transition: all 0.2s; backdrop-filter: blur(8px);
}
.reason-pill:hover {
    transform: translateX(6px);
    background: rgba(59,130,246,0.08);
}

/* ── Info Cards ── */
.ml-card {
    background: rgba(139,92,246,0.08);
    border: 1px solid rgba(139,92,246,0.22);
    border-radius: 12px; padding: 13px 16px;
    margin: 8px 0; font-size: 0.875rem;
    color: #c4b5fd; animation: floatUp 0.5s ease;
}
.history-card {
    background: rgba(245,158,11,0.08);
    border: 1px solid rgba(245,158,11,0.22);
    border-radius: 12px; padding: 13px 16px;
    margin: 8px 0; font-size: 0.875rem;
    color: #fcd34d; animation: floatUp 0.5s ease;
}
.api-card {
    background: rgba(34,211,238,0.07);
    border: 1px solid rgba(34,211,238,0.22);
    border-radius: 12px; padding: 13px 16px;
    margin: 8px 0; font-size: 0.875rem;
    color: #67e8f9; animation: floatUp 0.5s ease;
}
.trusted-card {
    background: rgba(34,197,94,0.07);
    border: 1px solid rgba(34,197,94,0.22);
    border-radius: 12px; padding: 13px 16px;
    margin: 8px 0; font-size: 0.875rem;
    color: #86efac;
}
.override-card {
    background: rgba(239,68,68,0.09);
    border: 1px solid rgba(239,68,68,0.3);
    border-radius: 12px; padding: 13px 16px;
    margin: 8px 0; font-size: 0.875rem;
    color: #fca5a5; animation: floatUp 0.5s ease;
}
.tip-card {
    background: rgba(255,255,255,0.03);
    border: 1px solid rgba(255,255,255,0.07);
    border-radius: 12px; padding: 12px 16px;
    margin: 5px 0; font-size: 0.85rem;
    color: #c8d4f0; transition: all 0.2s;
}
.tip-card:hover {
    background: rgba(59,130,246,0.09);
    border-color: rgba(59,130,246,0.28);
    transform: translateX(3px);
}
.action-card {
    border-radius: 14px; padding: 18px 22px;
    font-weight: 800; font-size: 1rem;
    margin-top: 8px; border: 1px solid;
    backdrop-filter: blur(14px);
    animation: floatUp 0.6s ease;
    letter-spacing: 0.2px;
}
.breakdown-card {
    background: rgba(0,0,0,0.7);
    border: 1px solid rgba(59,130,246,0.25);
    border-radius: 14px; padding: 20px;
    font-family: 'Courier New', monospace;
    font-size: 0.85rem; color: #67e8f9;
    white-space: pre; line-height: 2;
    backdrop-filter: blur(14px);
}

/* ── Section Headers ── */
.section-header {
    font-size: 0.95rem; font-weight: 800;
    color: #93c5fd; margin: 24px 0 12px;
    display: flex; align-items: center;
    gap: 8px; letter-spacing: -0.1px;
    text-transform: uppercase;
    font-size: 0.78rem; letter-spacing: 1.2px;
}

/* ── Gauge ── */
.gauge-wrap {
    background: rgba(255,255,255,0.03);
    border: 1px solid rgba(255,255,255,0.06);
    border-radius: 20px; padding: 10px;
    margin: 16px 0; backdrop-filter: blur(12px);
}

/* ── History Cards ── */
.hist-card {
    background: rgba(255,255,255,0.03);
    border: 1px solid rgba(255,255,255,0.06);
    border-radius: 18px; padding: 16px 18px;
    margin: 10px 0; backdrop-filter: blur(12px);
    transition: all 0.25s ease; animation: fadeIn 0.4s ease;
}
.hist-card:hover {
    background: rgba(59,130,246,0.07);
    border-color: rgba(59,130,246,0.28);
    transform: translateY(-2px);
    box-shadow: 0 8px 28px rgba(59,130,246,0.12);
}
.hist-badge {
    display: inline-flex; align-items: center;
    gap: 6px; padding: 4px 14px;
    border-radius: 999px; font-size: 0.8rem;
    font-weight: 700; border: 1px solid;
}
.hist-empty {
    text-align: center; padding: 60px 24px;
    color: rgba(150,165,200,0.4);
}
.hist-empty div { font-size: 4rem; margin-bottom: 16px; }

/* ── Trending ── */
.trending-card {
    background: rgba(245,158,11,0.05);
    border: 1px solid rgba(245,158,11,0.18);
    border-left: 3px solid rgba(245,158,11,0.5);
    border-radius: 10px; padding: 10px 14px;
    margin: 6px 0; font-size: 0.82rem;
    color: #fcd34d; transition: transform 0.2s;
}
.trending-card:hover { transform: translateX(3px); }

/* ── Upload Zone ── */
.upload-zone {
    background: rgba(59,130,246,0.05);
    border: 2px dashed rgba(59,130,246,0.28);
    border-radius: 20px; padding: 44px 24px;
    text-align: center; margin: 12px 0;
    transition: all 0.3s; cursor: pointer;
}
.upload-zone:hover {
    border-color: rgba(245,158,11,0.5);
    background: rgba(245,158,11,0.04);
    box-shadow: 0 0 40px rgba(245,158,11,0.08);
}
.upload-zone h3 {
    color: #c8d4f0; font-size: 1rem;
    margin: 12px 0 4px;
}
.upload-zone p {
    color: rgba(150,165,200,0.5);
    font-size: 0.82rem; margin: 0;
}

/* ── Metrics ── */
div[data-testid="stMetric"] {
    background: rgba(255,255,255,0.03) !important;
    border: 1px solid rgba(255,255,255,0.07) !important;
    border-radius: 12px !important;
    padding: 12px !important;
}
div[data-testid="stMetric"] label {
    color: rgba(150,165,200,0.7) !important;
    font-size: 0.75rem !important;
}
div[data-testid="stMetric"] div[data-testid="stMetricValue"] {
    color: #e8eeff !important; font-weight: 800 !important;
}

/* ── Expander ── */
details {
    background: rgba(255,255,255,0.02) !important;
    border: 1px solid rgba(255,255,255,0.07) !important;
    border-radius: 14px !important; padding: 4px !important;
}
details summary {
    color: #93c5fd !important; font-weight: 700 !important;
    font-size: 0.88rem !important; padding: 10px 14px !important;
}

/* ── File uploader ── */
div[data-testid="stFileUploader"] {
    background: rgba(59,130,246,0.04) !important;
    border: 1.5px dashed rgba(59,130,246,0.28) !important;
    border-radius: 14px !important; padding: 12px !important;
}

/* ── Selectbox ── */
div[data-testid="stSelectbox"] > div > div {
    background: rgba(2,8,24,0.95) !important;
    border: 1px solid rgba(59,130,246,0.28) !important;
    border-radius: 10px !important; color: #e8eeff !important;
}

/* ── HR ── */
hr {
    border: none !important;
    border-top: 1px solid rgba(255,255,255,0.06) !important;
    margin: 24px 0 !important;
}

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 5px; }
::-webkit-scrollbar-track { background: rgba(2,8,24,0.5); }
::-webkit-scrollbar-thumb {
    background: rgba(59,130,246,0.4); border-radius: 999px;
}
::-webkit-scrollbar-thumb:hover {
    background: rgba(59,130,246,0.7);
}

/* ── Glass Card ── */
.glass-card {
    background: rgba(255,255,255,0.03);
    border: 1px solid rgba(255,255,255,0.07);
    border-radius: 18px; padding: 20px 22px;
    backdrop-filter: blur(14px); margin: 14px 0;
    animation: floatUp 0.5s ease;
}
</style>
""", unsafe_allow_html=True)

# Render 3D background
render_3d_background()

# ─────────────────────────────────────────────────────────────────────────────
# SESSION STATE
# ─────────────────────────────────────────────────────────────────────────────
_defaults = {
    "total": 0, "scams": 0, "safe": 0, "suspicious": 0,
    "result": None, "analyzed_text": "",
    "history": [], "admin_logged_in": False,
    "input_text": "",
}
for k, v in _defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

# ─────────────────────────────────────────────────────────────────────────────
# EXAMPLES
# ─────────────────────────────────────────────────────────────────────────────
EXAMPLES = {
    "💸 Payment Scam": [
        "URGENT! Pay ₹999 registration fee via GPay to confirm your Google internship. Limited slots!!!",
        "Your Amazon order on hold. Pay ₹49 customs fee via UPI within 2 hours or parcel returned.",
        "Work from home confirmed! Pay ₹500 refundable deposit via UPI to activate your account today.",
        "Congratulations! You won ₹50,000 lucky draw. Pay ₹299 processing fee on PhonePe to claim.",
    ],
    "🔐 Phishing": [
        "Your SBI account is BLOCKED! Verify Aadhar + OTP at sbi-secure-login.tk immediately.",
        "HDFC Alert: Update KYC now at hdfc-kyc-update.xyz or account suspended in 24 hours.",
        "Your UPI PIN expired. Re-enter PIN at bit.ly/upi-renew to continue transactions.",
        "Your PAN card linked to illegal activity. Share Aadhar OTP with agent to avoid arrest.",
    ],
    "🎓 Fake Job": [
        "Earn ₹5000/day from home! No experience needed. WhatsApp 9123456789. 100% guaranteed!",
        "You are SELECTED for Data Entry. Salary ₹25000/month. No interview. Send Aadhar to confirm.",
        "Campus placement at TCS! Pay ₹1500 training fee before joining. Reply to confirm.",
        "Saw your resume on Naukri. WFH job ₹40k/month. Share bank account for salary setup.",
    ],
    "📈 Investment": [
        "This app gives 3x returns in 7 days! I earned ₹15000. Join: bit.ly/earn3x now!",
        "Crypto trading bot! Guaranteed ₹5000 daily profit. Invest ₹2000 to activate account.",
        "Stock market tips group. Pay ₹999 to join. Members earned ₹50k last week!",
    ],
    "✅ Safe": [
        "NPTEL enrollment closes April 30th. Register at swayam.gov.in before deadline!",
        "Internshala posted new software internships. Check linkedin.com. Deadline this Friday.",
        "Campus placement by Infosys on May 5th. Register on unstop.com before May 3rd.",
        "Hackathon on dare2compete.com this weekend! Team of 3-4. Last date: this Sunday.",
    ],
}

ALL_EXAMPLES = [ex for exs in EXAMPLES.values() for ex in exs]

SAFETY_TIPS = {
    LABEL_SCAM: [
        "🚫 Never share OTP — not even with bank staff",
        "🔒 Real internships NEVER charge registration fees",
        "📞 Verify only via official company website",
        "🗑️ Delete and block the sender immediately",
        "📢 Report to cybercrime.gov.in or call 1930",
    ],
    LABEL_SUSPICIOUS: [
        "🔍 Google company name + 'scam' before responding",
        "📧 Only use official .com / .org / .gov websites",
        "🤝 Ask a senior or professor before clicking links",
        "⏳ Scammers create urgency — never rush decisions",
    ],
    LABEL_SAFE: [
        "✅ Still verify the sender's identity officially",
        "🔗 Hover over links to preview the real URL",
        "🛡️ Keep your UPI PIN and passwords private always",
    ],
}

LABEL_BG = {
    LABEL_SAFE:       "rgba(34,197,94,0.1)",
    LABEL_SUSPICIOUS: "rgba(245,158,11,0.1)",
    LABEL_SCAM:       "rgba(239,68,68,0.1)",
}
LABEL_EMOJI = {
    LABEL_SAFE: "✅", LABEL_SUSPICIOUS: "⚠️", LABEL_SCAM: "🚫",
}


# ─────────────────────────────────────────────────────────────────────────────
# ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────
@st.cache_data(show_spinner=False, ttl=300)
def analyze(text: str) -> dict:
    processed = preprocess(text)
    rule_score, rule_reasons, payment_found = run_rules(processed["cleaned"])
    domain_score, domain_reasons, is_trusted = check_domain(processed["cleaned"])
    ml_score, ml_reason, ml_conf = get_ml_score(processed["normalized"])
    hist_score, hist_reason = check_history(processed["cleaned"])
    api_score, api_reasons  = run_api_checks(processed["cleaned"])

    final_score = calculate_final_score(
        rule_score=rule_score, domain_score=domain_score,
        ml_score=ml_score,     history_score=hist_score,
        is_trusted=is_trusted, payment_found=payment_found,
        api_score=api_score,
    )
    label, emoji, action = decide(final_score)
    color                = get_score_color(label)
    type_emoji, type_label, type_color = get_scam_type(processed["cleaned"])

    return {
        "rule_score": rule_score, "domain_score": domain_score,
        "ml_score": ml_score,     "hist_score": hist_score,
        "api_score": api_score,   "final_score": final_score,
        "label": label,           "emoji": emoji,
        "action": action,         "color": color,
        "type_emoji": type_emoji, "type_label": type_label,
        "type_color": type_color,
        "all_reasons": rule_reasons + domain_reasons + api_reasons,
        "ml_reason": ml_reason,   "ml_conf": ml_conf,
        "hist_reason": hist_reason,
        "is_trusted": is_trusted, "payment_found": payment_found,
    }


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def update_stats(label: str, text: str):
    if text == st.session_state.analyzed_text:
        return
    st.session_state.total += 1
    if label == LABEL_SCAM:         st.session_state.scams += 1
    elif label == LABEL_SAFE:       st.session_state.safe  += 1
    elif label == LABEL_SUSPICIOUS: st.session_state.suspicious += 1
    st.session_state.analyzed_text = text


def save_to_history(r: dict, text: str, source: str):
    if any(h["text"] == text for h in st.session_state.history):
        return
    st.session_state.history.insert(0, {
        "text": text,         "label": r["label"],
        "score": r["final_score"],
        "type_label": r["type_label"],
        "type_emoji": r["type_emoji"],
        "type_color": r["type_color"],
        "color": r["color"],  "reasons": r["all_reasons"],
        "time": datetime.now().strftime("%I:%M %p"),
        "source": source,     "result": r,
    })


def render_gauge(score: int, color: str):
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        domain={"x": [0,1], "y": [0,1]},
        title={"text": "RISK SCORE",
               "font": {"size": 12, "family": "Space Grotesk",
                        "color": "rgba(150,165,200,0.7)"}},
        gauge={
            "axis": {"range": [0,100], "tickwidth": 1,
                     "tickcolor": "rgba(150,165,200,0.2)",
                     "tickfont": {"color": "rgba(150,165,200,0.5)"}},
            "bar":  {"color": color, "thickness": 0.22},
            "bgcolor": "rgba(0,0,0,0)",
            "borderwidth": 0,
            "steps": [
                {"range": [0,  30], "color": "rgba(34,197,94,0.1)"},
                {"range": [30, 70], "color": "rgba(245,158,11,0.1)"},
                {"range": [70,100], "color": "rgba(239,68,68,0.12)"},
            ],
            "threshold": {
                "line":  {"color": color, "width": 3},
                "thickness": 0.72,
                "value": score,
            },
        },
        number={"font": {"size": 44, "color": color,
                         "family": "Space Grotesk"},
                "suffix": "/100"},
    ))
    fig.update_layout(
        height=210,
        margin=dict(l=20, r=20, t=44, b=5),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor ="rgba(0,0,0,0)",
        font=dict(family="Space Grotesk"),
    )
    st.plotly_chart(fig, use_container_width=True)


def render_bar(score: int, color: str):
    st.markdown(f"""
    <div class='bar-wrap'>
        <div class='bar-fill'
             style='width:{score}%;
                    background:linear-gradient(90deg,{color}77,{color});'>
        </div>
    </div>
    <div class='bar-labels'>
        <span>0 — Safe</span>
        <span>50 — Suspicious</span>
        <span>100 — Scam</span>
    </div>""", unsafe_allow_html=True)


def render_confidence_meter(r: dict):
    """Animated confidence meter for each score component."""

    def bar_colors(score):
        if score <= 30:
            return "#22c55e", "#16a34a"
        elif score <= 70:
            return "#f59e0b", "#d97706"
        else:
            return "#ef4444", "#dc2626"

    rs, re_ = bar_colors(r['rule_score'])
    ds, de  = bar_colors(r['domain_score'])
    ms, me  = bar_colors(r['ml_score'])
    hs, he  = bar_colors(r['hist_score'])
    fs, fe  = bar_colors(r['final_score'])

    st.markdown(f"""
    <div class='conf-wrap'>
        <div class='conf-title'>📊 Confidence Meters</div>

        <div class='conf-row'>
            <span class='conf-label'>📝 Rule Engine</span>
            <span class='conf-value' style='color:{rs};'>
                {r['rule_score']}/100
            </span>
        </div>
        <div class='conf-bar-bg'>
            <div class='conf-bar-fill'
                 style='--conf-width:{r["rule_score"]}%;
                        --bar-start:{rs};--bar-end:{re_};
                        width:{r["rule_score"]}%;'>
            </div>
        </div>

        <div class='conf-row' style='margin-top:10px;'>
            <span class='conf-label'>🌐 Domain Check</span>
            <span class='conf-value' style='color:{ds};'>
                {r['domain_score']}/100
            </span>
        </div>
        <div class='conf-bar-bg'>
            <div class='conf-bar-fill'
                 style='--conf-width:{r["domain_score"]}%;
                        --bar-start:{ds};--bar-end:{de};
                        width:{r["domain_score"]}%;'>
            </div>
        </div>

        <div class='conf-row' style='margin-top:10px;'>
            <span class='conf-label'>🤖 ML Model</span>
            <span class='conf-value' style='color:{ms};'>
                {r['ml_score']}/100
            </span>
        </div>
        <div class='conf-bar-bg'>
            <div class='conf-bar-fill'
                 style='--conf-width:{r["ml_score"]}%;
                        --bar-start:{ms};--bar-end:{me};
                        width:{r["ml_score"]}%;'>
            </div>
        </div>

        <div class='conf-row' style='margin-top:10px;'>
            <span class='conf-label'>📋 History Match</span>
            <span class='conf-value' style='color:{hs};'>
                {r['hist_score']}/100
            </span>
        </div>
        <div class='conf-bar-bg'>
            <div class='conf-bar-fill'
                 style='--conf-width:{r["hist_score"]}%;
                        --bar-start:{hs};--bar-end:{he};
                        width:{r["hist_score"]}%;'>
            </div>
        </div>

        <div style='border-top:1px solid rgba(255,255,255,0.07);
                    margin-top:12px;padding-top:12px;'>
            <div class='conf-row'>
                <span class='conf-label' style='font-weight:800;
                      color:#e8eeff;'>🎯 Final Score</span>
                <span class='conf-value' style='color:{fs};
                      font-size:1.1rem;'>
                    {r['final_score']}/100
                </span>
            </div>
            <div class='conf-bar-bg' style='height:12px;'>
                <div class='conf-bar-fill'
                     style='--conf-width:{r["final_score"]}%;
                            --bar-start:{fs};--bar-end:{fe};
                            width:{r["final_score"]}%;'>
                </div>
            </div>
        </div>
    </div>""", unsafe_allow_html=True)


def render_step_explainer(r: dict):
    """Step-by-step animated scam explanation."""
    color = r["color"]
    label = r["label"]

    steps = [
        {
            "num": "1",
            "label": "Keyword & Pattern Analysis",
            "score": r["rule_score"],
            "result": f"{r['rule_score']}/100 — "
                      f"{'🚨 High Risk' if r['rule_score']>70 else '⚠️ Suspicious' if r['rule_score']>30 else '✅ Clean'}",
            "detail": f"{len(r['all_reasons'])} suspicious pattern(s) found",
            "color":  "#3b82f6",
        },
        {
            "num": "2",
            "label": "Domain & URL Analysis",
            "score": r["domain_score"],
            "result": f"{r['domain_score']}/100 — "
                      f"{'🚨 Fake Domain' if r['domain_score']>70 else '⚠️ Suspicious URL' if r['domain_score']>30 else '✅ Clean URL'}",
            "detail": "Checked against brand impersonation database",
            "color":  "#f59e0b",
        },
        {
            "num": "3",
            "label": "ML Model Prediction",
            "score": r["ml_score"],
            "result": f"{r['ml_score']}/100 — "
                      f"{'🚨 Scam Detected' if r['ml_score']>70 else '⚠️ Possibly Suspicious' if r['ml_score']>30 else '✅ Looks Legitimate'}",
            "detail": r["ml_reason"] or "ML analysis complete",
            "color":  "#8b5cf6",
        },
        {
            "num": "4",
            "label": "History Database Search",
            "score": r["hist_score"],
            "result": f"{r['hist_score']}/100 — "
                      f"{'🚨 Known Scam Match' if r['hist_score']>70 else '⚠️ Similar Pattern Found' if r['hist_score']>30 else '✅ No Match Found'}",
            "detail": r["hist_reason"] or "No similar scams in history",
            "color":  "#22d3ee",
        },
        {
            "num": "5",
            "label": "Final Risk Calculation",
            "score": r["final_score"],
            "result": f"{r['final_score']}/100 — {label}",
            "detail": f"Weighted score across all {4} engines",
            "color":  color,
        },
    ]

    html = "<div class='steps-wrap'>"
    html += ("<div style='font-size:0.72rem;font-weight:700;"
             "text-transform:uppercase;letter-spacing:1.2px;"
             "color:rgba(150,165,200,0.6);margin-bottom:14px;'>"
             "⚡ Analysis Breakdown — Step by Step</div>")

    for i, step in enumerate(steps):
        delay    = i * 0.15
        sc       = step["score"]
        bar_color= step["color"]
        pct      = sc

        html += f"""
        <div class='step-row'
             style='animation-delay:{delay}s;'>
            <div class='step-num'
                 style='background:{bar_color}22;
                        color:{bar_color};
                        border:1px solid {bar_color}44;'>
                {step['num']}
            </div>
            <div style='flex:1;'>
                <div style='font-size:0.85rem;
                            color:rgba(200,215,245,0.9);
                            font-weight:600;margin-bottom:2px;'>
                    {step['label']}
                </div>
                <div style='font-size:0.75rem;
                            color:rgba(150,165,200,0.55);'>
                    {step['detail']}
                </div>
                <div style='background:rgba(255,255,255,0.05);
                            border-radius:999px;height:3px;
                            margin-top:6px;overflow:hidden;'>
                    <div style='height:100%;border-radius:999px;
                                width:{pct}%;
                                background:linear-gradient(90deg,
                                    {bar_color}88,{bar_color});
                                animation:confMeter 1s ease forwards;'>
                    </div>
                </div>
            </div>
            <div class='step-result'
                 style='color:{bar_color};
                        font-size:0.78rem;
                        max-width:160px;
                        text-align:right;'>
                {step['result']}
            </div>
        </div>"""

    html += "</div>"
    st.markdown(html, unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# RENDER RESULT
# ─────────────────────────────────────────────────────────────────────────────
def render_result(r: dict, input_text: str, source: str = "✍️ Text"):
    if not r or not input_text:
        return

    label = r["label"]; color = r["color"]; fs = r["final_score"]
    emoji = r["emoji"]; tc = r["type_color"]
    tl    = r["type_label"]; te = r["type_emoji"]

    update_stats(label, input_text)
    save_to_history(r, input_text, source)

    cls = {
        LABEL_SAFE:       "result-safe",
        LABEL_SUSPICIOUS: "result-suspicious",
        LABEL_SCAM:       "result-scam",
    }.get(label, "result-suspicious")

    # ── Result Card ────────────────────────────────────────────────────────
    st.markdown(f"""
    <div class='result-card {cls}'>
        <span class='result-icon'>{emoji}</span>
        <p class='result-label' style='color:{color};'>{label}</p>
        <p class='result-score' style='color:{color};'>
            {fs}<span>/100</span>
        </p>
        <span class='type-badge'
              style='background:{tc}18;color:{tc};
                     border-color:{tc}44;'>
            {te} {tl}
        </span>
    </div>""", unsafe_allow_html=True)

    # ── Gauge ──────────────────────────────────────────────────────────────
    st.markdown("<div class='gauge-wrap'>", unsafe_allow_html=True)
    render_gauge(fs, color)
    st.markdown("</div>", unsafe_allow_html=True)

    # ── Confidence Meters ──────────────────────────────────────────────────
    render_confidence_meter(r)

    # ── Step Explainer ─────────────────────────────────────────────────────
    render_step_explainer(r)

    # ── Score Breakdown ────────────────────────────────────────────────────
    with st.expander("🔢 Detailed Score Breakdown"):
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("📝 Rules",   f"{r['rule_score']}/100")
        c2.metric("🌐 Domain",  f"{r['domain_score']}/100")
        c3.metric("🤖 ML",      f"{r['ml_score']}/100")
        c4.metric("📋 History", f"{r['hist_score']}/100")
        c5.metric("🎯 Final",   f"{fs}/100")

        td = 25 if r["is_trusted"] and not r["payment_found"] else 0
        override = ""
        if r["is_trusted"] and r["payment_found"]:
            override = "\n⚠️  OVERRIDE: Trusted + Payment → Suspicious!"
        if r["hist_score"] >= 80:
            override = "\n🚨 OVERRIDE: Strong history match → High Risk!"

        st.markdown(f"""<div class='breakdown-card'>
Rule Score    {r['rule_score']:>3}  ×  35%  =  {int(r['rule_score']*0.35):>3}
Domain Score  {r['domain_score']:>3}  ×  30%  =  {int(r['domain_score']*0.30):>3}
ML Score      {r['ml_score']:>3}  ×  20%  =  {int(r['ml_score']*0.20):>3}
History Score {r['hist_score']:>3}  ×  15%  =  {int(r['hist_score']*0.15):>3}
Trust Bonus                          -  {td:>2}{override}
──────────────────────────────────────────────────
Final Score                          =  {fs} / 100</div>""",
                    unsafe_allow_html=True)

    # ── AI Insights ────────────────────────────────────────────────────────
    st.markdown(
        "<div class='section-header'>🤖 AI Insights</div>",
        unsafe_allow_html=True)

    if r["ml_reason"]:
        st.markdown(
            f"<div class='ml-card'>🤖 <b>ML Model</b> · {r['ml_reason']}</div>",
            unsafe_allow_html=True)
    if r["hist_reason"]:
        st.markdown(
            f"<div class='history-card'>📋 <b>History</b> · {r['hist_reason']}</div>",
            unsafe_allow_html=True)
    if r["api_score"] > 0:
        st.markdown(
            f"<div class='api-card'>🌐 <b>Live Threat Check</b> · Score: {r['api_score']}/100</div>",
            unsafe_allow_html=True)
    if r["is_trusted"] and not r["payment_found"]:
        st.markdown(
            "<div class='trusted-card'>✅ <b>Trusted Platform</b> · Verified campus platform detected</div>",
            unsafe_allow_html=True)
    if r["is_trusted"] and r["payment_found"]:
        st.markdown(
            "<div class='override-card'>🚨 <b>Override Alert</b> · Trusted name + payment request = possible impersonation!</div>",
            unsafe_allow_html=True)

    # ── Why flagged ────────────────────────────────────────────────────────
    st.markdown(
        "<div class='section-header'>🔎 Why This Score?</div>",
        unsafe_allow_html=True)
    reasons = r["all_reasons"]
    if reasons:
        for reason in reasons:
            st.markdown(
                f"<div class='reason-pill' style='border-color:{color};'>"
                f"{reason}</div>",
                unsafe_allow_html=True)
    else:
        st.markdown(
            "<div class='reason-pill' style='border-color:#22c55e;'>"
            "✅ No suspicious patterns detected.</div>",
            unsafe_allow_html=True)

    # ── Action ────────────────────────────────────────────────────────────
    st.markdown(
        "<div class='section-header'>💡 Recommended Action</div>",
        unsafe_allow_html=True)
    st.markdown(
        f"<div class='action-card' style='background:{LABEL_BG[label]};"
        f"color:{color};border-color:{color}44;'>"
        f"{emoji}&nbsp;&nbsp;{r['action']}</div>",
        unsafe_allow_html=True)

    # ── Safety Tips ────────────────────────────────────────────────────────
    st.markdown(
        "<div class='section-header'>🧠 Campus Safety Tips</div>",
        unsafe_allow_html=True)
    tips  = SAFETY_TIPS.get(label, [])
    tcols = st.columns(2)
    for i, tip in enumerate(tips):
        with tcols[i % 2]:
            st.markdown(
                f"<div class='tip-card'>{tip}</div>",
                unsafe_allow_html=True)

    # ── Report Button ─────────────────────────────────────────────────────
    st.markdown("<hr>", unsafe_allow_html=True)
    if label in [LABEL_SCAM, LABEL_SUSPICIOUS]:
        st.markdown(
            "<p style='color:rgba(150,165,200,0.6);"
            "font-size:0.83rem;margin-bottom:10px;'>"
            "🚩 Help protect your campus community</p>",
            unsafe_allow_html=True)

        # Glowing report button
        st.markdown("""
        <style>
        div[data-testid="stButton"].report-wrap > button {
            background: linear-gradient(135deg,
                rgba(239,68,68,0.85),
                rgba(185,28,28,0.85)) !important;
            border: 1.5px solid rgba(239,68,68,0.7) !important;
            color: #ffffff !important;
            font-size: 0.95rem !important;
            padding: 14px !important;
            box-shadow: 0 4px 24px rgba(239,68,68,0.4),
                        0 0 40px rgba(239,68,68,0.15) !important;
        }
        div[data-testid="stButton"].report-wrap > button:hover {
            box-shadow: 0 8px 32px rgba(239,68,68,0.6),
                        0 0 60px rgba(239,68,68,0.25) !important;
            transform: translateY(-2px) !important;
        }
        </style>
        """, unsafe_allow_html=True)

        if st.button(
            "🚩 Report This Scam — Protect Other Students",
            use_container_width=True,
            key=f"report_{source}_{fs}",
        ):
            saved = save_report(
                text=input_text, label=label, score=fs,
                scam_type=tl, reasons=reasons, source=source,
            )
            if saved:
                st.success(
                    "✅ Reported successfully! "
                    "This scam is now in our database. 🛡️")
                st.balloons()
            else:
                st.info("ℹ️ Already in our scam database. Thank you!")

    st.markdown("""
    <div style='text-align:center;color:rgba(150,165,200,0.3);
         font-size:0.73rem;padding:16px 0 4px;
         border-top:1px solid rgba(255,255,255,0.05);
         margin-top:16px;'>
        🛡️ Campus Fraud Shield ·
        Always verify before you click, pay or share
    </div>""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# HISTORY TAB
# ─────────────────────────────────────────────────────────────────────────────
def render_history_tab():
    history = st.session_state.history
    if not history:
        st.markdown("""
        <div class='hist-empty'>
            <div>🔍</div>
            <p style='color:rgba(150,165,200,0.5);'>
                <strong style='color:#93c5fd;'>No scans yet</strong><br>
                Analyze a message to get started!
            </p>
        </div>""", unsafe_allow_html=True)
        return

    total  = len(history)
    scams  = sum(1 for h in history if h["label"] == LABEL_SCAM)
    suspic = sum(1 for h in history if h["label"] == LABEL_SUSPICIOUS)
    safe   = sum(1 for h in history if h["label"] == LABEL_SAFE)

    h1,h2,h3,h4 = st.columns(4)
    with h1: st.markdown(f"<div class='stat-card'><div class='stat-num' style='color:#93c5fd;'>{total}</div><div class='stat-label'>Total Scans</div></div>", unsafe_allow_html=True)
    with h2: st.markdown(f"<div class='stat-card'><div class='stat-num' style='color:#ef4444;'>{scams}</div><div class='stat-label'>Scams</div></div>", unsafe_allow_html=True)
    with h3: st.markdown(f"<div class='stat-card'><div class='stat-num' style='color:#f59e0b;'>{suspic}</div><div class='stat-label'>Suspicious</div></div>", unsafe_allow_html=True)
    with h4: st.markdown(f"<div class='stat-card'><div class='stat-num' style='color:#22c55e;'>{safe}</div><div class='stat-label'>Safe</div></div>", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    col_f1, col_f2 = st.columns([4,1])
    with col_f1:
        fltr = st.selectbox("Filter",
            ["All","🚫 Scam","⚠️ Suspicious","✅ Safe"],
            label_visibility="collapsed")
    with col_f2:
        if st.button("🗑️ Clear", use_container_width=True, key="clear_hist"):
            for k in ["history","total","scams","safe",
                      "suspicious","analyzed_text"]:
                st.session_state[k] = (
                    [] if k=="history" else
                    "" if k=="analyzed_text" else 0
                )
            st.rerun()

    fmap = {"All":None, "🚫 Scam":LABEL_SCAM,
            "⚠️ Suspicious":LABEL_SUSPICIOUS, "✅ Safe":LABEL_SAFE}
    filtered = [h for h in history
                if fmap[fltr] is None or h["label"]==fmap[fltr]]

    if not filtered:
        st.info(f"No {fmap[fltr]} results yet.")
        return

    st.markdown(
        f"<p style='color:rgba(150,165,200,0.5);font-size:0.83rem;'>"
        f"{len(filtered)} scan{'s' if len(filtered)!=1 else ''}</p>",
        unsafe_allow_html=True)

    for idx, h in enumerate(filtered):
        color = h["color"]; label = h["label"]
        msg_p = h["text"][:100]+("..." if len(h["text"])>100 else "")
        st.markdown(f"""
        <div class='hist-card'>
            <div style='display:flex;align-items:center;
                        justify-content:space-between;gap:10px;'>
                <span class='hist-badge'
                      style='background:{color}18;color:{color};
                             border-color:{color}40;'>
                    {LABEL_EMOJI[label]} {label}
                </span>
                <span style='font-size:1.6rem;font-weight:900;
                             color:{color};font-family:Space Grotesk;'>
                    {h['score']}
                    <span style='font-size:0.85rem;font-weight:400;
                                 color:rgba(150,165,200,0.5);'>/100</span>
                </span>
                <span style='flex:1;'></span>
                <span style='font-size:0.7rem;
                             color:rgba(150,165,200,0.4);'>
                    {h.get('source','Text')} · {h['time']}
                </span>
            </div>
            <div style='font-size:0.76rem;
                        color:rgba(150,165,200,0.55);margin-top:4px;'>
                {h['type_emoji']} {h['type_label']}
            </div>
            <div style='margin-top:10px;padding-top:10px;
                        border-top:1px solid rgba(255,255,255,0.04);
                        font-size:0.84rem;color:#c8d4f0;line-height:1.5;'>
                {msg_p}
            </div>
            <div style='font-size:0.7rem;
                        color:rgba(150,165,200,0.4);margin-top:5px;'>
                {len(h['reasons'])} flag{'s' if len(h['reasons'])!=1 else ''} detected
            </div>
        </div>""", unsafe_allow_html=True)

        with st.expander(f"Details — Scan #{idx+1}"):
            st.markdown(
                f"<p style='color:#c8d4f0;font-size:0.88rem;'>"
                f"{h['text']}</p>",
                unsafe_allow_html=True)
            if h["reasons"]:
                for rr in h["reasons"]:
                    st.markdown(
                        f"<div class='reason-pill' "
                        f"style='border-color:{color};'>{rr}</div>",
                        unsafe_allow_html=True)
            render_bar(h["score"], color)
            if st.button("🔁 Re-analyze",
                         key=f"re_{idx}",
                         use_container_width=True):
                st.session_state.input_text = h["text"]
                st.session_state.result     = None
                st.rerun()

    st.markdown("<hr>", unsafe_allow_html=True)
    lines = ["Campus Fraud Shield — History\n"+"="*50+"\n"]
    for i,h in enumerate(history,1):
        lines.append(
            f"[{i}] {h['time']} | {h['label']} | "
            f"{h['score']}/100 | {h['type_label']}\n"
            f"    {h['text'][:80]}"
            f"{'...' if len(h['text'])>80 else ''}\n"
            f"    Flags: "
            f"{', '.join(h['reasons'][:3]) if h['reasons'] else 'None'}\n"
        )
    st.download_button(
        "📥 Export History",
        "\n".join(lines),
        "cfs_history.txt", "text/plain",
        use_container_width=True,
    )


# ─────────────────────────────────────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown(
        "<p class='sb-title'>🛡️ Campus Fraud Shield</p>",
        unsafe_allow_html=True)
    st.markdown(
        "<p style='font-size:0.7rem;color:rgba(150,165,200,0.4);"
        "margin-top:-6px;'>AI-Powered Scam Detection</p>",
        unsafe_allow_html=True)
    st.markdown(
        "<hr style='border-color:rgba(59,130,246,0.2);margin:10px 0;'>",
        unsafe_allow_html=True)

    # Stats
    st.markdown(f"""
    <div class='sb-section'>
        <div class='sb-section-title'>📊 Session Stats</div>
        <div class='sb-item'>Total Analyzed
            <span class='sb-num' style='margin-left:auto;'>
                {st.session_state.total}
            </span>
        </div>
        <div class='sb-item'>Scams Caught
            <span style='margin-left:auto;font-weight:900;
                         color:#ef4444;'>
                {st.session_state.scams}
            </span>
        </div>
        <div class='sb-item'>Suspicious
            <span style='margin-left:auto;font-weight:900;
                         color:#f59e0b;'>
                {st.session_state.suspicious}
            </span>
        </div>
        <div class='sb-item'>Safe Messages
            <span style='margin-left:auto;font-weight:900;
                         color:#22c55e;'>
                {st.session_state.safe}
            </span>
        </div>
    </div>""", unsafe_allow_html=True)

    # Helplines
    st.markdown("""
    <div class='sb-section'>
        <div class='sb-section-title'>🆘 Emergency Helplines</div>
        <div class='sb-item'>Cyber Crime
            <span class='sb-num' style='margin-left:auto;'>1930</span>
        </div>
        <div class='sb-item'>Police
            <span class='sb-num' style='margin-left:auto;'>100</span>
        </div>
        <div class='sb-item'>Bank Fraud
            <span class='sb-num' style='margin-left:auto;'>155260</span>
        </div>
        <div class='sb-item'>Women Helpline
            <span class='sb-num' style='margin-left:auto;'>1091</span>
        </div>
    </div>""", unsafe_allow_html=True)

    # Portals
    st.markdown("""
    <div class='sb-section'>
        <div class='sb-section-title'>🌐 Report Portals</div>
        <div class='sb-item' style='flex-direction:column;gap:2px;'>
            <span style='font-weight:600;'>Cyber Crime Portal</span>
            <span style='font-size:0.75rem;color:#67e8f9;'>
                cybercrime.gov.in
            </span>
        </div>
        <div class='sb-item' style='flex-direction:column;gap:2px;'>
            <span style='font-weight:600;'>Report Spam SMS</span>
            <span style='font-size:0.75rem;color:#67e8f9;'>
                sancharsaathi.gov.in
            </span>
        </div>
    </div>""", unsafe_allow_html=True)

    # Trusted
    st.markdown("""
    <div class='sb-section'>
        <div class='sb-section-title'>✅ Trusted Platforms</div>
        <div class='sb-item'>internshala.com
            <span class='sb-safe' style='margin-left:auto;'>Safe</span>
        </div>
        <div class='sb-item'>linkedin.com
            <span class='sb-safe' style='margin-left:auto;'>Safe</span>
        </div>
        <div class='sb-item'>unstop.com
            <span class='sb-safe' style='margin-left:auto;'>Safe</span>
        </div>
        <div class='sb-item'>nptel.ac.in
            <span class='sb-safe' style='margin-left:auto;'>Safe</span>
        </div>
        <div class='sb-item'>dare2compete.com
            <span class='sb-safe' style='margin-left:auto;'>Safe</span>
        </div>
    </div>""", unsafe_allow_html=True)

    # Golden Rules
    st.markdown("""
    <div class='sb-section'>
        <div class='sb-section-title'>🔑 Golden Rules</div>
        <div class='sb-item'>🚫 Never share OTP with anyone</div>
        <div class='sb-item'>💰 Real jobs never ask for fees</div>
        <div class='sb-item'>🔗 Avoid bit.ly short links</div>
        <div class='sb-item'>⏰ Urgency = red flag. Always.</div>
        <div class='sb-item'>✅ Verify on official website only</div>
    </div>""", unsafe_allow_html=True)

    # Trending
    trending = get_trending_scams(3)
    if trending:
        st.markdown(
            "<div class='sb-section'>"
            "<div class='sb-section-title'>🔥 Trending Scams</div>",
            unsafe_allow_html=True)
        for t in trending:
            preview = t.get("text","")[:45]+"..."
            st.markdown(
                f"<div class='trending-card'>"
                f"{t.get('type_emoji','⚠️')} {preview}</div>",
                unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("""
    <div style='text-align:center;padding:12px 0 4px;
         font-size:0.68rem;color:rgba(150,165,200,0.25);'>
        🛡️ Campus Fraud Shield · Stay safe. Stay smart.
    </div>""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN UI
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<div class='hero'>
    <div class='hero-badge'>
        🇮🇳 Built for Indian Campuses · Scalable Globally
    </div>
    <span class='hero-icon'>🛡️</span>
    <h1>Campus Fraud Shield</h1>
    <p>AI-powered scam detection ·
       Messages · Links · Screenshots · QR Codes</p>
</div>""", unsafe_allow_html=True)

# Stats
s1,s2,s3,s4 = st.columns(4)
with s1: st.markdown(f"<div class='stat-card'><div class='stat-num' style='color:#93c5fd;'>{st.session_state.total}</div><div class='stat-label'>Total Analyzed</div></div>", unsafe_allow_html=True)
with s2: st.markdown(f"<div class='stat-card'><div class='stat-num' style='color:#ef4444;'>{st.session_state.scams}</div><div class='stat-label'>Scams Caught</div></div>", unsafe_allow_html=True)
with s3: st.markdown(f"<div class='stat-card'><div class='stat-num' style='color:#f59e0b;'>{st.session_state.suspicious}</div><div class='stat-label'>Suspicious</div></div>", unsafe_allow_html=True)
with s4: st.markdown(f"<div class='stat-card'><div class='stat-num' style='color:#22c55e;'>{st.session_state.safe}</div><div class='stat-label'>Safe Messages</div></div>", unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# Tabs
hist_count = len(st.session_state.history)
tab1,tab2,tab3,tab4,tab5 = st.tabs([
    "🔍 Analyze",
    "📸 Screenshot",
    "📷 QR Code",
    f"📋 History ({hist_count})",
    "⚙️ Admin",
])


# ══════════════════════════════════════════════════════════════════
# TAB 1 — ANALYZE
# ══════════════════════════════════════════════════════════════════
with tab1:

    # ── Search Box ────────────────────────────────────────────────
    st.markdown("<div class='search-wrap'>", unsafe_allow_html=True)
    st.markdown(
        "<span class='search-label'>"
        "🔍 Paste any message, link, or suspicious content"
        "</span>",
        unsafe_allow_html=True)

    user_text = st.text_area(
        "input",
        label_visibility="collapsed",
        value=st.session_state.input_text,
        height=130,
        placeholder=(
            "Paste any WhatsApp message, suspicious link, "
            "or scam content here..."
        ),
        key="main_input",
    )

    # Buttons row
    col_a, col_b, col_c = st.columns([5, 1.2, 1])
    with col_a:
        analyze_btn = st.button(
            "🔍 Analyze Now",
            use_container_width=True,
            key="analyze_btn",
        )
    with col_b:
        random_btn = st.button(
            "🎲 Random",
            use_container_width=True,
            key="random_btn",
            help="Load a random example",
        )
    with col_c:
        clear_btn = st.button(
            "✕",
            use_container_width=True,
            key="clear_btn",
        )

    # Example category tags
    st.markdown(
        "<div style='margin-top:14px;'>"
        "<span style='font-size:0.67rem;font-weight:700;"
        "color:rgba(150,165,200,0.45);text-transform:uppercase;"
        "letter-spacing:1.2px;'>Quick examples →</span>"
        "</div>",
        unsafe_allow_html=True)

    tag_cols = st.columns(len(EXAMPLES))
    for col, (cat_name, cat_examples) in zip(tag_cols, EXAMPLES.items()):
        with col:
            if st.button(
                cat_name,
                use_container_width=True,
                key=f"tag_{cat_name}",
            ):
                # Pick random example from that category
                st.session_state.input_text = random.choice(cat_examples)
                st.session_state.result     = None
                st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)

    # Button logic
    if random_btn:
        st.session_state.input_text = random.choice(ALL_EXAMPLES)
        st.session_state.result     = None
        st.rerun()

    if clear_btn:
        st.session_state.input_text    = ""
        st.session_state.result        = None
        st.session_state.analyzed_text = ""
        st.rerun()

    active_text = (
        user_text.strip() or
        st.session_state.input_text.strip()
    )

    if analyze_btn:
        if not active_text:
            st.warning("⚠️ Please paste a message or click an example tag.")
        else:
            # Show step loader
            with st.spinner("🔍 Running AI analysis..."):
                result = analyze(active_text)
            st.session_state.result     = result
            st.session_state.input_text = active_text

    if st.session_state.result is not None:
        render_result(
            st.session_state.result,
            st.session_state.analyzed_text or active_text,
            "✍️ Text",
        )


# ══════════════════════════════════════════════════════════════════
# TAB 2 — SCREENSHOT
# ══════════════════════════════════════════════════════════════════
with tab2:
    st.markdown("""
    <div class='glass-card'>
        <div style='font-size:0.85rem;color:rgba(180,195,230,0.8);
                    line-height:1.75;'>
            📌 <strong style='color:#93c5fd;'>How it works:</strong>
            Upload any WhatsApp, SMS, or Instagram screenshot →
            text extracted automatically →
            analyzed for scam patterns instantly.
        </div>
    </div>""", unsafe_allow_html=True)

    ocr_file = st.file_uploader(
        "Choose screenshot",
        type=["png","jpg","jpeg","webp","bmp"],
        key="ocr_upload",
    )

    if ocr_file:
        st.image(ocr_file, caption="Uploaded screenshot",
                 use_container_width=True)
        st.markdown("<br>", unsafe_allow_html=True)

        if st.button("📸 Extract Text & Analyze",
                     use_container_width=True, key="ocr_btn"):
            with st.spinner("Extracting text from image..."):
                try:
                    from PIL import Image
                    import pytesseract
                    import numpy as np
                    import cv2

                    pytesseract.pytesseract.tesseract_cmd = (
                        r"C:\Program Files\Tesseract-OCR\tesseract.exe"
                    )
                    img    = Image.open(ocr_file).convert("RGB")
                    img_np = np.array(img)
                    gray   = cv2.cvtColor(img_np, cv2.COLOR_RGB2GRAY)
                    gray   = cv2.resize(gray, None, fx=2, fy=2,
                                        interpolation=cv2.INTER_CUBIC)
                    _, th  = cv2.threshold(gray, 150, 255,
                                           cv2.THRESH_BINARY)
                    extracted = pytesseract.image_to_string(
                        th, config="--oem 3 --psm 6").strip()

                    if not extracted:
                        st.error("❌ No text found. Try a clearer image.")
                    else:
                        st.markdown(f"""
                        <div style='background:rgba(34,211,238,0.06);
                                    border:1px solid rgba(34,211,238,0.2);
                                    border-left:3px solid rgba(34,211,238,0.6);
                                    border-radius:12px;padding:14px 18px;
                                    margin:12px 0;color:#c8d4f0;
                                    font-size:0.875rem;line-height:1.6;'>
                            <strong style='color:#22d3ee;'>
                                📸 Extracted Text:
                            </strong><br>{extracted}
                        </div>""", unsafe_allow_html=True)

                        edited = st.text_area(
                            "Edit if needed:",
                            value=extracted,
                            height=100,
                            key="ocr_edit",
                        )
                        with st.spinner("Analyzing..."):
                            res = analyze(edited.strip())
                        render_result(
                            res, edited.strip(), "📸 Screenshot")
                except Exception as e:
                    st.error(f"❌ OCR Error: {e}")
    else:
        st.markdown("""
        <div class='upload-zone'>
            <div style='font-size:4rem;margin-bottom:10px;
                        filter:drop-shadow(0 0 20px rgba(59,130,246,0.7));'>
                📸
            </div>
            <h3>Upload Screenshot</h3>
            <p>PNG, JPG, JPEG, WebP supported</p>
        </div>""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════
# TAB 3 — QR CODE
# ══════════════════════════════════════════════════════════════════
with tab3:
    st.markdown("""
    <div class='glass-card'>
        <div style='font-size:0.85rem;color:rgba(180,195,230,0.8);
                    line-height:1.75;'>
            📌 <strong style='color:#93c5fd;'>Safe QR Analysis:</strong>
            Upload the QR code here BEFORE scanning it anywhere.
            We decode and check the hidden URL for threats.
        </div>
    </div>""", unsafe_allow_html=True)

    qr_file = st.file_uploader(
        "Choose QR code image",
        type=["png","jpg","jpeg","webp","bmp"],
        key="qr_upload",
    )

    if qr_file:
        col_img, col_tips = st.columns([1,1])
        with col_img:
            st.image(qr_file, caption="Uploaded QR",
                     use_container_width=True)
        with col_tips:
            st.markdown("""
            <div class='glass-card' style='margin-top:0;'>
                <div style='font-size:0.85rem;color:#c8d4f0;
                            line-height:1.85;'>
                    <strong style='color:#93c5fd;'>
                        🛡️ Safe QR Tips
                    </strong><br><br>
                    ✅ Check URL before visiting<br>
                    🚫 Never pay from unknown QR<br>
                    🔍 Verify QR source first<br>
                    📱 UPI QR from trusted shops only
                </div>
            </div>""", unsafe_allow_html=True)

        if st.button("📷 Decode QR & Analyze",
                     use_container_width=True, key="qr_btn"):
            with st.spinner("Decoding QR code..."):
                try:
                    from PIL import Image
                    import cv2, numpy as np

                    img    = Image.open(qr_file).convert("RGB")
                    img_np = np.array(img)
                    img_np = cv2.copyMakeBorder(
                        img_np,50,50,50,50,
                        cv2.BORDER_CONSTANT,value=[255,255,255])
                    detector = cv2.QRCodeDetector()
                    data, _, _ = detector.detectAndDecode(img_np)

                    if not data:
                        gray = cv2.cvtColor(img_np,cv2.COLOR_RGB2GRAY)
                        data, _, _ = detector.detectAndDecode(gray)

                    if not data:
                        try:
                            from pyzbar.pyzbar import decode as pyd
                            decoded = pyd(img_np)
                            if decoded:
                                data = decoded[0].data.decode("utf-8")
                        except Exception:
                            pass

                    if not data:
                        st.error("❌ Could not decode QR. Try clearer image.")
                    else:
                        st.markdown(f"""
                        <div style='background:rgba(34,211,238,0.06);
                                    border:1px solid rgba(34,211,238,0.2);
                                    border-left:3px solid rgba(34,211,238,0.6);
                                    border-radius:12px;padding:14px 18px;
                                    margin:12px 0;color:#c8d4f0;
                                    font-size:0.875rem;'>
                            <strong style='color:#22d3ee;'>
                                📷 Decoded QR:
                            </strong><br>{data}
                        </div>""", unsafe_allow_html=True)
                        with st.spinner("Analyzing..."):
                            res = analyze(data.strip())
                        render_result(res, data.strip(), "📷 QR Code")
                except Exception as e:
                    st.error(f"❌ QR Error: {e}")
    else:
        st.markdown("""
        <div class='upload-zone'>
            <div style='font-size:4rem;margin-bottom:10px;
                        filter:drop-shadow(0 0 20px rgba(245,158,11,0.7));'>
                📷
            </div>
            <h3>Upload QR Code</h3>
            <p>PNG, JPG, JPEG, WebP supported</p>
        </div>""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════
# TAB 4 — HISTORY
# ══════════════════════════════════════════════════════════════════
with tab4:
    render_history_tab()


# ══════════════════════════════════════════════════════════════════
# TAB 5 — ADMIN
# ══════════════════════════════════════════════════════════════════
with tab5:
    render_admin_dashboard()