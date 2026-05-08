# Judges Evaluation Checklist ✅

## Campus Fraud Shield 🛡️

Use this to verify every feature during the demo.

---

## Core Functionality

### Scam Detection
- [ ] Paste fake internship message → SCAM verdict
- [ ] Paste prize/lottery message → SCAM verdict  
- [ ] Paste safe TCS interview message → SAFE verdict
- [ ] Confidence score shown (0–100)
- [ ] Verdict badge changes colour (red/yellow/green)

### 4-Engine Breakdown
- [ ] All 4 engine scores visible after scan
- [ ] Labels shown: Rules Engine / Domain Check / Semantic AI / FAISS History
- [ ] Weights shown: 35% / 30% / 20% / 15%
- [ ] Formula displayed: `0.35×Rules + 0.30×Domain + 0.20×ML + 0.15×History`

### Explainability
- [ ] "Why did we flag this?" section opens
- [ ] Technical mode: shows raw engine reasons
- [ ] Student mode toggle: shows plain English explanations
- [ ] Similar cases shown from ML training examples

### Override Logic
- [ ] OTP message → "Override Applied" banner appears
- [ ] Override reason shown in UI

### Conflicted Signal
- [ ] When engines disagree → conflict banner shown
- [ ] Message says "manual verification recommended"

---

## Action Steps

- [ ] Action steps shown for SCAM/SUSPICIOUS
- [ ] Helpline **1930** shown
- [ ] Link to cybercrime.gov.in shown
- [ ] "Copy Complaint Text" section present
- [ ] Complaint text is pre-filled and ready to copy

---

## UI/UX

- [ ] Dark theme (#0a0f1e background)
- [ ] 3 demo preset buttons work
- [ ] Clicking preset fills text box
- [ ] "Scan Message" button triggers analysis
- [ ] Empty input shows warning (not crash)
- [ ] Clear button resets state
- [ ] Progress bar shown during scan
- [ ] Results persist when toggling student mode

---

## India-Specific Knowledge

- [ ] Internshala fee policy known (never charges)
- [ ] NSP scholarship max amount known (₹3500/month)
- [ ] SBI official number known (1800-11-2211)
- [ ] KBC lottery pattern detected
- [ ] Gmail + company name = scam detected
- [ ] Personal UPI number = scam signal
- [ ] Hinglish patterns detected (jaldi karo, abhi bhejo)

---

## Technical Depth (for judges)

- [ ] Sentence transformer model: `all-MiniLM-L6-v2`
- [ ] FAISS inner product index with L2 normalisation
- [ ] Logistic Regression with balanced class weights
- [ ] SQLite WAL mode for persistence
- [ ] KMeans clustering on scam vectors
- [ ] Overlap phrase detection for explainability
- [ ] Weighted formula: verified adds to exactly 100%

---

## Resilience

- [ ] App loads even if models/ folder is empty
  (inline training fallback)
- [ ] App loads even if all imports fail
  (simulation mode banner shown)
- [ ] Each engine failure is caught individually
- [ ] No unhandled exceptions visible to user

---

## Scoring Summary

| Area | Max Points | Notes |
|---|---|---|
| Problem clarity | 10 | India-specific, well-defined |
| Technical depth | 25 | 4 engines, ML, FAISS, explainability |
| Working demo | 25 | All 3 presets + custom input |
| Innovation | 20 | Student mode, override, conflict detection |
| Impact | 20 | Helpline, complaint text, action steps |
| **Total** | **100** | |