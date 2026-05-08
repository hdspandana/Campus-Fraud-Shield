# Campus Fraud Shield 🛡️ — One Page Pitch

## The Problem

Every year, **lakhs of Indian college students** lose money to scams
targeting them specifically:

```
₹999 registration fee for fake Internshala internship
₹1500 processing fee to claim fake KBC prize
₹500 to release fake NSP scholarship of ₹25000
Share OTP to unblock fake SBI account
```

These scams work because students are:
- Desperate for internships and jobs
- Unfamiliar with how real companies operate
- Trusting of messages that look official
- Under pressure from urgency tactics

---

## Our Solution

**Campus Fraud Shield** — paste any WhatsApp/SMS message,
get instant analysis with explanation.

```
Input:  "Pay ₹999 registration fee to confirm Internshala slot"
Output: 🚨 SCAM — 88/100 confidence
        "Internshala NEVER charges registration fee"
        Steps: Block sender → Screenshot → Report 1930
```

---

## What Makes Us Different

| Feature | Others | Us |
|---|---|---|
| India-specific rules | ❌ | ✅ Internshala, NSP, SBI, KBC |
| Student-friendly explanations | ❌ | ✅ Plain English + what to do |
| 4-engine pipeline | ❌ | ✅ Rules + Domain + AI + History |
| Pre-filled complaint text | ❌ | ✅ Ready for cybercrime.gov.in |
| Community scam database | ❌ | ✅ FAISS vector search |
| Works offline | ❌ | ✅ No API keys needed |

---

## Technical Architecture

```
4 Engines → Weighted Score → Verdict + Actions

Rules Engine    35%  — 50+ India-specific regex patterns
Domain Check    30%  — URL/email verification + impersonation
Semantic AI     20%  — all-MiniLM-L6-v2 embeddings
FAISS History   15%  — Community scam report similarity
```

---

## Impact

```
Target users:  2.5 crore+ Indian college students
Scam types:    8 categories covered
Response time: < 3 seconds per scan
Languages:     English + Hinglish patterns
Helpline:      1930 (integrated)
```

---

## The Ask

Deploy this as a free tool at every college campus.
Add it to placement cell WhatsApp groups.
Make scam detection as easy as forwarding a message.

**One paste. Instant answer. Student protected.**