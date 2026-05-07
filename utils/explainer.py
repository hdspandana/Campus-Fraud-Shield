# utils/explainer.py
# ═════════════════════════════════════════════════════════════════
# Explain Like I'm 18 — Student-Friendly Explanations
# Maps technical reasons to plain English with specific advice
# Toggle between Technical Mode and Student Mode
# ═════════════════════════════════════════════════════════════════

from typing import List, Dict, Any


# ── Technical → Student Translation Dictionary ───────────────────
EXPLANATION_MAP = {
    # Fee violations
    "Internshala never charges registration fee": {
        "student": "⚠️ Internshala NEVER asks for money. The real Internshala is completely free for students. If someone asks for 'registration fee,' they are pretending to be Internshala.",
        "action": "Do not pay. Real internships don't need payment."
    },
    "Message contains fee demand": {
        "student": "🚨 A real company or scholarship will NEVER ask you to pay first. 'Pay to get job' is the #1 rule of scams.",
        "action": "Never pay for jobs, internships, or scholarships."
    },
    "Phonepe never charges registration fee": {
        "student": "⚠️ PhonePe is a payment app — it does not offer jobs or internships. This message is pretending to be official.",
        "action": "PhonePe never asks for registration fees."
    },
    "Nsp scholarship max is Rs.3500/month. Claimed Rs.25000 is suspicious": {
        "student": "📊 The real NSP scholarship gives Rs.1000-3500 per month. Claiming Rs.25,000 is a lie to trick you.",
        "action": "Check scholarships.gov.in only — never trust WhatsApp messages."
    },
    "Pm_Scholarship scholarship max is Rs.3000/month. Claimed Rs.50000 is suspicious": {
        "student": "📊 PM Scholarship is Rs.2000-3000/month maximum. Anyone promising more is lying.",
        "action": "Verify only on scholarships.gov.in"
    },

    # Contact violations
    "Real SBI never contacts via personal mobile number": {
        "student": "🏦 Real SBI uses official numbers like 1800-11-2211. They never call from random 10-digit mobile numbers.",
        "action": "Call SBI official number if unsure. Never share OTP."
    },
    "Real PAYTM never contacts via personal mobile number": {
        "student": "💳 Real Paytm uses their official app and website. They don't WhatsApp you from personal numbers.",
        "action": "Check the Paytm app directly — don't trust random messages."
    },
    "Real INTERNSHALA never uses Gmail — official email must end in @internshala.com": {
        "student": "📧 Real Internshala emails end with @internshala.com. @gmail.com means someone is pretending.",
        "action": "Check: Does the email end with the company name? If not, it's fake."
    },
    "Professional recruitment emails never use Gmail — real companies use official domain emails": {
        "student": "📧 HR at TCS/Amazon/Infosys uses @tcs.com, @amazon.in — NEVER @gmail.com. Gmail = personal account = fake recruiter.",
        "action": "Always check the email domain before replying."
    },

    # OTP / Security
    "Real banks NEVER ask for OTP via message/call. OTP sharing = scam": {
        "student": "🔐 Your OTP is your bank password. Real banks say: 'Never share OTP.' Anyone asking = 100% scammer.",
        "action": "Never share OTP. Hang up immediately."
    },
    "Asks to share sensitive mobile OTP": {
        "student": "🔐 OTP = key to your bank account. Sharing it is like giving your ATM PIN to a stranger.",
        "action": "Never share OTP via call, message, or WhatsApp."
    },

    # Process violations
    "Real internships/jobs interview BEFORE selecting candidates. Selection before interview = scam": {
        "student": "🎯 Real process: Apply → Interview → Offer. Scam process: 'You are selected!' → Pay fee → Nothing.",
        "action": "If they say 'selected' without interview, it's fake."
    },
    "Real companies NEVER ask for fee to confirm offer. Fee before joining = scam": {
        "student": "💼 Joining a real company: You get offer letter FIRST, then join. You NEVER pay to 'confirm' your seat.",
        "action": "If they ask money before offer letter = scam."
    },
    "KYC via WhatsApp = scam": {
        "student": "📱 Real KYC happens at bank branch or official app. Never via WhatsApp or phone call.",
        "action": "Visit bank branch or use official app only."
    },

    # Domain / URL
    "Suspicious shortened URL (bit.ly) hides real destination": {
        "student": "🔗 Short links (bit.ly, tinyurl) hide where they really go. Scammers use them to hide fake websites.",
        "action": "Never click short links in job/scholarship messages."
    },
    "Domain uses suspicious TLD (.xyz)": {
        "student": "🌐 Real banks use .com or .in. Scammers buy cheap domains like .xyz, .tk to look real.",
        "action": "Check the website ending. .xyz with bank name = fake."
    },
    "Fake Internshala website detected — real site is internshala.com": {
        "student": "🌐 Scammers create fake websites that look like Internshala but have wrong spelling or domain.",
        "action": "Always type internshala.com directly — never click links."
    },

    # Urgency
    "Urgency language detected — a common scam pressure tactic": {
        "student": "⏰ Scammers say '24 hours only!' or 'Offer expires!' to panic you so you don't think. Real offers don't expire in hours.",
        "action": "Take your time. Real opportunities wait."
    },
    "Multiple urgency tactics detected — scammers use time pressure to prevent thinking": {
        "student": "⏰ When a message shouts 'URGENT! ACT NOW! LIMITED!' — it's designed to stop your brain from thinking.",
        "action": "Pause. Ask a friend. Real things are not this urgent."
    },

    # Lottery / Prize
    "Lucky draw/lottery you never entered = guaranteed scam": {
        "student": "🎁 You can't win a lottery you never bought. 'You won iPhone/KBC!' is the oldest trick.",
        "action": "Delete the message. You didn't win anything."
    },

    # Safe signals
    "No suspicious patterns detected — message appears legitimate": {
        "student": "✅ This message looks safe. No scam patterns found.",
        "action": "Still good practice: verify by logging into official website directly."
    },
    "Semantic pattern match": {
        "student": "✅ The AI checked the message style and found it matches real, safe messages.",
        "action": "Looks legitimate, but always double-check important details."
    },
}


# ═════════════════════════════════════════════════════════════════
class Explainer:
    """
    Converts technical detection reasons into student-friendly language.
    Supports Technical Mode and Student Mode.
    """

    def __init__(self, student_mode: bool = False):
        self.student_mode = student_mode

    def explain(self, reasons: List[str]) -> List[Dict[str, str]]:
        """
        Convert list of technical reasons to explanations.

        Args:
            reasons: List of technical reason strings

        Returns:
            List of dicts with 'technical' and 'student' versions
        """
        results = []

        for reason in reasons:
            mapped = EXPLANATION_MAP.get(reason)

            if mapped:
                results.append({
                    "technical": reason,
                    "student":   mapped["student"],
                    "action":    mapped["action"]
                })
            else:
                # Fallback: return technical as-is if no mapping
                results.append({
                    "technical": reason,
                    "student":   f"⚠️ {reason}",
                    "action":    "Be cautious and verify independently."
                })

        return results

    def format_reasons(self, reasons: List[str]) -> str:
        """
        Format reasons for display based on current mode.

        Args:
            reasons: List of technical reason strings

        Returns:
            Formatted markdown string
        """
        explanations = self.explain(reasons)

        lines = []
        for i, exp in enumerate(explanations, 1):
            if self.student_mode:
                lines.append(f"**{i}.** {exp['student']}")
                lines.append(f"   👉 *What to do:* {exp['action']}")
            else:
                lines.append(f"**{i}.** {exp['technical']}")
            lines.append("")

        return "\n".join(lines)

    def get_single_explanation(self, reason: str) -> str:
        """Get student-friendly version of a single reason."""
        mapped = EXPLANATION_MAP.get(reason)
        if mapped:
            return mapped["student"]
        return reason

    def toggle_mode(self) -> bool:
        """Switch between technical and student mode."""
        self.student_mode = not self.student_mode
        return self.student_mode


# ── Quick Test ───────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("EXPLAINER TEST — Technical Mode")
    print("=" * 60)

    reasons = [
        "Internshala never charges registration fee",
        "Real SBI never contacts via personal mobile number",
        "Urgency language detected — a common scam pressure tactic",
        "No suspicious patterns detected — message appears legitimate",
    ]

    explainer = Explainer(student_mode=False)
    print(explainer.format_reasons(reasons))

    print("=" * 60)
    print("EXPLAINER TEST — Student Mode")
    print("=" * 60)

    explainer.toggle_mode()
    print(explainer.format_reasons(reasons))