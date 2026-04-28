def calculate_final_score(rule_score: int, domain_score: int, ml_score: int = 0) -> int:
    weighted = (rule_score * 0.50) + (domain_score * 0.30) + (ml_score * 0.20)
    return min(int(weighted), 100)
 
 
def decide(score: int) -> tuple[str, str, str]:
    if score <= 30:
        return "Safe",       "✅", "This looks okay. Still be cautious with unknown senders."
    elif score <= 70:
        return "Suspicious", "⚠️", "Do NOT click any links. Verify with the sender directly."
    else:
        return "Scam",       "🚫", "STOP. Do not click, share OTP, or make any payment."
 
 
def get_score_color(label: str) -> str:
    return {"Safe": "#22c55e", "Suspicious": "#f59e0b", "Scam": "#ef4444"}.get(label, "#6b7280")