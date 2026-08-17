"""
eval/diagnose_false_positive.py

Runs specific messages through the real pipeline and prints EVERY
engine's individual score plus whether conflict-escalation fired --
so we can see exactly which engine (or which mechanism) is causing a
false positive, instead of guessing.

USAGE
    python eval/diagnose_false_positive.py
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.pipeline import run_full_pipeline

CASES = [
    "Your internship is confirmed, no money required at any stage.",
    "This is a free internship, no fee, no charges, completely free of cost.",
    "No payment needed, this internship is 100% free for all students.",
    "Your Amazon order has shipped, track it at amazon.com",
    "Sign in to your Google account at google.com to continue",
    "Visit amazon.com for great deals today",
]


def main():
    for text in CASES:
        print("=" * 78)
        print(f"MESSAGE: {text}")
        print("=" * 78)
        result = run_full_pipeline(text)

        label = result.get("label", "?")
        score = result.get("final_score", result.get("score", "?"))
        confidence = result.get("confidence", "?")
        breakdown = result.get("breakdown", {})

        print(f"VERDICT: {label}   Final Score: {score}   Confidence: {confidence}")
        print()
        for engine_name in ("rules", "domain", "ml", "history"):
            eng = breakdown.get(engine_name, {})
            print(f"  {engine_name:10s} raw_score={eng.get('score', '?')!s:>8} "
                  f"weight={eng.get('weight', '?')}")

        # Compute the max pairwise gap between raw engine scores --
        # this is what conflict-escalation checks against a 45-point
        # threshold, independent of the final weighted score.
        raw_scores = {
            k: breakdown.get(k, {}).get("score", 0)
            for k in ("rules", "domain", "ml", "history")
        }
        vals = [v for v in raw_scores.values() if isinstance(v, (int, float))]
        if len(vals) >= 2:
            max_gap = max(vals) - min(vals)
            print(f"\n  Max pairwise engine gap: {max_gap:.0f} "
                  f"(conflict-escalation fires above 45)")
            if max_gap > 45:
                print("  >>> THIS IS LIKELY WHY IT'S SUSPICIOUS, NOT THE FINAL SCORE <<<")

        reasons = result.get("reasons", [])
        if reasons:
            print("\n  Reasons given:")
            for r in reasons[:5]:
                print(f"    - {r}")
        print()


if __name__ == "__main__":
    main()


    