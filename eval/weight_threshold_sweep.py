"""
eval/weight_threshold_sweep.py

Reads the per-engine score cache written by eval/baseline_ablation.py
(data/engine_scores_cache.json) and grid-searches over fusion weight
combinations and decision thresholds, to find whether the current
35/30/20/15 weights at threshold 50 are actually a good choice — or,
per the finding from the first run, an accident that made the fused
system behave identically to Rules-only.

WHY A GRID SEARCH, NOT A LEARNED (LOGISTIC REGRESSION) FUSION LAYER
──────────────────────────────────────────────────────────────────
With ~86 examples, fitting a 4-feature logistic regression to LEARN
weights risks overfitting to noise and produces a number that's hard
to defend under questioning ("we learned it" sounds impressive but
isn't trustworthy at this sample size). A grid search over a small,
interpretable set of weight combinations is more honest: every
candidate is still a transparent heuristic, just chosen by measuring
instead of guessing. This keeps "we chose these weights because they
measurably work better, here's the table" as the actual defensible
answer — not "we trained a model on 86 examples," which invites the
follow-up question you don't want.

WHAT THIS DOES NOT DO
──────────────────────
It does not automatically pick a winner and rewrite scorer.py. It
reports candidates ranked by a couple of different objectives — you
decide, because "best F1" and "best F1 given zero tolerance for false-
positives on real internships" can point to different answers, and
that's a product decision, not just a math one.

USAGE
─────
    python eval/weight_threshold_sweep.py

Requires data/engine_scores_cache.json to exist — run
eval/baseline_ablation.py first (with a working sentence-transformers
setup) to generate it.
"""

import itertools
import json
import os
import sys

import numpy as np

_here = os.path.dirname(os.path.abspath(__file__))
_root = _here
while _root != os.path.dirname(_root):
    if os.path.isdir(os.path.join(_root, "core")):
        break
    _root = os.path.dirname(_root)
else:
    raise RuntimeError("Could not find repo root.")
os.chdir(_root)

CACHE_PATH = "data/engine_scores_cache.json"
RESULTS_PATH = "data/weight_threshold_sweep_results.json"

# Weight grid: each engine gets a candidate value from this list, we
# keep every combination that sums to ~1.0 (within floating tolerance).
# Step of 0.05 keeps the grid small enough to be fully enumerable and
# to only test genuinely distinguishable weight splits.
WEIGHT_CANDIDATES = [0.0, 0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50]
THRESHOLDS = list(range(20, 81, 5))

# Hard constraint reflecting the project's stated goal: false-accusing
# a real internship/scholarship message is treated as worse than
# missing a scam. Candidates with FPR above this are still reported,
# just flagged separately rather than silently included in "best F1."
MAX_ACCEPTABLE_FPR = 0.05


def compute_metrics(scores, labels, threshold):
    from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score
    preds = (np.array(scores) >= threshold).astype(int)
    labels_arr = np.array(labels)
    tn, fp, fn, tp = confusion_matrix(labels_arr, preds, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {
        "precision": round(float(precision_score(labels_arr, preds, zero_division=0)), 4),
        "recall": round(float(recall_score(labels_arr, preds, zero_division=0)), 4),
        "f1": round(float(f1_score(labels_arr, preds, zero_division=0)), 4),
        "fpr": round(float(fpr), 4),
        "tp": int(tp), "tn": int(tn), "fp": int(fp), "fn": int(fn),
    }


def main():
    if not os.path.exists(CACHE_PATH):
        raise FileNotFoundError(
            f"{CACHE_PATH} not found. Run eval/baseline_ablation.py first "
            "(it needs to complete successfully, including semantic and "
            "FAISS scoring, to write this cache)."
        )

    with open(CACHE_PATH) as f:
        cache = json.load(f)

    labels = cache["labels"]
    scores = {
        "rules": np.array(cache["rules"]),
        "domain": np.array(cache["domain"]),
        "semantic": np.array(cache["semantic"]),
        "faiss": np.array(cache["faiss"]),
    }
    engines = ["rules", "domain", "semantic", "faiss"]
    print(f"Loaded cached scores for {len(labels)} examples.\n")

    # ── Baseline: current production weights, for comparison ──
    current_weights = {"rules": 0.35, "domain": 0.30, "semantic": 0.20, "faiss": 0.15}
    current_combined = sum(scores[e] * w for e, w in current_weights.items())
    current_metrics = compute_metrics(current_combined, labels, threshold=50)
    print("CURRENT PRODUCTION WEIGHTS (35/30/20/15 @ threshold 50):")
    print(f"  F1={current_metrics['f1']:.3f}  P={current_metrics['precision']:.3f}  "
          f"R={current_metrics['recall']:.3f}  FPR={current_metrics['fpr']:.3f}")
    print()

    # ── Grid search ──
    print("Running grid search (this enumerates all weight combos summing "
          "to ~1.0 across the threshold list — may take a few seconds)...")
    all_results = []
    seen = 0
    for w_rules, w_domain, w_semantic in itertools.product(WEIGHT_CANDIDATES, repeat=3):
        w_faiss = round(1.0 - w_rules - w_domain - w_semantic, 4)
        if w_faiss < 0 or w_faiss not in WEIGHT_CANDIDATES:
            continue
        weights = {"rules": w_rules, "domain": w_domain, "semantic": w_semantic, "faiss": w_faiss}
        combined = sum(scores[e] * w for e, w in weights.items())
        seen += 1

        for thresh in THRESHOLDS:
            m = compute_metrics(combined, labels, thresh)
            all_results.append({"weights": weights, "threshold": thresh, **m})

    print(f"Evaluated {len(all_results)} (weight-combo × threshold) configurations "
          f"across {seen} distinct weight splits.\n")

    # ── Rank by different objectives ──
    by_f1 = sorted(all_results, key=lambda r: -r["f1"])
    by_f1_safe = sorted(
        [r for r in all_results if r["fpr"] <= MAX_ACCEPTABLE_FPR],
        key=lambda r: -r["f1"],
    )
    by_recall_zero_fp = sorted(
        [r for r in all_results if r["fp"] == 0],
        key=lambda r: -r["recall"],
    )

    def show(title, rows, n=5):
        print("=" * 78)
        print(title)
        print("=" * 78)
        if not rows:
            print("  (no configurations matched this criterion)")
            return
        for r in rows[:n]:
            w = r["weights"]
            print(
                f"  R={w['rules']:.2f} D={w['domain']:.2f} S={w['semantic']:.2f} "
                f"F={w['faiss']:.2f}  @thresh={r['threshold']:2d}  "
                f"F1={r['f1']:.3f} P={r['precision']:.3f} R={r['recall']:.3f} FPR={r['fpr']:.3f}  "
                f"(FN={r['fn']}, FP={r['fp']})"
            )
        print()

    show("TOP 5 BY RAW F1 (ignores false-positive cost — read the FPR column)", by_f1)
    show(f"TOP 5 BY F1 SUBJECT TO FPR <= {MAX_ACCEPTABLE_FPR:.0%} "
         "(never mislabels more than ~1 in 20 legit messages)", by_f1_safe)
    show("TOP 5 BY RECALL SUBJECT TO ZERO FALSE POSITIVES "
         "(matches current system's FPR=0 property, but maximizes recall within it)",
         by_recall_zero_fp)

    with open(RESULTS_PATH, "w") as f:
        json.dump({
            "current_production": current_metrics,
            "top_by_f1": by_f1[:20],
            "top_by_f1_low_fpr": by_f1_safe[:20],
            "top_by_recall_zero_fp": by_recall_zero_fp[:20],
        }, f, indent=2)
    print(f"Full sweep results (top 20 per category) written to {RESULTS_PATH}")
    print(
        "\nIMPORTANT: pick a candidate based on what matches the project's "
        "actual priorities (recall vs. false-positive tolerance), not "
        "just whichever row has the highest F1 number. With only "
        f"{len(labels)} examples, small differences between nearby rows "
        "(e.g. F1=0.71 vs F1=0.73) are within noise — don't over-index "
        "on the single top row, look at the shape of the top 5-10."
    )


if __name__ == "__main__":
    main()