"""
eval/nested_weight_validation.py

The weight/threshold sweep found a strong-looking candidate (R=0.25
D=0.20 S=0.45 F=0.10 @thresh=35, F1=0.818 at FPR=0.000) by searching
11,583 configurations against the same 86 examples used to score them.
That's a real overfitting risk — with that many candidates tested on
one small dataset, some configuration will look great by chance alone.

This script checks whether the improvement is real using NESTED
cross-validation:
  1. Split the 86 examples into K outer folds.
  2. For each outer fold: run the FULL weight/threshold search using
     only the OTHER folds (the search never sees the held-out fold).
  3. Evaluate whatever weights that search picked on the held-out fold.
  4. Average performance across all K held-out folds.

This gives an honest estimate of how the "pick the best weights via
search" PROCEDURE performs on data it didn't choose the weights from —
which is the real question, not "what's the best score achievable on
the whole dataset."

If the nested (held-out) F1 is close to the naive sweep's reported
F1 (0.818), the improvement is likely real. If it's much lower, the
naive number was mostly overfitting and the current weights (or a
smaller adjustment) may be more honest to report.

USAGE
─────
    python eval/nested_weight_validation.py

Requires data/engine_scores_cache.json (written by baseline_ablation.py).
"""

import itertools
import json
import os

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
WEIGHT_CANDIDATES = [0.0, 0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50]
THRESHOLDS = list(range(20, 81, 5))
N_OUTER_FOLDS = 5


def compute_metrics(scores, labels, threshold):
    from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score
    preds = (np.array(scores) >= threshold).astype(int)
    labels_arr = np.array(labels)
    tn, fp, fn, tp = confusion_matrix(labels_arr, preds, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {
        "precision": float(precision_score(labels_arr, preds, zero_division=0)),
        "recall": float(recall_score(labels_arr, preds, zero_division=0)),
        "f1": float(f1_score(labels_arr, preds, zero_division=0)),
        "fpr": float(fpr),
        "fp": int(fp), "fn": int(fn),
    }


def search_best_zero_fp_weights(scores, labels, indices):
    """Same search as weight_threshold_sweep.py's 'zero FP' objective,
    but restricted to the given index subset (the training folds)."""
    best = None
    for w_rules, w_domain, w_semantic in itertools.product(WEIGHT_CANDIDATES, repeat=3):
        w_faiss = round(1.0 - w_rules - w_domain - w_semantic, 4)
        if w_faiss < 0 or w_faiss not in WEIGHT_CANDIDATES:
            continue
        weights = {"rules": w_rules, "domain": w_domain, "semantic": w_semantic, "faiss": w_faiss}
        combined = sum(scores[e][indices] * w for e, w in weights.items())

        for thresh in THRESHOLDS:
            m = compute_metrics(combined, [labels[i] for i in indices], thresh)
            if m["fp"] > 0:
                continue  # zero-FP constraint
            if best is None or m["f1"] > best["f1"]:
                best = {"weights": weights, "threshold": thresh, **m}
    return best


def main():
    if not os.path.exists(CACHE_PATH):
        raise FileNotFoundError(f"{CACHE_PATH} not found — run eval/baseline_ablation.py first.")

    with open(CACHE_PATH) as f:
        cache = json.load(f)

    labels = cache["labels"]
    scores = {k: np.array(cache[k]) for k in ["rules", "domain", "semantic", "faiss"]}
    n = len(labels)
    print(f"Loaded {n} examples. Running {N_OUTER_FOLDS}-fold nested validation...\n")
    print("(This re-runs the full grid search once per fold — may take a"
          " little longer than the plain sweep.)\n")

    from sklearn.model_selection import StratifiedKFold
    outer_cv = StratifiedKFold(n_splits=N_OUTER_FOLDS, shuffle=True, random_state=42)

    fold_results = []
    all_indices = np.arange(n)
    labels_arr = np.array(labels)

    for fold_i, (train_idx, test_idx) in enumerate(outer_cv.split(all_indices, labels_arr)):
        print(f"Fold {fold_i + 1}/{N_OUTER_FOLDS}: searching on {len(train_idx)} examples, "
              f"validating on {len(test_idx)} held-out examples...")

        best = search_best_zero_fp_weights(scores, labels, train_idx)
        if best is None:
            print("  No zero-FP configuration found on this fold's training data — skipping.")
            continue

        # Evaluate the weights this fold's search picked, on the HELD-OUT fold
        combined_test = sum(scores[e][test_idx] * w for e, w in best["weights"].items())
        held_out_metrics = compute_metrics(combined_test, [labels[i] for i in test_idx], best["threshold"])

        print(f"  Picked: R={best['weights']['rules']:.2f} D={best['weights']['domain']:.2f} "
              f"S={best['weights']['semantic']:.2f} F={best['weights']['faiss']:.2f} "
              f"@thresh={best['threshold']}")
        print(f"  In-sample (training folds) F1={best['f1']:.3f}  →  "
              f"held-out F1={held_out_metrics['f1']:.3f}  "
              f"(P={held_out_metrics['precision']:.3f} R={held_out_metrics['recall']:.3f} "
              f"FPR={held_out_metrics['fpr']:.3f}, FP={held_out_metrics['fp']})\n")

        fold_results.append({
            "fold": fold_i,
            "picked_weights": best["weights"],
            "picked_threshold": best["threshold"],
            "in_sample_f1": best["f1"],
            "held_out": held_out_metrics,
        })

    if not fold_results:
        print("No folds produced a valid zero-FP configuration. The zero-FP "
              "constraint may be too strict for this dataset size — consider "
              "relaxing to the FPR<=5% objective instead.")
        return

    in_sample_f1s = [r["in_sample_f1"] for r in fold_results]
    held_out_f1s = [r["held_out"]["f1"] for r in fold_results]
    held_out_fps = [r["held_out"]["fp"] for r in fold_results]

    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Mean in-sample F1 (what the search sees while picking):  {np.mean(in_sample_f1s):.3f}")
    print(f"Mean HELD-OUT F1 (honest generalization estimate):        {np.mean(held_out_f1s):.3f} "
          f"± {np.std(held_out_f1s):.3f}")
    print(f"Total held-out false positives across all folds: {sum(held_out_fps)} "
          f"(out of {n} total examples spread across folds)")
    print()
    gap = np.mean(in_sample_f1s) - np.mean(held_out_f1s)
    if gap > 0.10:
        print(f"⚠️  Gap of {gap:.3f} between in-sample and held-out F1 suggests real "
              "overfitting in the search procedure. The naive sweep's headline "
              "number (0.818) is likely optimistic. Report the held-out mean "
              "instead, or pick a simpler/rounder weight set from the middle "
              "of the sweep's top-10 cluster rather than the literal top row.")
    else:
        print(f"Gap of {gap:.3f} is modest — the improvement direction (more "
              "weight to Semantic, lower threshold) appears to genuinely "
              "generalize, not just overfit this specific 86-example set. "
              "Still recommend picking a round/central weight set from the "
              "sweep's top cluster rather than the exact literal winner.")


if __name__ == "__main__":
    main()