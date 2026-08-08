"""
eval/baseline_ablation.py

Runs baseline (single-engine) and ablation (leave-one-engine-out)
evaluation against data/scam_dataset.csv, reusing the same honest,
cross-validated methodology as train/train_model.py — never scoring
any engine on data it was fit on.

WHY THIS EXISTS
────────────────
"Our system gets 90% F1" proves nothing about WHY the 4-engine
architecture matters. This script answers: does each engine actually
contribute something the others don't? If Rules-only already gets 85%
F1, the other 3 engines need to be earning their complexity somewhere
else (e.g. lower false-positive rate on hard negatives), not raw
accuracy — and this script will show that directly instead of you
having to guess.

METHODOLOGY NOTES (read before trusting the numbers)
──────────────────────────────────────────────────────
1. Rules engine: pure regex/pattern matching, no fitting on data at
   all → scored directly on every example, zero leakage risk.

2. Domain engine: scored with LIVE THREAT-INTEL DISABLED. Two reasons:
   (a) reproducibility — a judge re-running this shouldn't need your
       VirusTotal/Safe Browsing API keys just to reproduce the number,
   (b) most of this dataset's examples don't contain a real
       (non-fictional) domain that VT/GSB would have an opinion on
       anyway. So "Domain" here means the local pattern heuristics
       (typosquatting, IP-based URLs, suspicious TLD, path keywords,
       homoglyphs) only. This is a real, disclosed scoping decision —
       say so explicitly if a judge asks "did you include threat intel
       in this eval."

3. Semantic engine: proper out-of-fold cross-validation — for each
   fold, fit ONLY on the training folds, predict on the held-out fold.
   No example is ever scored by a model that saw its label during
   fitting.

4. History/FAISS engine: THIS ONE NEEDS A DISCLOSURE, NOT JUST A
   METHODOLOGY NOTE. In production, core/history_engine.py's FAISS
   index starts EMPTY and only grows from real user-submitted reports
   (it reads from a `reports` SQLite table, not from
   data/scam_dataset.csv). For THIS eval only, we seed a temporary
   in-memory FAISS index from the training data itself, using
   leave-one-out (each example is scored against an index built from
   every OTHER example, never itself) to prevent trivial 100%-
   self-similarity leakage. This means the ablation number for FAISS
   describes "how good is history-matching once the index has been
   seeded with ~85 examples," NOT "how good is FAISS on day one of a
   real deployment," which is closer to a cold start with near-zero
   signal. State this distinction explicitly if it comes up — it's a
   legitimate, known limitation of the architecture, not something to
   hide.

5. Multiple seeds: with ~85 examples, a single CV split can flip
   several examples between folds and swing F1 by a lot. This script
   runs N different random seeds for the fold assignment and reports
   mean ± std, not a single point estimate. If std is large relative
   to the mean, that's a genuine finding to report as-is — "this
   number is noisy given dataset size" is a stronger judge answer than
   a fragile precise-looking one.

USAGE
─────
    python eval/baseline_ablation.py

Writes data/baseline_ablation_results.json and prints a summary table.
"""

import json
import os
import sys
import warnings

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

_here = os.path.dirname(os.path.abspath(__file__))
_root = _here
while _root != os.path.dirname(_root):
    if os.path.isdir(os.path.join(_root, "core")):
        break
    _root = os.path.dirname(_root)
else:
    raise RuntimeError("Could not find repo root (a folder containing 'core/').")
sys.path.insert(0, _root)
os.chdir(_root)

DATA_PATH = "data/scam_dataset.csv"
RESULTS_PATH = "data/baseline_ablation_results.json"
N_SEEDS = 5  # only used for semantic (the only engine with real fold randomness)
THRESHOLD = 50.0  # score >= this => predicted scam


# ─────────────────────────── Engine scorers ───────────────────────────

def score_rules(texts):
    """Deterministic, no fitting → safe to score directly, no leakage."""
    from core.rules_engine import RulesEngine
    engine = RulesEngine()
    return np.array([engine.analyze(t)["score"] for t in texts])


def score_domain_local(texts):
    """
    Domain engine with live threat-intel forced off (see module
    docstring point 2). Monkeypatches the module-level key constants
    to empty strings for the duration of this call only.
    """
    import core.domain_checker as dc_module
    original_vt = dc_module.VIRUSTOTAL_KEY
    original_gsb = dc_module.GOOGLE_SAFE_BROWSING_KEY
    dc_module.VIRUSTOTAL_KEY = ""
    dc_module.GOOGLE_SAFE_BROWSING_KEY = ""
    try:
        checker = dc_module.DomainChecker()
        scores = []
        for t in texts:
            result = checker.analyze(t)
            assert result["ti_status"] == "not_configured", (
                "Expected threat-intel to be force-disabled for this eval "
                "— if this fires, the monkeypatch above isn't working and "
                "results may silently include live network calls."
            )
            scores.append(result["score"])
        return np.array(scores)
    finally:
        dc_module.VIRUSTOTAL_KEY = original_vt
        dc_module.GOOGLE_SAFE_BROWSING_KEY = original_gsb


def score_semantic_oof(texts, labels, seed):
    """
    Proper out-of-fold CV: fit only on training folds, predict on the
    held-out fold, for every example. Returns scam-probability * 100
    for every example, using only information available at eval time
    for that fold (never sees its own label during fitting).
    """
    from sentence_transformers import SentenceTransformer
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import StratifiedKFold

    embedder = SentenceTransformer("all-MiniLM-L6-v2")
    embeddings = embedder.encode(texts, show_progress_bar=False, convert_to_numpy=True)
    labels_arr = np.array(labels)

    min_class = int(min((labels_arr == 0).sum(), (labels_arr == 1).sum()))
    n_splits = min(5, min_class)
    if n_splits < 2:
        raise ValueError("Not enough examples per class for CV.")

    cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=seed)
    oof_scores = np.zeros(len(texts))

    for train_idx, test_idx in cv.split(embeddings, labels_arr):
        clf = LogisticRegression(class_weight="balanced", max_iter=1000, random_state=seed)
        clf.fit(embeddings[train_idx], labels_arr[train_idx])
        proba = clf.predict_proba(embeddings[test_idx])[:, 1]
        oof_scores[test_idx] = proba * 100

    return oof_scores


def score_history_loo(texts, labels, seed):
    """
    Leave-one-out FAISS similarity scoring. For each example i, build
    an index from every OTHER example, then query with example i.
    Score = similarity to the best-matching SCAM neighbor above 0.60,
    else 0. This deliberately mirrors history_engine.py's own
    min_similarity threshold for consistency, but is a standalone
    implementation — see module docstring point 4 for why this can't
    reuse core/history_engine.py directly (that class is coupled to a
    persistent SQLite reports table, not a batch eval harness).
    """
    import faiss
    from sentence_transformers import SentenceTransformer

    embedder = SentenceTransformer("all-MiniLM-L6-v2")
    embeddings = embedder.encode(texts, show_progress_bar=False, convert_to_numpy=True).astype("float32")
    faiss.normalize_L2(embeddings)
    labels_arr = np.array(labels)

    n = len(texts)
    scores = np.zeros(n)
    MIN_SIMILARITY = 0.60

    for i in range(n):
        mask = np.ones(n, dtype=bool)
        mask[i] = False
        index = faiss.IndexFlatIP(embeddings.shape[1])
        index.add(embeddings[mask])

        query = embeddings[i:i + 1]
        k = min(5, mask.sum())
        sims, idxs = index.search(query, k)

        other_labels = labels_arr[mask]
        best_scam_sim = 0.0
        for sim, idx in zip(sims[0], idxs[0]):
            if idx == -1 or sim < MIN_SIMILARITY:
                continue
            if other_labels[idx] == 1:
                best_scam_sim = max(best_scam_sim, float(sim))
        scores[i] = best_scam_sim * 100

    return scores


# ─────────────────────────── Metrics ───────────────────────────

def compute_metrics(scores, labels, threshold=THRESHOLD):
    from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score
    preds = (np.array(scores) >= threshold).astype(int)
    labels_arr = np.array(labels)
    tn, fp, fn, tp = confusion_matrix(labels_arr, preds, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {
        "precision": round(float(precision_score(labels_arr, preds, zero_division=0)), 4),
        "recall": round(float(recall_score(labels_arr, preds, zero_division=0)), 4),
        "f1": round(float(f1_score(labels_arr, preds, zero_division=0)), 4),
        "false_positive_rate": round(float(fpr), 4),
        "tp": int(tp), "tn": int(tn), "fp": int(fp), "fn": int(fn),
    }


def combine(score_dict, engine_names, weights=None):
    """Weighted average across the named engines' score arrays."""
    if weights is None:
        weights = {name: 1.0 / len(engine_names) for name in engine_names}
    total = np.zeros(len(next(iter(score_dict.values()))))
    for name in engine_names:
        total += score_dict[name] * weights[name]
    return total


# ─────────────────────────── Main ───────────────────────────

def main():
    df = pd.read_csv(DATA_PATH)
    texts = df["text"].astype(str).tolist()
    labels = df["label"].astype(int).tolist()
    print(f"Loaded {len(texts)} examples ({sum(labels)} scam / {len(labels) - sum(labels)} safe)\n")

    print("Scoring Rules engine (deterministic, no leakage possible)...")
    rules_scores = score_rules(texts)

    print("Scoring Domain engine (local heuristics only, live threat-intel disabled)...")
    domain_scores = score_domain_local(texts)

    semantic_available = True
    semantic_runs = []
    for seed in range(N_SEEDS):
        try:
            print(f"Scoring Semantic engine, seed {seed} (out-of-fold CV)...")
            semantic_runs.append(score_semantic_oof(texts, labels, seed))
        except Exception as e:
            print(f"  SKIPPED — could not run semantic scoring: {e}")
            semantic_available = False
            break

    # NOTE: history_faiss_only was previously run across N_SEEDS with a
    # reported ±std — that was misleading. score_history_loo has no
    # random component (cosine similarity search is deterministic given
    # fixed embeddings), so every "seed" produced identical output. This
    # was an eval-script bug, not a real stability finding. Fixed: run
    # once, and say plainly there's no spread to report.
    faiss_available = True
    faiss_scores = None
    try:
        print("Scoring History/FAISS engine (leave-one-out, deterministic — no seed variance to report)...")
        faiss_scores = score_history_loo(texts, labels, seed=42)
    except Exception as e:
        print(f"  SKIPPED — could not run FAISS scoring: {e}")
        faiss_available = False

    results = {
        "n_examples": len(texts),
        "n_scam": sum(labels),
        "n_safe": len(labels) - sum(labels),
        "threshold": THRESHOLD,
        "single_engine": {},
        "combinations": {},
        "notes": [],
    }

    results["single_engine"]["rules_only"] = compute_metrics(rules_scores, labels)
    results["single_engine"]["domain_only_local"] = compute_metrics(domain_scores, labels)

    semantic_mean_scores = None
    if semantic_available:
        semantic_mean_scores = np.mean(semantic_runs, axis=0)
        semantic_metrics = [compute_metrics(s, labels) for s in semantic_runs]
        results["single_engine"]["semantic_only"] = {
            "mean": {k: round(float(np.mean([m[k] for m in semantic_metrics])), 4)
                     for k in ["precision", "recall", "f1", "false_positive_rate"]},
            "std": {k: round(float(np.std([m[k] for m in semantic_metrics])), 4)
                    for k in ["precision", "recall", "f1", "false_positive_rate"]},
            "per_seed": semantic_metrics,
        }
    else:
        results["notes"].append(
            "semantic_only could not be computed in this environment "
            "(sentence-transformers model download failed/blocked)."
        )

    if faiss_available:
        results["single_engine"]["history_faiss_only"] = compute_metrics(faiss_scores, labels)
        results["notes"].append(
            "history_faiss_only was evaluated with the FAISS index seeded "
            "from this dataset via leave-one-out — this does NOT reflect "
            "day-one production behavior, where the index starts empty. "
            "It is also a deterministic score (no random component), so "
            "no seed spread is reported for it, unlike semantic_only."
        )
    else:
        results["notes"].append(
            "history_faiss_only could not be computed in this environment "
            "(sentence-transformers/faiss model download failed/blocked)."
        )

    if semantic_available:
        results["combinations"]["rules_plus_domain"] = compute_metrics(
            combine({"rules": rules_scores, "domain": domain_scores}, ["rules", "domain"]),
            labels,
        )
        results["combinations"]["rules_plus_semantic"] = compute_metrics(
            combine({"rules": rules_scores, "semantic": semantic_mean_scores}, ["rules", "semantic"]),
            labels,
        )

        if faiss_available:
            full_scores = combine(
                {"rules": rules_scores, "domain": domain_scores,
                 "semantic": semantic_mean_scores, "faiss": faiss_scores},
                ["rules", "domain", "semantic", "faiss"],
                weights={"rules": 0.35, "domain": 0.30, "semantic": 0.20, "faiss": 0.15},
            )
            results["combinations"]["full_cfs_weighted_35_30_20_15"] = compute_metrics(full_scores, labels)

            ablation_configs = {
                "full_minus_rules":    {"domain": 0.30, "semantic": 0.20, "faiss": 0.15},
                "full_minus_domain":   {"rules": 0.35, "semantic": 0.20, "faiss": 0.15},
                "full_minus_semantic": {"rules": 0.35, "domain": 0.30, "faiss": 0.15},
                "full_minus_faiss":    {"rules": 0.35, "domain": 0.30, "semantic": 0.20},
            }
            score_pool = {"rules": rules_scores, "domain": domain_scores,
                           "semantic": semantic_mean_scores, "faiss": faiss_scores}
            for name, weights in ablation_configs.items():
                total_w = sum(weights.values())
                norm_weights = {k: v / total_w for k, v in weights.items()}
                ablated_scores = combine(score_pool, list(weights.keys()), norm_weights)
                results["combinations"][name] = compute_metrics(ablated_scores, labels)

    os.makedirs(os.path.dirname(RESULTS_PATH), exist_ok=True)
    with open(RESULTS_PATH, "w") as f:
        json.dump(results, f, indent=2)

    # ── Cache raw per-example score arrays for eval/weight_threshold_sweep.py ──
    # so the sweep doesn't need to re-download/re-embed everything.
    if semantic_available and faiss_available:
        cache = {
            "labels": labels,
            "rules": rules_scores.tolist(),
            "domain": domain_scores.tolist(),
            "semantic": semantic_mean_scores.tolist(),
            "faiss": faiss_scores.tolist(),
        }
        cache_path = "data/engine_scores_cache.json"
        with open(cache_path, "w") as f:
            json.dump(cache, f)
        print(f"\nCached raw per-engine scores to {cache_path} for weight/threshold sweeping.")
    else:
        print(
            "\nNOT caching scores — semantic and/or FAISS scoring didn't "
            "complete, so the cache would be incomplete. Fix the network/"
            "model issue and re-run before using the sweep script."
        )

    # ── Print summary table ──
    print("\n" + "=" * 70)
    print("SINGLE-ENGINE BASELINES")
    print("=" * 70)
    for name, m in results["single_engine"].items():
        if "mean" in m:
            mm = m["mean"]
            print(f"{name:25s} F1={mm['f1']:.3f}±{m['std']['f1']:.3f}  "
                  f"P={mm['precision']:.3f}  R={mm['recall']:.3f}  FPR={mm['false_positive_rate']:.3f}")
        else:
            print(f"{name:25s} F1={m['f1']:.3f}  P={m['precision']:.3f}  "
                  f"R={m['recall']:.3f}  FPR={m['false_positive_rate']:.3f}")

    if results["combinations"]:
        print("\n" + "=" * 70)
        print("COMBINATIONS / ABLATIONS")
        print("=" * 70)
        for name, m in results["combinations"].items():
            print(f"{name:30s} F1={m['f1']:.3f}  P={m['precision']:.3f}  "
                  f"R={m['recall']:.3f}  FPR={m['false_positive_rate']:.3f}")

    if results["notes"]:
        print("\n" + "=" * 70)
        print("NOTES")
        print("=" * 70)
        for note in results["notes"]:
            print(f"- {note}")

    print(f"\nFull results written to {RESULTS_PATH}")


if __name__ == "__main__":
    main()