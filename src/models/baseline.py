from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, f1_score, roc_curve

from src.data.prepare import FEATURES

PROC, FPR = Path("data/processed"), 0.01
SEEDS, METRICS = (0, 1, 2), ["macro_f1", "pr_auc", "recall", "realized_fpr", "oracle_recall_1fpr"]


def load(name, split):
    d = pd.read_parquet(PROC / f"{name}_{split}.parquet")
    return d[FEATURES], d["Label"].to_numpy()


def fit(Xtr, ytr, Xva, yva, seed):
    m = lgb.LGBMClassifier(n_estimators=500, learning_rate=0.1, num_leaves=63,
                           subsample=0.8, subsample_freq=1, colsample_bytree=0.8,
                           random_state=seed, n_jobs=4, verbose=-1)
    m.fit(Xtr, ytr, eval_set=[(Xva, yva)], callbacks=[lgb.early_stopping(30, verbose=False)])
    return m


def evaluate(m, thr, X, y):
    s = m.predict_proba(X)[:, 1]
    pred = s > thr
    f, t, _ = roc_curve(y, s)
    return {"n_test": len(y), "test_attack_rate": y.mean(), "threshold": thr,
            "macro_f1": f1_score(y, pred, average="macro"),
            "pr_auc": average_precision_score(y, s),
            "recall": pred[y == 1].mean(), "realized_fpr": pred[y == 0].mean(),
            "oracle_recall_1fpr": t[f <= FPR].max()}   # diagnostic only: uses target labels


def main():
    data = {n: {k: load(n, k) for k in ("train", "val", "test")} for n in ("A", "B")}
    rows = []
    for src in ("A", "B"):
        (Xtr, ytr), (Xva, yva) = data[src]["train"], data[src]["val"]
        for seed in SEEDS:
            m = fit(Xtr, ytr, Xva, yva, seed)
            thr = np.quantile(m.predict_proba(Xva)[:, 1][yva == 0], 1 - FPR)  # source val only
            for tgt in ("A", "B"):
                Xte, yte = data[tgt]["test"]
                rows.append({"train": src, "test": tgt, "seed": seed, "n_train": len(ytr),
                             "train_attack_rate": ytr.mean(), "best_iter": m.best_iteration_,
                             **evaluate(m, thr, Xte, yte)})
            print(f"done: train={src} seed={seed}", flush=True)
    df = pd.DataFrame(rows)
    Path("results").mkdir(exist_ok=True)
    df.to_csv("results/baseline.csv", index=False)
    print(df.groupby(["train", "test"])[METRICS].agg(["mean", "std"]).round(4).to_string())
    print(df.groupby(["train", "test"])[["n_test", "test_attack_rate", "threshold"]].first().round(4).to_string())


if __name__ == "__main__":
    main()
