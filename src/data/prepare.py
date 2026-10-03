import argparse
from pathlib import Path

import numpy as np
import pandas as pd

FEATURES = ["PROTOCOL", "L7_PROTO", "IN_BYTES", "OUT_BYTES", "IN_PKTS",
            "OUT_PKTS", "TCP_FLAGS", "FLOW_DURATION_MILLISECONDS"]
PORTS = ["L4_SRC_PORT", "L4_DST_PORT"]  # dropped per leakage rule 5


def inspect_duplicates(df: pd.DataFrame) -> None:
    """Report exact duplicates and feature-identical rows with label conflicts."""
    features = [c for c in df.columns if c not in ("Label", "Attack")]
    exact_duplicates = df.duplicated().sum()
    feature_duplicates = df.duplicated(subset=features).sum()
    nun = df.groupby(features, dropna=False)["Label"].transform("nunique")
    conflicting_rows = nun.gt(1).sum()

    print("Duplicate report")
    print("----------------")
    print(f"Exact duplicate rows: {exact_duplicates}")
    print(f"Feature-only duplicate rows: {feature_duplicates}")
    print(f"Rows in conflicting groups: {conflicting_rows}")


def clean(df: pd.DataFrame) -> pd.DataFrame:
    """Drop ports, dedupe on model-visible features + Label, cast dtypes."""
    n0, rate0 = len(df), df["Label"].mean()
    df = df.drop(columns=PORTS)
    df = df.drop_duplicates(subset=FEATURES + ["Label"]).reset_index(drop=True)  # keeps row order
    twins = df.duplicated(subset=FEATURES, keep=False).sum()
    print(f"clean: {n0:,} -> {len(df):,} rows | attack rate {rate0:.4f} -> "
          f"{df['Label'].mean():.4f} | rows with opposite-label twin: {twins:,}")
    df[FEATURES] = df[FEATURES].astype("float32")
    df["Label"] = df["Label"].astype("int8")
    return df


def split_dataset(df, seed, block_size=10_000):
    """Blocked 70/15/15 split: whole contiguous blocks go to one split."""
    block = np.arange(len(df)) // block_size
    ids = np.unique(block)
    np.random.default_rng(seed).shuffle(ids)
    n_tr, n_va = int(0.70 * len(ids)), int(0.15 * len(ids))
    tr = np.isin(block, ids[:n_tr])
    va = np.isin(block, ids[n_tr:n_tr + n_va])
    return df[tr], df[va], df[~tr & ~va]


def family_coverage(train, val, test) -> None:
    """Rows per Attack family in each split; flag families missing from train."""
    cov = pd.concat({"train": train["Attack"].value_counts(),
                     "val": val["Attack"].value_counts(),
                     "test": test["Attack"].value_counts()}, axis=1).fillna(0).astype(int)
    print(cov.to_string())
    missing = cov.index[(cov["train"] == 0) & (cov.index != "Benign")]
    if len(missing):
        print("WARNING: families absent from train:", list(missing))


def print_split_info(name: str, df: pd.DataFrame) -> None:
    counts = df["Label"].value_counts().sort_index()
    print(f"\n{name}: rows={len(df):,} | " +
          " | ".join(f"label {k}: {v:,} ({v / len(df):.4f})" for k, v in counts.items()))


def save_split(df, name, split, max_rows, seed) -> None:
    """Optionally subsample (stratified by Label), then write Parquet."""
    if max_rows and len(df) > max_rows:
        df = df.groupby("Label", group_keys=False).sample(frac=max_rows / len(df), random_state=seed)
    out = Path("data/processed") / f"{name}_{split}.parquet"
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out, index=False)
    print(f"saved {out} | n={len(df):,} | attack_rate={df['Label'].mean():.4f}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-train", type=int, default=1_000_000)
    parser.add_argument("--skip-report", action="store_true")
    parser.add_argument("--block-size", type=int, default=10_000)

    args = parser.parse_args()

    path = Path(args.path)
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")

    print(f"Loading dataset: {path}")
    raw = pd.read_parquet(path)
    print(f"Dataset {args.name} | Shape: {raw.shape}")

    if not args.skip_report:
        inspect_duplicates(raw)
    df = clean(raw)
    del raw
    train, val, test = split_dataset(df, seed=args.seed, block_size=args.block_size)
    family_coverage(train, val, test)

    for split, part in (("train", train), ("val", val), ("test", test)):
        print_split_info(split, part)
        save_split(part, args.name, split,
                   args.max_train if split == "train" else None, args.seed)


if __name__ == "__main__":
    main()