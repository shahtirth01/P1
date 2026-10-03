import pandas as pd
from src.data.prepare import FEATURES

for n in ("A", "B"):
    s = {k: pd.read_parquet(f"data/processed/{n}_{k}.parquet") for k in ("train", "val", "test")}
    for k, d in s.items():
        assert not any(c in d.columns for c in ("L4_SRC_PORT", "L4_DST_PORT")), "ports present"
        assert all(str(d[c].dtype) == "float32" for c in FEATURES), "feature dtype != float32"
        assert d["Label"].dtype.name == "int8"
        print(f"{n} {k}: n={len(d):,} attack_rate={d.Label.mean():.4f} nulls={int(d[FEATURES].isna().sum().sum())}")
    h = {k: set(pd.util.hash_pandas_object(d[FEATURES + ["Label"]], index=False)) for k, d in s.items()}
    print(f"{n} identical feature+label rows across splits: "
          f"train&val={len(h['train'] & h['val'])} train&test={len(h['train'] & h['test'])} val&test={len(h['val'] & h['test'])}")
print("verify OK")
