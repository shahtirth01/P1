import sys
import pandas as pd

df = pd.read_parquet(sys.argv[1])

print("shape:", df.shape)
print(df.dtypes.to_string())

nulls = df.isna().sum()
print("nulls:", nulls[nulls > 0].to_dict() or "none")

print("Attack counts:\n", df["Attack"].value_counts().to_string())

feat = df.drop(columns=["Label", "Attack"])

print(
    "dup rows (feat+label):",
    df.duplicated().sum(),
    f"({df.duplicated().mean():.2%})"
)

print("dup rows (feat only):", feat.duplicated().sum())

# Row-order check
y = df["Label"].to_numpy()
p = df["Label"].mean()

print(
    "adjacent label flips:",
    round((y[1:] != y[:-1]).mean(), 4),
    "| shuffled expectation:",
    round(2 * p * (1 - p), 4)
)

print(
    "L7_PROTO nunique:",
    df["L7_PROTO"].nunique(),
    "| PROTOCOL values:",
    sorted(df["PROTOCOL"].unique())[:15]
)

print(
    feat.describe().T[["min", "max"]].to_string()
)