import pandas as pd


def inspect_schema(file_path):
    df = pd.read_parquet(file_path)

    print("Columns:")
    for column in df.columns:
        print(column)

    print(f"\nNumber of columns: {len(df.columns)}")


def inspect_labels(file_path):
    df = pd.read_parquet(file_path)

    print("\nLabel counts:")
    print(df["Label"].value_counts())


inspect_schema("data/nfunswnb15/NF-UNSW-NB15.parquet")
inspect_labels("data/nfunswnb15/NF-UNSW-NB15.parquet")