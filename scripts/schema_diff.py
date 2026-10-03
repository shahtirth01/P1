import pandas as pd

P = {"A": "data/nf-cse-cic-ids2018/NF-CSE-CIC-IDS2018.parquet",
     "B": "data/nfunswnb15/NF-UNSW-NB15.parquet"}
cols = ["L7_PROTO", "PROTOCOL", "IN_BYTES", "IN_PKTS", "TCP_FLAGS"]
l7, pr = {}, {}
for n, p in P.items():
    d = pd.read_parquet(p, columns=cols)
    l7[n], pr[n] = set(d.L7_PROTO.unique()), set(d.PROTOCOL.unique())
    print(n, "L7 dtype:", d.L7_PROTO.dtype, "| non-integer share: %.4f" % (d.L7_PROTO % 1 != 0).mean())
    print(n, "IN_BYTES==0:", int((d.IN_BYTES == 0).sum()), "| TCP_FLAGS>31:", int((d.TCP_FLAGS > 31).sum()))
    print(n, "top-5 L7 share:", d.L7_PROTO.value_counts(normalize=True).head(5).round(3).to_dict())
print("L7 in both:", len(l7["A"] & l7["B"]), "| A only:", len(l7["A"] - l7["B"]), "| B only:", len(l7["B"] - l7["A"]))
print("PROTOCOL in both:", sorted(pr["A"] & pr["B"]), "| A only:", sorted(pr["A"] - pr["B"]))
