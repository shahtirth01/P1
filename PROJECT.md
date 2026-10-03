# P1: Shift-Robust Network Intrusion Detector

**Status:** Blocks A, B, C done (baseline run). Next: one-variable fixes | **Updated:** 2026-10-02
**Purpose:** Portfolio project for internship and research applications.
**Rule:** This file is the single source of truth for project state. Unknown = `TBD`. Never assume dataset names, columns, labels or results.

## 1. Goal
Measure how an ML intrusion detector degrades when tested on a different network, test fixes one variable at a time, monitor distribution shift, and ship a small live demo (FastAPI + Streamlit + Docker + tests + CI).

**Research question:** How much does performance drop when a detector trained on one network is evaluated on another, and which single interventions improve robustness?

## 2. Prior work (cite in README)
- D'hooge et al., *Sensors* 2023: generalization across CIC datasets.
- Cantone et al., arXiv:2402.10974: cross-dataset generalization.

Cross-dataset collapse is already known. Our contribution is a reproducible, leakage-safe evaluation, one-variable fixes, a drift monitor and a tested live demo. Do not claim the collapse itself as novel.
Sanity check status: our in-dataset vs cross-dataset gap is consistent in direction with the published pattern. Magnitude comparison with the papers' tables: TBD.

## 3. Data
| Role | Dataset | Link |
|------|---------|------|
| A | NF-CSE-CIC-IDS2018 | https://www.kaggle.com/datasets/dhoogla/nf-cse-cic-ids2018 |
| B | NF-UNSW-NB15 | https://www.kaggle.com/datasets/dhoogla/nfunswnb15 |

Kaggle pages describe both as NetFlow versions (University of Queensland) of the original datasets, hosted by dhoogla.

**Verified (local, Parquet):**
- Files: `data/nf-cse-cic-ids2018/NF-CSE-CIC-IDS2018.parquet` (~60 MB), `data/nfunswnb15/NF-UNSW-NB15.parquet` (~17 MB). Zips ~52 MB / ~15 MB (not needed after unzip).
- Columns, identical in A and B (12): L4_SRC_PORT, L4_DST_PORT, PROTOCOL, L7_PROTO, IN_BYTES, OUT_BYTES, IN_PKTS, OUT_PKTS, TCP_FLAGS, FLOW_DURATION_MILLISECONDS, Label, Attack.
- 10 features: consistent with NF v1; not yet confirmed against the Kaggle page (TBD).
- No timestamp, IP or flow-ID columns exist. No nulls. No negative values (all minimums >= 0).
- Dtypes: see `logs/inspect_A.log`, `logs/inspect_B.log`. L7_PROTO is float32 in both; storage widths of other columns differ between A and B (irrelevant after the float32 cast).
- Rows: A = 5,918,803 (benign 5,534,773 / attack 384,030 = 6.49%); B = 1,484,211 (benign 1,421,093 / attack 63,118 = 4.25%).
- Labels: binary `Label` (0 benign, 1 attack); category column `Attack`.
- Raw attack families A (rows): DoS-Hulk 108,129; SSH-Bruteforce 71,148; Infilteration 59,374; DDoS-LOIC-HTTP 49,751; DoS-GoldenEye 32,582; DoS-Slowloris 17,109; Bot 15,498; DoS-SlowHTTPTest 14,116; FTP-BruteForce 14,116; DDOS-LOIC-UDP 1,667; DDOS-HOIC 230; Brute Force-Web 173; Brute Force-XSS 101; SQL Injection 36.
- Raw attack families B (rows): Exploits 23,418; Fuzzers 17,994; Reconnaissance 10,832; Generic 4,165; DoS 3,723; Shellcode 1,365; Backdoor 737; Analysis 731; Worms 153.
- Exact duplicate rows (all 12 columns): A = 0, B = 0 (consistent with the source being already deduplicated; unverified).
- Feature-only duplicate rows (10 raw features): A = 22,060, B = 2,937. Conflicting-label feature groups: A = 7,649 groups / 15,302 rows (~0.26%); B = 149 groups / 399 rows (~0.03%).
- Row order: A adjacent label flips 0.0726 vs 0.1213 expected if shuffled (partly clustered); B 0.0766 vs 0.0814 (near shuffled). Chronological order NOT verified.
- After dropping ports and deduplicating on the 8 model features + Label: A 5,918,803 -> 1,714,024 rows (attack rate 6.49% -> 6.05%); B 1,484,211 -> 321,191 rows (attack rate 4.25% -> 14.83%). Rows with an opposite-label feature twin: A 30,510, B 3,900. FTP-BruteForce and DDOS-HOIC are absent after dedupe (all their rows are feature-identical to earlier same-label rows).

**Schema differences between A and B (candidate environment fingerprints):**
- L7_PROTO: 237 unique IDs in A, 265 in B; 74 shared, 163 A-only, 191 B-only. Fractional values: A 24.4% of rows, B 0.5%. Unknown (0) is 64.8% of A and 31.7% of B. Treat as a categorical ID (interpretation unverified).
- TCP_FLAGS: values > 31 in 1,743,305 raw A rows (29.5%); none in B (max 31). Whether this separates labels in A: TBD (`logs/flags_check.log`).
- PROTOCOL: A has value 58, absent from B; B ranges up to 255. A IN_BYTES == 0: 1 row; B has none.
- Duration max ~4,294,9xx ms in both (likely a 32-bit ceiling; unverified).

**Still TBD:** NF v1 vs v2 confirmation; whether L7_PROTO ID meanings match across A and B.

## 4. Leakage rules
1. Dedupe **before** splitting.
2. Any step that learns from data (imputation, scaling, encoding, selection, resampling, thresholds) is fitted on training data only.
3. In-dataset evaluation: split by time window/capture segment where possible. A random-row split is reported only as an "optimistic reference".
4. Thresholds (for Recall@1%FPR) are chosen on a source-domain validation set, never on the target dataset.
5. Drop identifiers (IPs, ports, timestamps, flow IDs) and log each removal:

| Feature | Reason | Dataset(s) |
|---------|--------|------------|
| Attack | Label leakage (category of Label); kept as metadata only, never a feature | A, B |
| L4_SRC_PORT | Ephemeral port, identifier-like | A, B |
| L4_DST_PORT | Service identity, dataset shortcut; dropped in baseline, add-back is a later experiment | A, B |

No IP, timestamp or flow-ID columns exist in either dataset.

6. Cross-dataset: primary task is binary benign vs attack. Per-family results only for families present in both datasets. Label mapping: only DoS is shared by name. A: DoS-Hulk, GoldenEye, Slowloris, SlowHTTPTest. B: DoS. DDoS variants excluded from the DoS group. Same name does not mean same behaviour (different generation methods). Other families: in-dataset analysis only.
7. No timestamp exists, so a time-window split is impossible. In-dataset split is a blocked split (see Decisions); results are an optimistic reference, not a time-based evaluation.
8. Early stopping uses the source validation set only. A's validation attack mix is narrow (DoS-Hulk, Infilteration, GoldenEye); logged as a limitation.

## 5. Compute and data handling
- Local: 8 GB RAM, WSL2 capped at 4 GB. Both datasets fit locally; the baseline (6 LightGBM models) ran locally.
- Kaggle: not needed so far. Files over about 1.5 GB would be inspected on Kaggle, not downloaded locally.
- Sampling: train split capped at 1,000,000 rows (stratified by Label, seed 42; only A exceeds the cap, 1,199,024 -> 1,000,000). Val and test are full. Features float32, Label int8, Parquet in `data/processed/`.

## 6. Metrics
Macro-F1, PR-AUC, Recall@1%FPR (threshold = 99th percentile of benign scores on the source validation set). Not plain accuracy.
Also reported: realized FPR on the target at that fixed threshold, and oracle recall at exactly 1% FPR on the target (diagnostic only: uses target labels, never used to choose anything).
Comparability: PR-AUC and Macro-F1 depend on test prevalence (A test 5.89%, B test 15.39%), so they are not comparable across directions. Trivial all-benign Macro-F1 (computed from test prevalence, not measured): A ~0.485, B ~0.458. Oracle recall is not comparable to fixed-threshold recall when realized FPR differs from 1%.
Every reported result states: train set, test set, split, sample sizes, class distribution, features, model, preprocessing, threshold, seed.

## 7. Plan
- **A (done):** environment, repo, Kaggle auth, dataset schema report.
- **B (done):** load, dedupe, label mapping, drop identifiers, leakage-safe split, Parquet samples, verification.
- **C (done):** LightGBM baseline: in-dataset and cross-dataset (A to B, B to A), 3 seeds.
- **Then:** one-variable fixes (each: baseline, changed variable, held constant, hypothesis, result); drift score (PSI or Wasserstein, method documented); FastAPI + Streamlit demo; Docker; tests; CI; README.

## 8. Repository structure
```text
PROJECT.md  README.md  Makefile  requirements.txt  .gitignore
configs/  scripts/  src/{data,features,models,evaluation,drift}/
app/{api,streamlit}/  tests/  notebooks/ (plots only)
results/  data/{raw,processed}/ (gitignored)  logs/ (gitignored)
```
Logic lives in `src/`. Scripts write output to `logs/`.
Existing code: `scripts/inspect_more.py`, `scripts/schema_diff.py`, `scripts/verify_processed.py`, `src/data/prepare.py`, `src/models/baseline.py`. Results: `results/baseline.csv`.

## 9. Decisions
| Date | Decision | Reason |
|------|----------|--------|
| 2026-09-30 | Datasets: NF-CSE-CIC-IDS2018 (A), NF-UNSW-NB15 (B) | Found on Kaggle; NetFlow format |
| 2026-09-30 | Baseline model: LightGBM | Fast on CPU, strong tabular baseline |
| 2026-09-30 | Heavy runs on Kaggle, local samples only | 8 GB RAM constraint |
| 2026-10-01 | Local schema inspection instead of Kaggle | Files are 60 MB / 17 MB |
| 2026-10-01 | Baseline drops Attack, L4_SRC_PORT, L4_DST_PORT | Leakage rule 5 |
| 2026-10-01 | Dedupe on 8 model features + Label after dropping ports | Rule 1: no identical-feature twins across splits |
| 2026-10-01 | Blocked split (contiguous blocks, seed 42, 70/15/15), block size 1000 | Block size 10,000 gave A val = Infilteration only (attack rate 7.9% / 1.6% / 2.2%); 1000 passed the pre-set gate (DoS-Hulk and Infilteration >= 500 rows in val and test); not retuned further. Smaller blocks raise sibling-flow leakage, so A in-dataset is an optimistic reference |
| 2026-10-01 | Per-family cross-dataset = DoS only | Only shared family name |
| 2026-10-01 | Baseline: LightGBM n_estimators 500, early stop 30 on source val, lr 0.1, num_leaves 63, subsample 0.8, colsample 0.8, no class weighting; seeds 0,1,2 (model only, split fixed) | Fixed settings, no tuning, so fixes compare against one baseline |

## 10. Results
Setup: blocked split bs=1000, seed 42; features = 8 (PROTOCOL, L7_PROTO, IN_BYTES, OUT_BYTES, IN_PKTS, OUT_PKTS, TCP_FLAGS, FLOW_DURATION_MILLISECONDS); LightGBM as in Decisions; threshold = 99th percentile of benign source-val scores (seed 0: A-source 0.1209, B-source 0.6709); mean ± std over 3 model seeds.
Sizes: train A 1,000,000 (attack 6.42%), B 224,191 (14.55%); test A 258,000 (5.89%), B 49,000 (15.39%).

| Train | Test | Macro-F1 | PR-AUC | Recall@1%FPR (fixed thr.) | Realized FPR | Oracle recall @1%FPR | Notes |
|-------|------|---------:|-------:|-------------:|-------------:|-------------:|-------|
| A | A | 0.8532 ± 0.0012 | 0.7970 ± 0.0009 | 0.7123 ± 0.0003 | 0.0161 ± 0.0003 | 0.6978 ± 0.0004 | optimistic reference; mostly DoS-Hulk + Infilteration |
| A | B | 0.4867 ± 0.0069 | 0.3136 ± 0.0219 | 0.0304 ± 0.0082 | 0.0054 ± 0.0024 | 0.0495 ± 0.0027 | cross; Macro-F1 ~ trivial 0.458 |
| B | B | 0.9111 ± 0.0032 | 0.9232 ± 0.0015 | 0.7868 ± 0.0093 | 0.0127 ± 0.0001 | 0.7305 ± 0.0031 | near-shuffled order, optimistic reference |
| B | A | 0.5160 ± 0.0024 | 0.0723 ± 0.0075 | 0.0377 ± 0.0010 | 0.0078 ± 0.0024 | 0.0385 ± 0.0017 | cross; PR-AUC near chance (prevalence 0.0589) |

Observations (not claims of cause):
- Cross-dataset recall collapses to 3-4%; oracle recall collapses too, so the ranking does not transfer and threshold recalibration alone would not help.
- Realized target FPR is below 1% in both cross directions: the model scores nearly everything as benign.
- Seed std reflects model randomness only (split fixed).

Post-dedupe family counts (train / val / test, bs=1000):

| A family | train | val | test |
|---|---:|---:|---:|
| Benign | 1,122,036 | 245,435 | 242,809 |
| DoS-Hulk | 55,363 | 6,604 | 9,260 |
| Infilteration | 17,102 | 3,965 | 5,261 |
| DoS-GoldenEye | 2,361 | 996 | 0 |
| DDOS-LOIC-UDP | 1,646 | 0 | 0 |
| Bot | 149 | 0 | 104 |
| Brute Force-Web | 103 | 0 | 0 |
| SSH-Bruteforce | 94 | 0 | 0 |
| Brute Force-XSS | 73 | 0 | 0 |
| DoS-Slowloris | 47 | 0 | 0 |
| SQL Injection | 30 | 0 | 0 |
| DDoS-LOIC-HTTP | 19 | 0 | 566 |
| DoS-SlowHTTPTest | 1 | 0 | 0 |

| B family | train | val | test |
|---|---:|---:|---:|
| Benign | 191,567 | 40,528 | 41,459 |
| Exploits | 15,495 | 3,554 | 3,533 |
| Fuzzers | 9,485 | 2,087 | 2,221 |
| Reconnaissance | 2,232 | 523 | 542 |
| Generic | 2,224 | 535 | 514 |
| DoS | 2,133 | 484 | 502 |
| Shellcode | 489 | 115 | 149 |
| Analysis | 254 | 106 | 22 |
| Backdoor | 225 | 46 | 43 |
| Worms | 87 | 22 | 15 |

Per-family claims only where val/test counts are large. Not for: A rare families, B Analysis (22 test rows) and Worms (15).

## 11. Run log
| Date | Change / experiment | Result | Notes |
|------|---------------------|--------|-------|
| 2026-09-30 | Identified datasets A and B | Links recorded | Block A |
| 2026-10-01 | Kaggle auth, download, schema check (A and B) | Same 12 columns; A 5.92M rows, B 1.48M rows | Block A |
| 2026-10-01 | inspect_more.py on A, B | dtypes, Attack counts, duplicates, order check, ranges (Section 3) | Block A closed |
| 2026-10-01 | schema_diff.py | L7_PROTO 74 shared IDs; TCP_FLAGS > 31 only in A; PROTOCOL 58 only in A | Fingerprint candidates |
| 2026-10-01 | prepare.py, block size 10,000 | A split attack rates 7.9% / 1.6% / 2.2%; val had Infilteration only | Rejected before any model was trained |
| 2026-10-01 | prepare.py, block size 1000 (A and B) | A 6.42% / 4.50% / 5.89%; B 14.55% / 15.57% / 15.39%; gate passed | Accepted |
| 2026-10-01 | verify_processed.py | 0 identical feature+label rows across splits (A and B); ports absent; float32 | OK |
| 2026-10-02 | LightGBM baseline, 4 train/test pairs, 3 seeds | Section 10 | `results/baseline.csv` |

## 12. Open questions
- [x] Same column schema in A and B? Yes (12 identical columns)
- [x] Label mapping and shared attack families? DoS only (Section 4)
- [x] Row order, duplicate rate? Section 3
- [ ] NF v1 or v2? Looks like v1 (10 features); confirm on the Kaggle page
- [ ] Is TCP_FLAGS > 31 a label shortcut in A? (`logs/flags_check.log` not yet reviewed)
- [ ] Which columns leak dataset identity? Candidates: L7_PROTO, TCP_FLAGS, PROTOCOL 58
- [ ] First one-variable fixes (proposed, not yet run): (1) drop L7_PROTO, (2) mask TCP_FLAGS to its lower 5 bits. Not planned: scaling or log transforms (tree models are invariant to monotone transforms) and target-threshold recalibration (oracle recall also collapses)
- [ ] Which drift metric? (PSI per feature proposed)
- [ ] What does the live demo accept as input? (proposed: the 8 features as JSON/CSV, returns score and drift flags)
- [ ] Compare the size of our drop with D'hooge and Cantone

## 13. Current status
**Blocks A, B, C done.**
- Done: environment, Kaggle auth, downloads, schema report, leakage-safe prepare (dedupe, blocked split, Parquet), verification (0 overlap), LightGBM baseline (4 pairs, 3 seeds).
- Next: review `flags_check.log`; run fix 1 and fix 2 against the same baseline; drift score (PSI); FastAPI + Streamlit demo; Docker; tests; CI; README.
- Not started: fixes, drift monitor, demo, Docker, tests, CI, README.
- Git: last push TBD (verify on GitHub).
- Environment: Python 3.12.3, git 2.43.0, lightgbm 4.7.0, numpy 2.5.3, pandas 3.0.6, pyarrow 25.0.1, scikit-learn 1.9.1. Pinning in requirements.txt: TBD (verify the file exists and matches).

## 14. Change history
| Date | Summary |
|------|---------|
| 2026-09-30 | Initial spec; trimmed; datasets, leakage and threshold rules added |
| 2026-10-01 | Block A closed: schema verified, leakage table filled, no-timestamp constraint, DoS-only label mapping |
| 2026-10-01 | Block B: dedupe on model features, blocked split (bs=1000), verification |
| 2026-10-02 | Block C: LightGBM baseline results (Section 10); Section 6 metrics extended; Section 12 updated |