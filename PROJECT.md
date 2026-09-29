# P1: Shift-Robust Network Intrusion Detector

**Status:** Block A (environment, repo, dataset schema) | **Updated:** 2026-09-30
**Purpose:** Portfolio project for internship and research applications.
**Rule:** This file is the single source of truth for project state. Unknown = `TBD`. Never assume dataset names, columns, labels or results.

## 1. Goal
Measure how an ML intrusion detector degrades when tested on a different network, test fixes one variable at a time, monitor distribution shift, and ship a small live demo (FastAPI + Streamlit + Docker + tests + CI).

**Research question:** How much does performance drop when a detector trained on one network is evaluated on another, and which single interventions improve robustness?

## 2. Prior work (cite in README)
- D'hooge et al., *Sensors* 2023: generalization across CIC datasets.
- Cantone et al., arXiv:2402.10974: cross-dataset generalization.

Cross-dataset collapse is already known. Our contribution is a reproducible, leakage-safe evaluation, one-variable fixes, a drift monitor and a tested live demo. Do not claim the collapse itself as novel. First sanity check: our in-dataset vs cross-dataset gap should resemble the published pattern.

## 3. Data
| Role | Dataset | Link |
|------|---------|------|
| A | NF-CSE-CIC-IDS2018 | https://www.kaggle.com/datasets/dhoogla/nf-cse-cic-ids2018 |
| B | NF-UNSW-NB15 | https://www.kaggle.com/datasets/dhoogla/nfunswnb15 |

Kaggle pages describe both as NetFlow versions (University of Queensland) of the original datasets, hosted by dhoogla.

**TBD in Block A (verify programmatically, do not assume):**
- Dataset version (NF v1 vs v2), file names, file format, sizes
- Row counts, column names and dtypes, missing values
- Whether A and B share the same columns (expected by design, unverified)
- Label columns and values (binary label vs attack-category column)
- Duplicate rate, identifier columns
- Which attack families exist in both datasets (likely few; DoS is a candidate)

## 4. Leakage rules
1. Dedupe **before** splitting.
2. Any step that learns from data (imputation, scaling, encoding, selection, resampling, thresholds) is fitted on training data only.
3. In-dataset evaluation: split by time window/capture segment where possible. A random-row split is reported only as an "optimistic reference".
4. Thresholds (for Recall@1%FPR) are chosen on a source-domain validation set, never on the target dataset.
5. Drop identifiers (IPs, ports, timestamps, flow IDs) and log each removal:

| Feature | Reason | Dataset(s) |
|---------|--------|------------|
| TBD | TBD | TBD |

6. Cross-dataset: primary task is binary benign vs attack. Per-family results only for families present in both datasets; document the label mapping. Note that "attack" means different things in each dataset.

## 5. Compute and data handling
- Local: 8 GB RAM, WSL2 capped at 4 GB. Use for code, tests, schema inspection, small runs (0.5-1M row stratified samples, float32, Parquet).
- Kaggle: raw-data processing, full training, expensive comparisons. Files over about 1.5 GB are inspected on Kaggle, not downloaded locally.
- Document sampling method and seed so results are reproducible.

## 6. Metrics
Macro-F1, PR-AUC, Recall@1%FPR. Not plain accuracy.
Every reported result states: train set, test set, split, sample sizes, class distribution, features, model, preprocessing, threshold, seed.

## 7. Plan
- **A:** environment, repo, Kaggle auth, dataset schema report.
- **B:** load, dedupe, label mapping, drop identifiers, leakage-safe split, Parquet samples.
- **C:** LightGBM baseline: in-dataset and cross-dataset (A to B, B to A), multiple seeds.
- **Then:** one-variable fixes (each: baseline, changed variable, held constant, hypothesis, result); drift score (PSI or Wasserstein, method documented); FastAPI + Streamlit demo; Docker; tests; CI; README.

## 8. Repository structure
```text
PROJECT.md  README.md  Makefile  requirements.txt  .gitignore
configs/  scripts/  src/{data,features,models,evaluation,drift}/
app/{api,streamlit}/  tests/  notebooks/ (plots only)
results/  data/{raw,processed}/ (gitignored)  logs/ (gitignored)
```
Logic lives in `src/`. Scripts write output to `logs/last_run.log`.

## 9. Decisions
| Date | Decision | Reason |
|------|----------|--------|
| 2026-09-30 | Datasets: NF-CSE-CIC-IDS2018 (A), NF-UNSW-NB15 (B) | Found on Kaggle; NetFlow format |
| 2026-09-30 | Baseline model: LightGBM | Fast on CPU, strong tabular baseline |
| 2026-09-30 | Heavy runs on Kaggle, local samples only | 8 GB RAM constraint |

## 10. Results
| Train | Test | Macro-F1 | PR-AUC | Recall@1%FPR | Notes |
|-------|------|---------:|-------:|-------------:|-------|
| A | A | | | | |
| A | B | | | | |
| B | B | | | | |
| B | A | | | | |

## 11. Run log
| Date | Change / experiment | Result | Notes |
|------|---------------------|--------|-------|
| 2026-09-30 | Identified datasets A and B | Links recorded | Block A |

## 12. Open questions
- [ ] Same column schema in A and B? Which columns are comparable?
- [ ] NF v1 or v2? Exact files and sizes?
- [ ] Label mapping and shared attack families?
- [ ] Which columns leak dataset/environment identity?
- [ ] Which drift metric? Which one-variable fixes first?
- [ ] What does the live demo accept as input?

## 13. Current status
**Block A in progress.**
- Done: WSL2, Ubuntu, git, GitHub SSH, venv workflow, Kaggle CLI installed, VS Code + WSL, datasets identified.
- Next: Kaggle authentication, file listing, schema check on Kaggle, schema report.
- Not started: preprocessing, splits, baseline, cross-dataset evaluation, fixes, drift monitor, demo, Docker, tests, CI, README.
- Environment: Python TBD (record version), git 2.43.0. Package versions pinned in requirements.txt (TBD).

## 14. Change history
| Date | Summary |
|------|---------|
| 2026-09-30 | Initial spec; trimmed; datasets, leakage and threshold rules added |
