# LattigoStats Notebook Guide

This guide explains how to use the Jupyter Notebooks in this repository efficiently and how to interpret the Homomorphic Encryption (HE) results.

## Key Components

1. **`lattigo_stats.py`**: A Python wrapper that streamlines calls to the Go binaries (`ddia`, `do_encrypt`, `da_run`). It handles JSON generation and execution management.
2. **`credit_card_analysis_v2.ipynb`**: The recommended notebook for analyzing the credit card dataset.

## Common Issues & Troubleshooting

### 1. Nonsensical Decrypted Values (e.g., `1e160`)
If you see extremely large numbers in your decrypted results, it almost always means a **division by zero** occurred during the homomorphic computation.

**Why?**
The `Mean`, `Variance`, and `Stdev` operations involve computing the inverse of the count (`1/n`). In HE, this is done using Newton iteration. If the filter matches zero rows (i.e., `n=0`), the Newton iteration fails and results in exploding noise values.

**Fix:**
- Check your job conditions. For example, if you filter for `Class == 1` and your dataset sample doesn't contain any fraud cases, the count will be 0.
- Use a larger data sample or adjust your filter.

### 2. Privacy Inspection Violations
If `ls.inspect()` returns `approved: false`, the result violated a privacy rule (usually `min_count`).

**Why?**
Differential Privacy or simple k-anonymity rules often require a minimum number of samples to release a statistic. If your filtered subset is too small, the DDIA will block the result to prevent potential data leakage.

## Seamless Integration
The `LattigoStats` wrapper provides:
- `ls.load_decrypted_result(path)`: Automatically filters out extreme noise values.
- `ls.plot_results(values)`: Quick visualization for analyst sanity checks.
- Helper methods for schema and job generation to reduce JSON errors.
