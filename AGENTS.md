```markdown
# PRD: Lattigo-STAT — HEaaN-STAT-equivalent Statistical Toolkit on Lattigo (CKKS)
**Date:** 2025-12-05  
**Owner:** (you)  
**Status:** Draft PRD (implementation-ready)  
**Goal:** Reproduce the *same* end-to-end capabilities described in “HEaaN-STAT” (TDSC 2024) using **Lattigo (Go) CKKS**, including the system workflow + supported statistical operations + utility primitives.

---

## 1) Background & Problem Statement
Organizations want to **fuse** large-scale tabular datasets from different domains (millions of rows, tens of columns) and run **simple but critical statistics** (mean/variance/correlation, contingency tables, bin-average/variance, k-percentile) while:
- data owners do **not** learn others’ data,
- data owners do **not** participate after sending encrypted data,
- an oversight party checks outputs for privacy leakage before releasing results,
- the system can scale to nation-scale datasets.

The paper’s reference deployment uses CKKS with bootstrapping, additional encodings for categorical counting, and several HE utility functions (inverse, equality-check/table lookup, k-percentile).

This PRD specifies a **Lattigo-based reimplementation** with equivalent functionality and comparable semantics.

---

## 2) Goals (What we must ship)
### G1 — Same system model / roles
Implement the multi-party workflow with distinct roles:
- **DDIA** (trusted key holder / decryptor / privacy inspector)
- **Data Owners (DOᵢ)** (encrypt + export)
- **DMA** (data merge authority; merges by protected identifiers)
- **DA** (data analyst; runs HE computations but cannot decrypt)
- **U** (user requesting statistical queries)

### G2 — Same supported operations
Implement the toolkit operations matching HEaaN-STAT:
- Numerical: **mean, variance, stdev, Pearson correlation**
- Categorical/ordinal: **Bc (bin-count), Ba (bin-average), Bv (bin-variance)**
- Large-scale contingency: **LBc (Large-Bin-Count)** using **PBMV + BBMV** + post-processing model
- Utility primitives: **INVNTHSQRT**, **DISCRETEEQUALZERO** (≈ equality to 0), **table lookup**
- Ordinal: **k-percentile** using BMVs + comparison

### G3 — Large-scale table representation
Match the paper’s core table/block/slot model:
- Table columns stored as **blocks**, each block = **one CKKS ciphertext**
- **Validity vectors** per variable/column
- **BMVs** for categorical variables

### G4 — Practical engineering deliverable
A Go module/repo with:
- reproducible parameter sets,
- deterministic serialization formats,
- job specs for requests,
- correctness tests vs plaintext,
- performance instrumentation.

---

## 3) Non-Goals (Explicitly out of scope)
- Differential privacy, hypothesis tests, regression/ML training, secure joins beyond identifier matching.
- Interactive protocols requiring DO participation after upload (must remain non-interactive after export).
- GPU acceleration as a hard requirement (paper uses GPU heavily for LBc; we will design an interface that can later add GPU, but MVP is CPU + concurrency).

---

## 4) Users & Key Use-Cases
### Personas
- **DO engineer:** exports encrypted columns with metadata, validity vectors, BMVs/PBMV/BBMV.
- **DA engineer:** runs approved HE tasks and sends encrypted results to DDIA.
- **DDIA officer:** decrypts, runs privacy inspection, releases.
- **Analyst/User (U):** requests “mean(varA where condition)”, “contingency table for (A,B,C)”, “90th percentile of ordinal X”.

### Example user stories
1) “Compute mean and variance of numeric column `income` ignoring invalid cells.”
2) “Compute Pearson corr between `spend` and `late_payments`.”
3) “Compute contingency table counts for (region, gender, risk_bucket).”
4) “Compute Ba: avg(target=`income`) for rows where (gender=female, region=TR-34).”
5) “Compute k-percentile (k=90) for ordinal `risk_score_bucket`.”
6) “Compute LBc for millions of cases and millions of rows; release only post-processed table.”

---

## 5) System Architecture (Matches paper workflow)
### 5.1 Actors and trust boundaries
- **DDIA holds CKKS secret key (sk)** and is the only decryptor.
- **DA** has pk + evaluation keys (relin/rot/bootstrap keys) but no sk.
- **DMA** merges encrypted rows by **protected identifiers** (e.g., HMAC/CMAC token) without decrypting.

### 5.2 End-to-end flow (steps to implement)
1. **DDIA: Setup**
   - chooses CKKS params, generates keys: pk, sk, relin, rot keys, bootstrap keys (if needed).
2. **DDIA → DOᵢ/DMA/DA: Distribute**
   - delivers params + pk + evaluation keys; delivers **sMAC** for identifier protection.
3. **DOᵢ: Precompute & encrypt**
   - compute validity vectors
   - compute BMVs (and possibly PBMV/BBMV if LBc mode)
   - encrypt data columns + auxiliary ciphertexts
   - protect identifiers: token = HMAC(sMAC, raw_id)
4. **DOᵢ → DMA: Upload**
5. **DMA: Merge**
   - join rows cross-sources by token (exact match)
   - output fused encrypted table to DA
6. **U → DA: Request**
   - query includes which operation, target columns, filters (categorical conditions), k for percentile, etc.
7. **DA: Execute with Lattigo-STAT**
   - runs HE ops, outputs encrypted result
8. **DA → DDIA: Send result ciphertext(s)**
9. **DDIA: Decrypt + privacy inspection**
10. **DDIA → U: Release approved result**

---

## 6) Data Model & Encoding
### 6.1 Column types
- **Numerical:** real values (paper uses normalized range like [−1,1] or [0,1]); in CKKS this is “encoded float with scale”.
- **Categorical:** integer in `[1..S_f]`.
- **Ordinal:** categorical with ordering; also integer in `[1..S_f]`.

### 6.2 Block/slot layout
- Choose CKKS ring degree `N`; **Slots = N/2**.
- A **block** is one ciphertext containing up to `Slots` rows’ values for one column.
- For `R` rows, number of blocks: `NB = ceil(R / Slots)`.

### 6.3 Validity vectors
For each column `f`:
- `v_f[b]` is a ciphertext block with slots ∈ {0,1}
- invalid cell → 0, valid cell → 1

### 6.4 BMVs (Bin Mask Vectors)
For each categorical variable `f` with `S_f` categories:
- For each value `j ∈ [1..S_f]` and each block `b`, create ciphertext `bmv[f][j][b]`
- Slot is 1 if row has category j, else 0

> Storage cost is large: O(S_f * NB). This is expected (paper does this), and we’ll implement streaming + compressed serialization.

---

## 7) Cryptographic Requirements (Lattigo mapping)
### 7.1 Required CKKS operations
Must be available via Lattigo:
- Encode/Encrypt/Decrypt
- Add/Sub
- Mul (ct×ct and ct×pt)
- Relinearization
- Rescale management
- Rotate (Galois keys)
- Bootstrapping (for INVNTHSQRT, DISCRETEEQUALZERO, comparison, some percentile paths)

### 7.2 Parameter sets
Deliver at least two “profiles”:
- **Profile A (no-bootstrap):** supports mean/variance/Bc/Ba/Bv within limited depth (for smaller tasks / or if DDIA assists recrypt—NOT preferred).
- **Profile B (bootstrapped):** supports all functions including INVNTHSQRT / DISCRETEEQUALZERO / k-percentile with bounded error.

Each profile must specify:
- `LogN`, modulus chain, scaling strategy, bootstrapping parameters (if enabled),
- rotation steps needed: `{1,2,4,...,Slots/2}` for reductions + application-specific rotations.

### 7.3 Security model support
- **Model-I:** DDIA receives ciphertext of final result and decrypts → trivial under IND-CPA.
- **Model-II (LBc):** DA outputs ciphertext(s) that DDIA decrypts and then (DDIA) or U post-processes. We must implement **DDIA-side post-processing** to avoid the paper’s leakage caveat when `R > Slots * 2^Δ`.

---

## 8) Functional Requirements (FR)
### FR-1 Key management service (DDIA)
- Generate CKKS parameters (from approved templates).
- Generate keys: `sk, pk, rlk, galks(rot), btpks`.
- Export public bundle for DA/DO/DMA.
- Never export sk.

### FR-2 Identifier protection (DMA join)
- DDIA generates `sMAC`.
- DO computes token = HMAC(sMAC, id).
- DMA joins by token equality.
- DMA never sees raw identifiers.

### FR-3 Encrypted table storage format
Define a stable binary format:
- metadata.json: schema, column types, category counts, Slots, NB, scaling, parameter hash
- blocks/*.bin: ciphertext blobs (Lattigo marshaled)
- bmvs/*.bin: per categorical value per block blobs (optionally chunked)
- validity/*.bin
- pbmv/bbmv/*.bin (for LBc mode)
Must support streaming read/write and partial loading per column/block.

### FR-4 Query/job specification (U→DA)
Provide `JobSpec` (JSON/YAML) with:
- operation: `mean|var|stdev|corr|bc|ba|bv|lbc|percentile|lookup`
- inputs: columns, categorical conditions `(f=value)` list
- target numeric column for Ba/Bv
- k for percentile
- output: “full table” vs “selected cases”, and expected shape
- privacy policy tag (forwarded to DDIA)

### FR-5 Numerical ops (mean/var/stdev/corr)
Implement paper-equivalent:
- `NUM-OP(x, v, mean|var)` using:
  - masked sums: Σ(x_i * v_i)
  - count sums: Σ(v_i)
  - slot reduction via rotations `{1,2,4,...}`
  - inverse via `INVNTHSQRT(count, n=1)`
- `CORR(x,y,v)` via:
  - means m1,m2, variances v1,v2
  - inv stdev via `INVNTHSQRT(var, n=2)`
  - masked covariance sum and normalize

### FR-6 BIN-OP for categorical functions (Bc/Ba/Bv)
Given F=(f0..fm-1), values W=(w0..wm-1):
- Build mask per block: `mask = v_target` (Ba/Bv) or `1` (Bc)
- Multiply by each `bmv[fj][wj][block]`
- For Bc: sum masks across blocks, then slot-reduce to total count
- For Ba/Bv: call NUM-OP with `mask` as validity vector

### FR-7 INVNTHSQRT (Newton iteration + bootstrapping)
Implement Algorithm 1 behavior:
- Input: ciphertext x, plaintext init y0, integer n, iteration k
- Iteration: `y <- (y*( (n+1) - x*y^n )) / n`
- Bootstrapping schedule:
  - bootstrap x at start
  - bootstrap y when level < required depth
  - optional bootstrap at end of each iteration (configurable)
- Provide tuned defaults:
  - n=1 with ~25 iterations
  - n=2 with ~21 iterations
Expose knobs: iterations, bootstrap frequency, target relative error.

### FR-8 DISCRETEEQUALZERO(x; Sf, K) + table lookup
Implement the paper’s approximation pipeline:
- Normalize `x <- x / 2^d`, where d=ceil(log2 Sf)
- Compute Chebyshev coefficients offline for:
  - sinc(θ) and cos(πθ) on θ∈[-1,1]
- Evaluate polynomials via power-cache to minimize depth
- Build sinc(θ) via repeated double-angle cosine recursion
- Apply filtering map `p(s)=4s^3 - 3s^4`
Output ciphertext approximating indicator: 1 if x==0 (integer), else ~0.

**Table lookup**:
- To select rows where categorical==j:
  - compute `eq = DISCRETEEQUALZERO(cat - j)`
  - multiply `eq * target_numeric` (or multiply into masks)

### FR-9 Approx comparison / sign (for percentile and COMP)
Provide an `ApproxSign` / `COMP` module:
- Inputs bounded to paper’s intended range (often [0,1] or scaled)
- Output slotwise sign or “greater-than” bit with tolerance
Implementation options (choose one as baseline, keep interface stable):
1) Polynomial approximation of sign with bootstrapping
2) Port an HE comparison construction consistent with CKKS constraints
Deliver:
- `APPROXSIGN(ct)` returns approx in {−1,0,+1} (or {0,1})
- `COMP(x1,x2)` returns approx {0,0.5,1} per slot

### FR-10 k-Percentile (ordinal)
Implement Algorithm 7 semantics:
- For ordinal variable with BMVs for values 1..S_f:
  - compute frequency per value by summing BMV blocks + slot-reduce
  - build encrypted cumulative histogram in a single ciphertext where slot i holds cumulative count for value i
- Compute `invR = INVNTHSQRT(sum(valid), n=1)`
- Compare cumulative/R with k/100 using `APPROXSIGN`
- Apply mapping `f(x) = -0.5(x-0.5)^2 + 1.125` (paper’s “flip to 0/1” trick)
- Slot-reduce and derive l (percentile index)

### FR-11 LBc (Large-Bin-Count) with PBMV/BBMV
Implement PBMV+BBMV encoding + multiplication plan:
- PBMV for one categorical variable f0:
  - encode one-hot category into spaced bit-fields with parameters (Δ, δ)
- BBMV for other variables:
  - encode masks as {0, 2^Λ} to separate “signal” from CKKS noise
- Optionally compress multiple variables into “virtual variables” f′ to satisfy modulus bit constraints (paper’s m→m′ trick)

**Execution model (Model-II):**
- DA computes batched products producing partial packed results.
- DA sends ciphertext batch to DDIA.
- DDIA decrypts and performs post-processing and aggregation into the final contingency table.

**Security requirement (matches paper’s caveat):**
- If R is bigger than `Slots * 2^Δ`, DDIA must perform aggregation and only release final table counts (not raw decrypted chunks).

### FR-12 Privacy inspection hooks (DDIA)
- DDIA receives decrypted numeric outputs / tables and runs policy checks (pluggable):
  - k-anonymity thresholds for bins
  - “small group” suppression
  - max-precision caps / rounding rules for numeric outputs
  - query auditing metadata (what was requested)

---

## 9) Non-Functional Requirements (NFR)
### NFR-1 Scale
- Must handle **millions of rows** by streaming blocks from disk.
- Must support tens of columns; BMVs may be huge → implement:
  - lazy loading per variable/value range,
  - mmap or chunked reads,
  - optional “generate BMVs on demand” path (DISCRETEEQUALZERO).

### NFR-2 Accuracy
- For numerical ops: relative error dominated by bootstrap error; target “paper-like” stability once data is large.
- For DISCRETEEQUALZERO: must produce a sharp spike at equality (validate false positive/negative rates).
- For percentile: stable result for large R.

### NFR-3 Performance
- Concurrent execution across blocks (Go worker pools).
- Avoid keeping all ciphertexts in RAM.
- Provide profiling counters:
  - time spent in mul/rot/bootstrap
  - ciphertext IO volume
  - per-job depth/level tracking

### NFR-4 Reproducibility
- Parameter bundles hashed and recorded.
- Deterministic coefficient generation versioned.
- Golden plaintext fixtures for correctness.

---

## 10) Proposed Repository Structure (Go)
```

lattigo-stat/
cmd/
ddia/           # keygen + decrypt + privacy-inspect + postprocess
do_encrypt/     # data owner encryption pipeline
dma_merge/      # merge authority join tool
da_run/         # analyst job runner
pkg/
params/         # parameter profiles + validation
schema/         # table schema, metadata, typing
storage/        # ciphertext serialization, chunking
he/             # thin wrapper around lattigo evaluator/encoder/bootstrapper
ops/
numeric/      # mean/var/stdev/corr + invnthsqt
categorical/  # bmv + binop + lbc encodings
approx/       # discreteequalzero + approxsign/comp
ordinal/      # percentile
jobs/           # JobSpec parsing + planning
privacy/        # DDIA policy checks
test/
fixtures/       # small plaintext datasets + expected outputs

```

---

## 11) Acceptance Criteria (Must-pass)
### AC-1 Correctness (small scale)
On a toy dataset (e.g., R<=1024):
- mean/var/corr match plaintext within configured epsilon.
- Bc exact after DDIA decryption.
- Ba/Bv within epsilon.
- DISCRETEEQUALZERO distinguishes equality vs non-equality for integer-coded categories.
- percentile returns correct bucket index.

### AC-2 End-to-end workflow
- DO encrypts + uploads
- DMA merges
- DA executes JobSpec
- DDIA decrypts + passes privacy inspection
- U receives result

### AC-3 LBc safety behavior
For R > Slots * 2^Δ:
- DDIA aggregates decrypted chunks and releases only final table.
- Raw per-chunk outputs are never exposed to U.

---

## 12) Engineering Risks & Mitigations
1) **Bootstrapping cost / availability in chosen Lattigo version**
   - Mitigation: lock to a known bootstrapping-enabled parameter profile; keep interfaces independent of exact Lattigo package layout.
2) **BMV storage blow-up**
   - Mitigation: chunked serialization; “generate BMV on demand” mode using DISCRETEEQUALZERO.
3) **Depth/scale management**
   - Mitigation: centralized evaluator wrapper that enforces scale policy + logs level consumption; unit tests per op.
4) **Approximation brittleness (DISCRETEEQUALZERO / APPROXSIGN)**
   - Mitigation: coefficient generator + sweep tests; track false positives/negatives; tune K,d,filter stages.
5) **LBc without GPU may be slow**
   - Mitigation: concurrency + batching; design a “backend interface” so later a GPU evaluator can drop in.

---

## 13) Milestones (Suggested)
- **M0:** Params + IO + key distribution scaffolding
- **M1:** Numeric ops + INVNTHSQRT
- **M2:** BMV + BIN-OP (Bc/Ba/Bv)
- **M3:** DISCRETEEQUALZERO + table lookup
- **M4:** APPROXSIGN/COMP + k-percentile
- **M5:** LBc (PBMV/BBMV) + DDIA post-processing + policy enforcement
- **M6:** Performance pass (streaming, concurrency, profiling)

---

## 14) Appendix: Concrete “Operation-to-Module” Mapping
- Algorithm 1 (INVNTHSQRT) → `pkg/ops/numeric/inv.go`
- Algorithm 2 (NUM-OP) → `pkg/ops/numeric/meanvar.go`
- Algorithm 3 (CORR) → `pkg/ops/numeric/corr.go`
- Algorithm 4 (BIN-OP) → `pkg/ops/categorical/binop.go`
- Algorithm 5 (GENBIGMASK / BBMV) → `pkg/ops/categorical/lbc_bbmv.go`
- Algorithm 6 (DISCRETEEQUALZERO) → `pkg/ops/approx/discrete_equal_zero.go`
- Algorithm 7 (PERCENTILE) → `pkg/ops/ordinal/percentile.go`

---
```

If you want, I can also output a **matching `JobSpec` schema** (JSON) and the **exact function signatures** (Go interfaces) for `Evaluator`, `Bootstrapper`, and each op module so implementation starts immediately without redesign.
```markdown
# PRD: Lattigo-STAT — HEaaN-STAT-equivalent Statistical Toolkit on Lattigo (CKKS)
**Date:** 2025-12-05  
**Owner:** (you)  
**Status:** Draft PRD (implementation-ready)  
**Goal:** Reproduce the *same* end-to-end capabilities described in “HEaaN-STAT” (TDSC 2024) using **Lattigo (Go) CKKS**, including the system workflow + supported statistical operations + utility primitives.

---

## 1) Background & Problem Statement
Organizations want to **fuse** large-scale tabular datasets from different domains (millions of rows, tens of columns) and run **simple but critical statistics** (mean/variance/correlation, contingency tables, bin-average/variance, k-percentile) while:
- data owners do **not** learn others’ data,
- data owners do **not** participate after sending encrypted data,
- an oversight party checks outputs for privacy leakage before releasing results,
- the system can scale to nation-scale datasets.

The paper’s reference deployment uses CKKS with bootstrapping, additional encodings for categorical counting, and several HE utility functions (inverse, equality-check/table lookup, k-percentile).

This PRD specifies a **Lattigo-based reimplementation** with equivalent functionality and comparable semantics.

---

## 2) Goals (What we must ship)
### G1 — Same system model / roles
Implement the multi-party workflow with distinct roles:
- **DDIA** (trusted key holder / decryptor / privacy inspector)
- **Data Owners (DOᵢ)** (encrypt + export)
- **DMA** (data merge authority; merges by protected identifiers)
- **DA** (data analyst; runs HE computations but cannot decrypt)
- **U** (user requesting statistical queries)

### G2 — Same supported operations
Implement the toolkit operations matching HEaaN-STAT:
- Numerical: **mean, variance, stdev, Pearson correlation**
- Categorical/ordinal: **Bc (bin-count), Ba (bin-average), Bv (bin-variance)**
- Large-scale contingency: **LBc (Large-Bin-Count)** using **PBMV + BBMV** + post-processing model
- Utility primitives: **INVNTHSQRT**, **DISCRETEEQUALZERO** (≈ equality to 0), **table lookup**
- Ordinal: **k-percentile** using BMVs + comparison

### G3 — Large-scale table representation
Match the paper’s core table/block/slot model:
- Table columns stored as **blocks**, each block = **one CKKS ciphertext**
- **Validity vectors** per variable/column
- **BMVs** for categorical variables

### G4 — Practical engineering deliverable
A Go module/repo with:
- reproducible parameter sets,
- deterministic serialization formats,
- job specs for requests,
- correctness tests vs plaintext,
- performance instrumentation.

---

## 3) Non-Goals (Explicitly out of scope)
- Differential privacy, hypothesis tests, regression/ML training, secure joins beyond identifier matching.
- Interactive protocols requiring DO participation after upload (must remain non-interactive after export).
- GPU acceleration as a hard requirement (paper uses GPU heavily for LBc; we will design an interface that can later add GPU, but MVP is CPU + concurrency).

---

## 4) Users & Key Use-Cases
### Personas
- **DO engineer:** exports encrypted columns with metadata, validity vectors, BMVs/PBMV/BBMV.
- **DA engineer:** runs approved HE tasks and sends encrypted results to DDIA.
- **DDIA officer:** decrypts, runs privacy inspection, releases.
- **Analyst/User (U):** requests “mean(varA where condition)”, “contingency table for (A,B,C)”, “90th percentile of ordinal X”.

### Example user stories
1) “Compute mean and variance of numeric column `income` ignoring invalid cells.”
2) “Compute Pearson corr between `spend` and `late_payments`.”
3) “Compute contingency table counts for (region, gender, risk_bucket).”
4) “Compute Ba: avg(target=`income`) for rows where (gender=female, region=TR-34).”
5) “Compute k-percentile (k=90) for ordinal `risk_score_bucket`.”
6) “Compute LBc for millions of cases and millions of rows; release only post-processed table.”

---

## 5) System Architecture (Matches paper workflow)
### 5.1 Actors and trust boundaries
- **DDIA holds CKKS secret key (sk)** and is the only decryptor.
- **DA** has pk + evaluation keys (relin/rot/bootstrap keys) but no sk.
- **DMA** merges encrypted rows by **protected identifiers** (e.g., HMAC/CMAC token) without decrypting.

### 5.2 End-to-end flow (steps to implement)
1. **DDIA: Setup**
   - chooses CKKS params, generates keys: pk, sk, relin, rot keys, bootstrap keys (if needed).
2. **DDIA → DOᵢ/DMA/DA: Distribute**
   - delivers params + pk + evaluation keys; delivers **sMAC** for identifier protection.
3. **DOᵢ: Precompute & encrypt**
   - compute validity vectors
   - compute BMVs (and possibly PBMV/BBMV if LBc mode)
   - encrypt data columns + auxiliary ciphertexts
   - protect identifiers: token = HMAC(sMAC, raw_id)
4. **DOᵢ → DMA: Upload**
5. **DMA: Merge**
   - join rows cross-sources by token (exact match)
   - output fused encrypted table to DA
6. **U → DA: Request**
   - query includes which operation, target columns, filters (categorical conditions), k for percentile, etc.
7. **DA: Execute with Lattigo-STAT**
   - runs HE ops, outputs encrypted result
8. **DA → DDIA: Send result ciphertext(s)**
9. **DDIA: Decrypt + privacy inspection**
10. **DDIA → U: Release approved result**

---

## 6) Data Model & Encoding
### 6.1 Column types
- **Numerical:** real values (paper uses normalized range like [−1,1] or [0,1]); in CKKS this is “encoded float with scale”.
- **Categorical:** integer in `[1..S_f]`.
- **Ordinal:** categorical with ordering; also integer in `[1..S_f]`.

### 6.2 Block/slot layout
- Choose CKKS ring degree `N`; **Slots = N/2**.
- A **block** is one ciphertext containing up to `Slots` rows’ values for one column.
- For `R` rows, number of blocks: `NB = ceil(R / Slots)`.

### 6.3 Validity vectors
For each column `f`:
- `v_f[b]` is a ciphertext block with slots ∈ {0,1}
- invalid cell → 0, valid cell → 1

### 6.4 BMVs (Bin Mask Vectors)
For each categorical variable `f` with `S_f` categories:
- For each value `j ∈ [1..S_f]` and each block `b`, create ciphertext `bmv[f][j][b]`
- Slot is 1 if row has category j, else 0

> Storage cost is large: O(S_f * NB). This is expected (paper does this), and we’ll implement streaming + compressed serialization.

---

## 7) Cryptographic Requirements (Lattigo mapping)
### 7.1 Required CKKS operations
Must be available via Lattigo:
- Encode/Encrypt/Decrypt
- Add/Sub
- Mul (ct×ct and ct×pt)
- Relinearization
- Rescale management
- Rotate (Galois keys)
- Bootstrapping (for INVNTHSQRT, DISCRETEEQUALZERO, comparison, some percentile paths)

### 7.2 Parameter sets
Deliver at least two “profiles”:
- **Profile A (no-bootstrap):** supports mean/variance/Bc/Ba/Bv within limited depth (for smaller tasks / or if DDIA assists recrypt—NOT preferred).
- **Profile B (bootstrapped):** supports all functions including INVNTHSQRT / DISCRETEEQUALZERO / k-percentile with bounded error.

Each profile must specify:
- `LogN`, modulus chain, scaling strategy, bootstrapping parameters (if enabled),
- rotation steps needed: `{1,2,4,...,Slots/2}` for reductions + application-specific rotations.

### 7.3 Security model support
- **Model-I:** DDIA receives ciphertext of final result and decrypts → trivial under IND-CPA.
- **Model-II (LBc):** DA outputs ciphertext(s) that DDIA decrypts and then (DDIA) or U post-processes. We must implement **DDIA-side post-processing** to avoid the paper’s leakage caveat when `R > Slots * 2^Δ`.

---

## 8) Functional Requirements (FR)
### FR-1 Key management service (DDIA)
- Generate CKKS parameters (from approved templates).
- Generate keys: `sk, pk, rlk, galks(rot), btpks`.
- Export public bundle for DA/DO/DMA.
- Never export sk.

### FR-2 Identifier protection (DMA join)
- DDIA generates `sMAC`.
- DO computes token = HMAC(sMAC, id).
- DMA joins by token equality.
- DMA never sees raw identifiers.

### FR-3 Encrypted table storage format
Define a stable binary format:
- metadata.json: schema, column types, category counts, Slots, NB, scaling, parameter hash
- blocks/*.bin: ciphertext blobs (Lattigo marshaled)
- bmvs/*.bin: per categorical value per block blobs (optionally chunked)
- validity/*.bin
- pbmv/bbmv/*.bin (for LBc mode)
Must support streaming read/write and partial loading per column/block.

### FR-4 Query/job specification (U→DA)
Provide `JobSpec` (JSON/YAML) with:
- operation: `mean|var|stdev|corr|bc|ba|bv|lbc|percentile|lookup`
- inputs: columns, categorical conditions `(f=value)` list
- target numeric column for Ba/Bv
- k for percentile
- output: “full table” vs “selected cases”, and expected shape
- privacy policy tag (forwarded to DDIA)

### FR-5 Numerical ops (mean/var/stdev/corr)
Implement paper-equivalent:
- `NUM-OP(x, v, mean|var)` using:
  - masked sums: Σ(x_i * v_i)
  - count sums: Σ(v_i)
  - slot reduction via rotations `{1,2,4,...}`
  - inverse via `INVNTHSQRT(count, n=1)`
- `CORR(x,y,v)` via:
  - means m1,m2, variances v1,v2
  - inv stdev via `INVNTHSQRT(var, n=2)`
  - masked covariance sum and normalize

### FR-6 BIN-OP for categorical functions (Bc/Ba/Bv)
Given F=(f0..fm-1), values W=(w0..wm-1):
- Build mask per block: `mask = v_target` (Ba/Bv) or `1` (Bc)
- Multiply by each `bmv[fj][wj][block]`
- For Bc: sum masks across blocks, then slot-reduce to total count
- For Ba/Bv: call NUM-OP with `mask` as validity vector

### FR-7 INVNTHSQRT (Newton iteration + bootstrapping)
Implement Algorithm 1 behavior:
- Input: ciphertext x, plaintext init y0, integer n, iteration k
- Iteration: `y <- (y*( (n+1) - x*y^n )) / n`
- Bootstrapping schedule:
  - bootstrap x at start
  - bootstrap y when level < required depth
  - optional bootstrap at end of each iteration (configurable)
- Provide tuned defaults:
  - n=1 with ~25 iterations
  - n=2 with ~21 iterations
Expose knobs: iterations, bootstrap frequency, target relative error.

### FR-8 DISCRETEEQUALZERO(x; Sf, K) + table lookup
Implement the paper’s approximation pipeline:
- Normalize `x <- x / 2^d`, where d=ceil(log2 Sf)
- Compute Chebyshev coefficients offline for:
  - sinc(θ) and cos(πθ) on θ∈[-1,1]
- Evaluate polynomials via power-cache to minimize depth
- Build sinc(θ) via repeated double-angle cosine recursion
- Apply filtering map `p(s)=4s^3 - 3s^4`
Output ciphertext approximating indicator: 1 if x==0 (integer), else ~0.

**Table lookup**:
- To select rows where categorical==j:
  - compute `eq = DISCRETEEQUALZERO(cat - j)`
  - multiply `eq * target_numeric` (or multiply into masks)

### FR-9 Approx comparison / sign (for percentile and COMP)
Provide an `ApproxSign` / `COMP` module:
- Inputs bounded to paper’s intended range (often [0,1] or scaled)
- Output slotwise sign or “greater-than” bit with tolerance
Implementation options (choose one as baseline, keep interface stable):
1) Polynomial approximation of sign with bootstrapping
2) Port an HE comparison construction consistent with CKKS constraints
Deliver:
- `APPROXSIGN(ct)` returns approx in {−1,0,+1} (or {0,1})
- `COMP(x1,x2)` returns approx {0,0.5,1} per slot

### FR-10 k-Percentile (ordinal)
Implement Algorithm 7 semantics:
- For ordinal variable with BMVs for values 1..S_f:
  - compute frequency per value by summing BMV blocks + slot-reduce
  - build encrypted cumulative histogram in a single ciphertext where slot i holds cumulative count for value i
- Compute `invR = INVNTHSQRT(sum(valid), n=1)`
- Compare cumulative/R with k/100 using `APPROXSIGN`
- Apply mapping `f(x) = -0.5(x-0.5)^2 + 1.125` (paper’s “flip to 0/1” trick)
- Slot-reduce and derive l (percentile index)

### FR-11 LBc (Large-Bin-Count) with PBMV/BBMV
Implement PBMV+BBMV encoding + multiplication plan:
- PBMV for one categorical variable f0:
  - encode one-hot category into spaced bit-fields with parameters (Δ, δ)
- BBMV for other variables:
  - encode masks as {0, 2^Λ} to separate “signal” from CKKS noise
- Optionally compress multiple variables into “virtual variables” f′ to satisfy modulus bit constraints (paper’s m→m′ trick)

**Execution model (Model-II):**
- DA computes batched products producing partial packed results.
- DA sends ciphertext batch to DDIA.
- DDIA decrypts and performs post-processing and aggregation into the final contingency table.

**Security requirement (matches paper’s caveat):**
- If R is bigger than `Slots * 2^Δ`, DDIA must perform aggregation and only release final table counts (not raw decrypted chunks).

### FR-12 Privacy inspection hooks (DDIA)
- DDIA receives decrypted numeric outputs / tables and runs policy checks (pluggable):
  - k-anonymity thresholds for bins
  - “small group” suppression
  - max-precision caps / rounding rules for numeric outputs
  - query auditing metadata (what was requested)

---

## 9) Non-Functional Requirements (NFR)
### NFR-1 Scale
- Must handle **millions of rows** by streaming blocks from disk.
- Must support tens of columns; BMVs may be huge → implement:
  - lazy loading per variable/value range,
  - mmap or chunked reads,
  - optional “generate BMVs on demand” path (DISCRETEEQUALZERO).

### NFR-2 Accuracy
- For numerical ops: relative error dominated by bootstrap error; target “paper-like” stability once data is large.
- For DISCRETEEQUALZERO: must produce a sharp spike at equality (validate false positive/negative rates).
- For percentile: stable result for large R.

### NFR-3 Performance
- Concurrent execution across blocks (Go worker pools).
- Avoid keeping all ciphertexts in RAM.
- Provide profiling counters:
  - time spent in mul/rot/bootstrap
  - ciphertext IO volume
  - per-job depth/level tracking

### NFR-4 Reproducibility
- Parameter bundles hashed and recorded.
- Deterministic coefficient generation versioned.
- Golden plaintext fixtures for correctness.

---

## 10) Proposed Repository Structure (Go)
```

lattigo-stat/
cmd/
ddia/           # keygen + decrypt + privacy-inspect + postprocess
do_encrypt/     # data owner encryption pipeline
dma_merge/      # merge authority join tool
da_run/         # analyst job runner
pkg/
params/         # parameter profiles + validation
schema/         # table schema, metadata, typing
storage/        # ciphertext serialization, chunking
he/             # thin wrapper around lattigo evaluator/encoder/bootstrapper
ops/
numeric/      # mean/var/stdev/corr + invnthsqt
categorical/  # bmv + binop + lbc encodings
approx/       # discreteequalzero + approxsign/comp
ordinal/      # percentile
jobs/           # JobSpec parsing + planning
privacy/        # DDIA policy checks
test/
fixtures/       # small plaintext datasets + expected outputs

```

---

## 11) Acceptance Criteria (Must-pass)
### AC-1 Correctness (small scale)
On a toy dataset (e.g., R<=1024):
- mean/var/corr match plaintext within configured epsilon.
- Bc exact after DDIA decryption.
- Ba/Bv within epsilon.
- DISCRETEEQUALZERO distinguishes equality vs non-equality for integer-coded categories.
- percentile returns correct bucket index.

### AC-2 End-to-end workflow
- DO encrypts + uploads
- DMA merges
- DA executes JobSpec
- DDIA decrypts + passes privacy inspection
- U receives result

### AC-3 LBc safety behavior
For R > Slots * 2^Δ:
- DDIA aggregates decrypted chunks and releases only final table.
- Raw per-chunk outputs are never exposed to U.

---

## 12) Engineering Risks & Mitigations
1) **Bootstrapping cost / availability in chosen Lattigo version**
   - Mitigation: lock to a known bootstrapping-enabled parameter profile; keep interfaces independent of exact Lattigo package layout.
2) **BMV storage blow-up**
   - Mitigation: chunked serialization; “generate BMV on demand” mode using DISCRETEEQUALZERO.
3) **Depth/scale management**
   - Mitigation: centralized evaluator wrapper that enforces scale policy + logs level consumption; unit tests per op.
4) **Approximation brittleness (DISCRETEEQUALZERO / APPROXSIGN)**
   - Mitigation: coefficient generator + sweep tests; track false positives/negatives; tune K,d,filter stages.
5) **LBc without GPU may be slow**
   - Mitigation: concurrency + batching; design a “backend interface” so later a GPU evaluator can drop in.

---

## 13) Milestones (Suggested)
- **M0:** Params + IO + key distribution scaffolding
- **M1:** Numeric ops + INVNTHSQRT
- **M2:** BMV + BIN-OP (Bc/Ba/Bv)
- **M3:** DISCRETEEQUALZERO + table lookup
- **M4:** APPROXSIGN/COMP + k-percentile
- **M5:** LBc (PBMV/BBMV) + DDIA post-processing + policy enforcement
- **M6:** Performance pass (streaming, concurrency, profiling)

---

## 14) Appendix: Concrete “Operation-to-Module” Mapping
- Algorithm 1 (INVNTHSQRT) → `pkg/ops/numeric/inv.go`
- Algorithm 2 (NUM-OP) → `pkg/ops/numeric/meanvar.go`
- Algorithm 3 (CORR) → `pkg/ops/numeric/corr.go`
- Algorithm 4 (BIN-OP) → `pkg/ops/categorical/binop.go`
- Algorithm 5 (GENBIGMASK / BBMV) → `pkg/ops/categorical/lbc_bbmv.go`
- Algorithm 6 (DISCRETEEQUALZERO) → `pkg/ops/approx/discrete_equal_zero.go`
- Algorithm 7 (PERCENTILE) → `pkg/ops/ordinal/percentile.go`

---
```

If you want, I can also output a **matching `JobSpec` schema** (JSON) and the **exact function signatures** (Go interfaces) for `Evaluator`, `Bootstrapper`, and each op module so implementation starts immediately without redesign.
