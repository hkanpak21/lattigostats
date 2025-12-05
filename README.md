# Lattigo-STAT

A homomorphic encryption statistical toolkit built on [Lattigo](https://github.com/tuneinsight/lattigo) (Go) using CKKS scheme. This project implements the capabilities described in the HEaaN-STAT paper (TDSC 2024) for privacy-preserving statistical analysis.

## Overview

Lattigo-STAT enables organizations to fuse large-scale tabular datasets from different domains and compute statistical operations (mean, variance, correlation, contingency tables, percentiles) while:

- Data owners do **not** learn others' data
- Data owners do **not** participate after sending encrypted data  
- An oversight party checks outputs for privacy leakage before releasing results
- The system can scale to nation-scale datasets

## Features

### Statistical Operations
- **Numerical:** Mean, Variance, Standard Deviation, Pearson Correlation
- **Categorical:** Bin Count (Bc), Bin Average (Ba), Bin Variance (Bv)
- **Large-scale:** Large-Bin-Count (LBc) with PBMV/BBMV encoding
- **Ordinal:** k-Percentile using BMVs and comparison

### Utility Primitives
- **INVNTHSQRT:** Newton iteration for computing x^(-1/n)
- **DISCRETEEQUALZERO:** Approximate indicator function for equality to zero
- **APPROXSIGN:** Polynomial approximation of sign function

### System Components
- **DDIA (Data Discovery and Inspection Authority):** Key generation, decryption, privacy inspection
- **DO (Data Owner):** Data encryption and export
- **DMA (Data Merge Authority):** Row merging by protected identifiers
- **DA (Data Analyst):** HE computation execution

## Installation

```bash
# Clone the repository
git clone https://github.com/hkanpak21/lattigostats.git
cd lattigostats

# Install dependencies
go mod download

# Build CLI tools
go build -o bin/ddia ./cmd/ddia
go build -o bin/do_encrypt ./cmd/do_encrypt
go build -o bin/dma_merge ./cmd/dma_merge
go build -o bin/da_run ./cmd/da_run
```

## Quick Start

### 1. Generate Keys (DDIA)

```bash
./bin/ddia keygen -profile A -output ./keys
```

This generates:
- `secret.key` - Secret key (NEVER share!)
- `public.key` - Public key for encryption
- `eval.key` - Evaluation keys for HE operations
- `params.json` - Parameter metadata

### 2. Encrypt Data (Data Owner)

Create a schema file (`schema.json`):
```json
{
  "name": "my_dataset",
  "columns": [
    {"name": "income", "type": "numerical"},
    {"name": "gender", "type": "categorical", "category_count": 2}
  ]
}
```

Encrypt your CSV data:
```bash
./bin/do_encrypt \
  -input data.csv \
  -schema schema.json \
  -keys ./keys \
  -output ./encrypted
```

### 3. Run Statistical Jobs (DA)

Create a job specification (`job.json`):
```json
{
  "id": "mean_income",
  "operation": "mean",
  "columns": ["income"]
}
```

Execute:
```bash
./bin/da_run \
  -job job.json \
  -table ./encrypted \
  -keys ./keys \
  -output result.ct
```

### 4. Decrypt and Inspect (DDIA)

```bash
./bin/ddia decrypt \
  -keys ./keys \
  -input result.ct

./bin/ddia inspect \
  -input decrypted_result.json \
  -policy policy.json
```

## Parameter Profiles

| Profile | LogN | Slots | Bootstrapping | Use Case |
|---------|------|-------|---------------|----------|
| A | 14 | 8,192 | No | Mean, Variance, Bc, Ba, Bv |
| B | 16 | 32,768 | Yes | INVNTHSQRT, DISCRETEEQUALZERO, Percentile |

## Project Structure

```
lattigo-stat/
├── cmd/
│   ├── ddia/          # DDIA CLI tool
│   ├── do_encrypt/    # Data encryption tool
│   ├── dma_merge/     # Data merge tool
│   └── da_run/        # Job execution tool
├── pkg/
│   ├── params/        # CKKS parameter profiles
│   ├── schema/        # Table schema definitions
│   ├── storage/       # Ciphertext serialization
│   ├── he/            # Lattigo wrapper
│   ├── ops/
│   │   ├── numeric/   # Mean, Var, Corr, INVNTHSQRT
│   │   ├── categorical/ # BMV, BIN-OP, LBc
│   │   ├── approx/    # DISCRETEEQUALZERO, APPROXSIGN
│   │   └── ordinal/   # Percentile
│   ├── jobs/          # Job specification
│   └── privacy/       # Privacy inspection
└── test/
    ├── fixtures/      # Test data
    └── integration/   # Integration tests
```

## Supported Operations

### Mean
```json
{"operation": "mean", "columns": ["income"]}
```

### Variance / StdDev
```json
{"operation": "var", "columns": ["income"]}
{"operation": "stdev", "columns": ["income"]}
```

### Correlation
```json
{"operation": "corr", "columns": ["income", "spending"]}
```

### Bin Count (Bc)
```json
{
  "operation": "bc",
  "conditions": [
    {"column": "gender", "value": 1},
    {"column": "region", "value": 2}
  ]
}
```

### Bin Average (Ba)
```json
{
  "operation": "ba",
  "target": "income",
  "conditions": [{"column": "gender", "value": 1}]
}
```

### k-Percentile
```json
{
  "operation": "percentile",
  "columns": ["risk_bucket"],
  "k": 90
}
```

## Privacy Policy

The DDIA enforces privacy policies including:

- **k-anonymity threshold:** Minimum count for bin release
- **Small group suppression:** Suppress bins below threshold
- **Precision limits:** Round numeric outputs
- **Query limits:** Maximum queries per session

Example policy:
```json
{
  "k_anonymity_threshold": 5,
  "small_group_threshold": 3,
  "max_precision": 6,
  "max_queries_per_session": 100
}
```

## Testing

```bash
# Run unit tests
go test ./pkg/...

# Run integration tests
go test ./test/integration/...

# Run all tests with coverage
go test -cover ./...
```

## References

- HEaaN-STAT: Statistical Analysis on Encrypted Data (TDSC 2024)
- [Lattigo](https://github.com/tuneinsight/lattigo) - Homomorphic Encryption Library in Go

## License

MIT License

## Contributing

Contributions are welcome! Please read the AGENTS.md file for implementation details and roadmap.
