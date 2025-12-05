# Lattigo-STAT Test Fixtures

This directory contains test fixtures for validating Lattigo-STAT correctness.

## Files

### Schema
- `test_schema.json` - Schema definition for the test dataset

### Data
- `test_data.csv` - Small test dataset (20 rows)

### Job Specifications
- `job_mean.json` - Mean income computation
- `job_corr.json` - Correlation between income and spending
- `job_bc.json` - Bin count for females in South region
- `job_ba.json` - Bin average income for males
- `job_percentile.json` - 90th percentile of risk bucket

## Expected Results

Based on `test_data.csv`:

### Mean Income
- Expected: 51300 (sum=1026000, count=20)

### Variance Income
- Expected: ~264,960,000

### Correlation (income, spending)
- Expected: ~0.997 (very high positive correlation)

### Bin Count (gender=2, region=2)
- Females in South: 4 (rows 2, 6, 10, 16, 20)

### Bin Average Income (gender=1)
- Male avg income: 40000 (rows 1,3,5,7,9,11,13,15,17,19)

### 90th Percentile Risk Bucket
- Values: 3,2,4,2,3,1,5,2,3,1,4,2,3,1,5,2,3,1,4,2
- Sorted: 1,1,1,1,1, 2,2,2,2,2,2, 3,3,3,3,3, 4,4,4, 5,5
- 90th percentile: bucket 5

## Usage

```bash
# Generate test keys
cd /path/to/lattigostats
go run ./cmd/ddia keygen -profile A -output ./test/keys

# Encrypt test data
go run ./cmd/do_encrypt \
  -input ./test/fixtures/test_data.csv \
  -schema ./test/fixtures/test_schema.json \
  -keys ./test/keys \
  -output ./test/encrypted

# Run a job
go run ./cmd/da_run \
  -job ./test/fixtures/job_mean.json \
  -table ./test/encrypted \
  -keys ./test/keys \
  -output ./test/result_mean.ct
```
