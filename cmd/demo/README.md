# Lattigo-STAT Demo Suite

This demo showcases homomorphic encryption (HE) statistical computations using CKKS encryption from the Lattigo library.

## What It Demonstrates

The demo performs end-to-end encrypted statistical operations:

1. **Key Generation** - Creates CKKS cryptographic keys (secret, public, relinearization, Galois rotation keys)
2. **Vector Generation** - Generates random test vectors and validity masks
3. **Encryption** - Encrypts vectors using CKKS scheme
4. **HE Computation** - Computes statistics on encrypted data without decryption
5. **Decryption & Verification** - Decrypts results and compares against plaintext computations
6. **Noise Analysis** - Measures encryption/computation noise characteristics

## Statistical Operations

| Operation | Formula | Use Case |
|-----------|---------|----------|
| **Masked Sum** | Σ(xᵢ · maskᵢ) | Sum with validity filtering |
| **Sum of Squares** | Σ(xᵢ²) | Variance computation |
| **Dot Product** | Σ(xᵢ · yᵢ) | Correlation, covariance |
| **Count** | Σ(maskᵢ) | Valid entry counting |

## Running the Demo

```bash
cd /path/to/lattigostats
go run ./cmd/demo
```

## Sample Output

```
Profile Type:      A (No Bootstrapping)
Ring Degree (N):   2^14 = 16384
Slots:             8192

╔═══════════════════╦═══════════════════╦═══════════════════╦═══════════════╗
║ Statistic         ║ Plaintext         ║ Encrypted         ║ Rel Error     ║
╠═══════════════════╬═══════════════════╬═══════════════════╬═══════════════╣
║ Masked Sum        ║          2.902600 ║          2.902600 ║     1.80e-05% ║
║ Sum of Squares    ║        447.784765 ║        447.784765 ║     2.23e-08% ║
║ Dot Product       ║        133.159276 ║        133.159275 ║     2.99e-07% ║
║ Count             ║         10.000000 ║         10.000000 ║     1.81e-06% ║
╚═══════════════════╩═══════════════════╩═══════════════════╩═══════════════╝
```

## Understanding CKKS Noise

CKKS is an **approximate** homomorphic encryption scheme. Key characteristics:

- **Encryption noise**: ~10⁻⁹ per element (negligible)
- **Computation noise**: Grows with operation depth
- **Typical precision**: 22-27 bits for simple operations
- **Relative errors**: Usually < 0.001%

### Noise Sources

1. **Initial encoding** - Converting floats to polynomials
2. **Encryption randomness** - Security-required noise injection
3. **Rescaling** - Precision loss after multiplication
4. **Rotation** - Slot permutation operations

### Level Consumption

Each multiplicative operation consumes one "level" from the ciphertext:
- Fresh ciphertext: Level 7 (Profile A)
- After multiplication + rescale: Level 6
- After another multiplication: Level 5

When levels are exhausted, bootstrapping is required (Profile B).

## Configuration

The demo uses **Profile A** (no bootstrapping):

| Parameter | Value |
|-----------|-------|
| Ring Degree (N) | 2¹⁴ = 16384 |
| Slots | N/2 = 8192 |
| Log Scale | 40 bits |
| Max Level | 7 |
| Security | 128-bit |

## Code Structure

```
cmd/demo/main.go
├── main()                    # Entry point, runs demos at 3 scales
├── runDemo()                 # Single demo execution
├── generateRandomVector()    # Random float vector in [-10, 10]
├── generateMaskVector()      # Random validity mask (0 or 1)
├── computePlaintextStats()   # Reference plaintext computation
├── computeEncryptedSum()     # HE masked sum via rotations
├── computeEncryptedSumSq()   # HE sum of squares
├── computeEncryptedDot()     # HE dot product
└── computeEncryptedCount()   # HE valid count
```

## Extending the Demo

To add new operations:

1. Implement plaintext reference in `computePlaintextStats()`
2. Add HE computation function (use `eval.Mul`, `eval.Add`, `sumSlots()`)
3. Add result comparison in the output table

## Related

- [AGENTS.md](../../AGENTS.md) - Full PRD for Lattigo-STAT
- [Lattigo](https://github.com/tuneinsight/lattigo) - Go HE library
- [CKKS Paper](https://eprint.iacr.org/2016/421) - Original CKKS scheme
