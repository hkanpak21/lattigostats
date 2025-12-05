// Package categorical implements categorical statistical operations:
// BMV (Bin Mask Vectors), Bc (bin-count), Ba (bin-average), Bv (bin-variance),
// and LBc (Large-Bin-Count) using PBMV/BBMV encodings.
package categorical

import (
	"fmt"
	"math"

	"github.com/hkanpak21/lattigostats/pkg/he"
	"github.com/hkanpak21/lattigostats/pkg/ops/numeric"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// CategoricalOp computes categorical statistics on encrypted data
type CategoricalOp struct {
	eval      *he.Evaluator
	numericOp *numeric.NumericOp
}

// NewCategoricalOp creates a new categorical operations handler
func NewCategoricalOp(eval *he.Evaluator) *CategoricalOp {
	return &CategoricalOp{
		eval:      eval,
		numericOp: numeric.NewNumericOp(eval),
	}
}

// Condition represents a categorical filter condition (column = value)
type Condition struct {
	ColumnName string
	Value      int
}

// BMVStore provides access to BMV ciphertexts
type BMVStore interface {
	// GetBMV returns the BMV block for the given column, value, and block index
	GetBMV(columnName string, value int, blockIndex int) (*rlwe.Ciphertext, error)
	// BlockCount returns the number of blocks
	BlockCount() int
}

// BuildMask builds a combined mask from multiple conditions
// mask[b] = v_target[b] * bmv[f0][w0][b] * bmv[f1][w1][b] * ...
func (c *CategoricalOp) BuildMask(
	validityBlocks []*rlwe.Ciphertext,
	conditions []Condition,
	bmvStore BMVStore,
) ([]*rlwe.Ciphertext, error) {
	blockCount := len(validityBlocks)
	masks := make([]*rlwe.Ciphertext, blockCount)

	for b := 0; b < blockCount; b++ {
		// Start with validity mask
		mask := validityBlocks[b].CopyNew()

		// Multiply by each condition's BMV
		for _, cond := range conditions {
			bmv, err := bmvStore.GetBMV(cond.ColumnName, cond.Value, b)
			if err != nil {
				return nil, fmt.Errorf("failed to get BMV for %s=%d block %d: %w",
					cond.ColumnName, cond.Value, b, err)
			}

			mask, err = c.eval.Mul(mask, bmv)
			if err != nil {
				return nil, fmt.Errorf("block %d mul failed: %w", b, err)
			}
			mask, err = c.eval.Rescale(mask)
			if err != nil {
				return nil, fmt.Errorf("block %d rescale failed: %w", b, err)
			}
		}

		masks[b] = mask
	}

	return masks, nil
}

// Bc computes bin-count: count of rows matching all conditions
func (c *CategoricalOp) Bc(
	validityBlocks []*rlwe.Ciphertext,
	conditions []Condition,
	bmvStore BMVStore,
) (*rlwe.Ciphertext, error) {
	// Build mask
	masks, err := c.BuildMask(validityBlocks, conditions, bmvStore)
	if err != nil {
		return nil, fmt.Errorf("build mask failed: %w", err)
	}

	// Sum all mask values = count
	return c.numericOp.Count(masks)
}

// Ba computes bin-average: average of target column for rows matching conditions
func (c *CategoricalOp) Ba(
	targetBlocks []*rlwe.Ciphertext,
	validityBlocks []*rlwe.Ciphertext,
	conditions []Condition,
	bmvStore BMVStore,
) (*rlwe.Ciphertext, error) {
	// Build mask
	masks, err := c.BuildMask(validityBlocks, conditions, bmvStore)
	if err != nil {
		return nil, fmt.Errorf("build mask failed: %w", err)
	}

	// Compute mean with the combined mask
	return c.numericOp.Mean(targetBlocks, masks)
}

// Bv computes bin-variance: variance of target column for rows matching conditions
func (c *CategoricalOp) Bv(
	targetBlocks []*rlwe.Ciphertext,
	validityBlocks []*rlwe.Ciphertext,
	conditions []Condition,
	bmvStore BMVStore,
) (*rlwe.Ciphertext, error) {
	// Build mask
	masks, err := c.BuildMask(validityBlocks, conditions, bmvStore)
	if err != nil {
		return nil, fmt.Errorf("build mask failed: %w", err)
	}

	// Compute variance with the combined mask
	return c.numericOp.Variance(targetBlocks, masks)
}

// LBcConfig configures Large-Bin-Count computation
type LBcConfig struct {
	Delta       int // Δ: bit spacing in PBMV between categories
	DeltaOffset int // δ: initial bit offset (paper's δ)
	LambdaBig   int // Λ: scale factor for BBMV (2^Λ)
}

// DefaultLBcConfig returns default LBc configuration
func DefaultLBcConfig() LBcConfig {
	return LBcConfig{
		Delta:       10,
		DeltaOffset: 10,
		LambdaBig:   30,
	}
}

// ValidateLBcConfig validates the LBc configuration parameters
func ValidateLBcConfig(config LBcConfig, categories int) error {
	// Check that the maximum exponent fits in float64 mantissa (52 bits)
	maxExp := config.DeltaOffset + config.Delta*(categories-1)
	if maxExp > 52 {
		return fmt.Errorf("PBMV exponent overflow: δ + Δ*(S-1) = %d > 52 bits", maxExp)
	}
	if config.LambdaBig > 52 {
		return fmt.Errorf("BBMV Λ = %d > 52 bits", config.LambdaBig)
	}
	return nil
}

// PBMVEncoder encodes categorical values using spaced bit-field encoding
type PBMVEncoder struct {
	config     LBcConfig
	categories int // S_f: number of categories
	slots      int
}

// NewPBMVEncoder creates a new PBMV encoder
func NewPBMVEncoder(categories, slots int, config LBcConfig) *PBMVEncoder {
	return &PBMVEncoder{
		config:     config,
		categories: categories,
		slots:      slots,
	}
}

// EncodePBMV encodes categorical values into PBMV format
// For category value v ∈ [1..S], slot gets 2^(δ + Δ*(v-1))
// This creates a one-hot encoding in power-of-two bit positions
func (p *PBMVEncoder) EncodePBMV(values []int) []float64 {
	result := make([]float64, p.slots)

	for i, v := range values {
		if i >= p.slots {
			break
		}
		if v < 1 || v > p.categories {
			continue // invalid category, leave as 0
		}

		// PBMV exponent: exp = δ + Δ*(v-1)
		exp := p.config.DeltaOffset + p.config.Delta*(v-1)
		// Use math.Ldexp for exact power-of-two representation
		result[i] = math.Ldexp(1.0, exp)
	}

	return result
}

// BBMVEncoder encodes binary masks with scaling
type BBMVEncoder struct {
	config LBcConfig
	slots  int
}

// NewBBMVEncoder creates a new BBMV encoder
func NewBBMVEncoder(slots int, config LBcConfig) *BBMVEncoder {
	return &BBMVEncoder{
		config: config,
		slots:  slots,
	}
}

// EncodeBBMV encodes a binary mask with 2^Λ scaling
// Mask values: 0 or 2^Λ (separates signal from CKKS noise)
func (b *BBMVEncoder) EncodeBBMV(mask []bool) []float64 {
	result := make([]float64, b.slots)
	scale := math.Ldexp(1.0, b.config.LambdaBig) // 2^Λ

	for i, m := range mask {
		if i >= b.slots {
			break
		}
		if m {
			result[i] = scale
		}
	}

	return result
}

// EncodeBBMVForValue encodes a BBMV for rows matching a specific categorical value
// values: the categorical values for each row
// want: the category value to match
func (b *BBMVEncoder) EncodeBBMVForValue(values []int, want int) []float64 {
	result := make([]float64, b.slots)
	scale := math.Ldexp(1.0, b.config.LambdaBig)

	for i, v := range values {
		if i >= b.slots {
			break
		}
		if v == want {
			result[i] = scale
		}
	}

	return result
}

// LBcComputer computes Large-Bin-Count using PBMV/BBMV
type LBcComputer struct {
	eval   *he.Evaluator
	config LBcConfig
}

// NewLBcComputer creates a new LBc computer
func NewLBcComputer(eval *he.Evaluator, config LBcConfig) *LBcComputer {
	return &LBcComputer{
		eval:   eval,
		config: config,
	}
}

// PBMVStore provides access to PBMV ciphertexts
type PBMVStore interface {
	GetPBMV(columnName string, blockIndex int) (*rlwe.Ciphertext, error)
	BlockCount() int
}

// BBMVStore provides access to BBMV ciphertexts
type BBMVStore interface {
	GetBBMV(columnName string, blockIndex int) (*rlwe.Ciphertext, error)
	BlockCount() int
}

// LBcResult holds the encrypted result of LBc computation
// DDIA must decrypt and post-process to get final contingency table
type LBcResult struct {
	// PackedResults contains the encrypted batched products
	PackedResults []*rlwe.Ciphertext
	// NumBlocks is the number of blocks
	NumBlocks int
	// RowsPerBlock is R per block
	RowsPerBlock int
	// RequiresAggregation is true if R > Slots * 2^Δ
	RequiresAggregation bool
}

// ComputeLBc computes Large-Bin-Count for a multi-way contingency table
// f0: primary variable (encoded as PBMV)
// others: additional variables (encoded as BBMV)
func (l *LBcComputer) ComputeLBc(
	f0Column string,
	pbmvStore PBMVStore,
	otherColumns []string,
	bbmvStores map[string]BBMVStore,
	validityBlocks []*rlwe.Ciphertext,
) (*LBcResult, error) {
	blockCount := pbmvStore.BlockCount()
	results := make([]*rlwe.Ciphertext, blockCount)

	for b := 0; b < blockCount; b++ {
		// Get PBMV for primary variable
		pbmv, err := pbmvStore.GetPBMV(f0Column, b)
		if err != nil {
			return nil, fmt.Errorf("failed to get PBMV for %s block %d: %w", f0Column, b, err)
		}

		// Start with PBMV
		result := pbmv.CopyNew()

		// Multiply by validity
		result, err = l.eval.Mul(result, validityBlocks[b])
		if err != nil {
			return nil, fmt.Errorf("block %d validity mul failed: %w", b, err)
		}
		result, err = l.eval.Rescale(result)
		if err != nil {
			return nil, fmt.Errorf("block %d validity rescale failed: %w", b, err)
		}

		// Multiply by each BBMV
		for _, col := range otherColumns {
			store, ok := bbmvStores[col]
			if !ok {
				return nil, fmt.Errorf("no BBMV store for column %s", col)
			}
			bbmv, err := store.GetBBMV(col, b)
			if err != nil {
				return nil, fmt.Errorf("failed to get BBMV for %s block %d: %w", col, b, err)
			}

			result, err = l.eval.Mul(result, bbmv)
			if err != nil {
				return nil, fmt.Errorf("block %d %s mul failed: %w", b, col, err)
			}
			result, err = l.eval.Rescale(result)
			if err != nil {
				return nil, fmt.Errorf("block %d %s rescale failed: %w", b, col, err)
			}
		}

		results[b] = result
	}

	// Sum across blocks
	var packed *rlwe.Ciphertext
	for i, r := range results {
		if packed == nil {
			packed = r.CopyNew()
		} else {
			err := l.eval.AddInPlace(packed, r)
			if err != nil {
				return nil, fmt.Errorf("block %d sum failed: %w", i, err)
			}
		}
	}

	slots := l.eval.Slots()
	rowsPerBlock := slots // simplified
	requiresAgg := blockCount*rowsPerBlock > slots*(1<<l.config.Delta)

	return &LBcResult{
		PackedResults:       []*rlwe.Ciphertext{packed},
		NumBlocks:           blockCount,
		RowsPerBlock:        rowsPerBlock,
		RequiresAggregation: requiresAgg,
	}, nil
}

// PlaintextBc computes bin-count from plaintext (for validation)
func PlaintextBc(values [][]int, conditions []int, valid []bool) int {
	count := 0
	for i := range valid {
		if !valid[i] {
			continue
		}
		match := true
		for j, cond := range conditions {
			if values[j][i] != cond {
				match = false
				break
			}
		}
		if match {
			count++
		}
	}
	return count
}

// PlaintextBa computes bin-average from plaintext (for validation)
func PlaintextBa(target []float64, values [][]int, conditions []int, valid []bool) float64 {
	var sum float64
	count := 0
	for i := range valid {
		if !valid[i] {
			continue
		}
		match := true
		for j, cond := range conditions {
			if values[j][i] != cond {
				match = false
				break
			}
		}
		if match {
			sum += target[i]
			count++
		}
	}
	if count == 0 {
		return 0
	}
	return sum / float64(count)
}

// PlaintextBv computes bin-variance from plaintext (for validation)
func PlaintextBv(target []float64, values [][]int, conditions []int, valid []bool) float64 {
	mean := PlaintextBa(target, values, conditions, valid)
	var sumSq float64
	count := 0
	for i := range valid {
		if !valid[i] {
			continue
		}
		match := true
		for j, cond := range conditions {
			if values[j][i] != cond {
				match = false
				break
			}
		}
		if match {
			diff := target[i] - mean
			sumSq += diff * diff
			count++
		}
	}
	if count == 0 {
		return 0
	}
	return sumSq / float64(count)
}
