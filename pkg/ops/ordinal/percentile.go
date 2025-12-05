// Package ordinal implements ordinal statistical operations:
// k-percentile computation using BMVs and comparison.
package ordinal

import (
	"fmt"
	"sort"

	"github.com/hkanpak21/lattigostats/pkg/he"
	"github.com/hkanpak21/lattigostats/pkg/ops/approx"
	"github.com/hkanpak21/lattigostats/pkg/ops/numeric"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// OrdinalOp computes ordinal statistics on encrypted data
type OrdinalOp struct {
	eval      *he.Evaluator
	numericOp *numeric.NumericOp
	approxOp  *approx.ApproxOp
}

// NewOrdinalOp creates a new ordinal operations handler
func NewOrdinalOp(eval *he.Evaluator) *OrdinalOp {
	return &OrdinalOp{
		eval:      eval,
		numericOp: numeric.NewNumericOp(eval),
		approxOp:  approx.NewApproxOp(eval),
	}
}

// PercentileConfig configures k-percentile computation
type PercentileConfig struct {
	K          float64 // Percentile value (0-100)
	Categories int     // S_f: number of ordinal categories
}

// BMVStore provides access to BMV ciphertexts for ordinal values
type BMVStore interface {
	// GetBMV returns the BMV block for the given value and block index
	GetBMV(value int, blockIndex int) (*rlwe.Ciphertext, error)
	// BlockCount returns the number of blocks
	BlockCount() int
}

// Percentile computes the k-th percentile of an ordinal variable
// Returns the percentile bucket index (1 to Categories)
func (o *OrdinalOp) Percentile(
	validityBlocks []*rlwe.Ciphertext,
	bmvStore BMVStore,
	config PercentileConfig,
) (*rlwe.Ciphertext, error) {
	blockCount := bmvStore.BlockCount()

	// Step 1: Compute frequency for each value by summing BMV blocks
	freqs := make([]*rlwe.Ciphertext, config.Categories)
	for v := 1; v <= config.Categories; v++ {
		var sum *rlwe.Ciphertext
		for b := 0; b < blockCount; b++ {
			bmv, err := bmvStore.GetBMV(v, b)
			if err != nil {
				return nil, fmt.Errorf("failed to get BMV for value %d block %d: %w", v, b, err)
			}

			// Multiply by validity
			masked, err := o.eval.Mul(bmv, validityBlocks[b])
			if err != nil {
				return nil, fmt.Errorf("value %d block %d mul failed: %w", v, b, err)
			}
			masked, err = o.eval.Rescale(masked)
			if err != nil {
				return nil, fmt.Errorf("value %d block %d rescale failed: %w", v, b, err)
			}

			if sum == nil {
				sum = masked
			} else {
				err = o.eval.AddInPlace(sum, masked)
				if err != nil {
					return nil, fmt.Errorf("value %d block %d add failed: %w", v, b, err)
				}
			}
		}

		// Sum across slots to get total frequency for this value
		freq, err := o.eval.SumSlots(sum)
		if err != nil {
			return nil, fmt.Errorf("value %d sum slots failed: %w", v, err)
		}
		freqs[v-1] = freq
	}

	// Step 2: Compute cumulative histogram
	// cumul[i] = sum(freq[0..i])
	cumul := make([]*rlwe.Ciphertext, config.Categories)
	cumul[0] = freqs[0].CopyNew()
	for i := 1; i < config.Categories; i++ {
		var err error
		cumul[i], err = o.eval.Add(cumul[i-1], freqs[i])
		if err != nil {
			return nil, fmt.Errorf("cumul %d add failed: %w", i, err)
		}
	}

	// Step 3: Compute total count R and inverse
	R := cumul[config.Categories-1]
	invR, err := o.numericOp.INVNTHSQRT(R, numeric.DefaultINVConfig())
	if err != nil {
		return nil, fmt.Errorf("inv R failed: %w", err)
	}

	// Step 4: Compute cumul[i] / R and compare with k/100
	kThreshold := config.K / 100.0
	signConfig := approx.DefaultApproxSignConfig()

	// For each bucket, compute: sign(cumul[i]/R - k/100)
	// Then apply mapping to get indicator
	indicators := make([]*rlwe.Ciphertext, config.Categories)
	for i := 0; i < config.Categories; i++ {
		// cumul[i] * invR
		ratio, err := o.eval.Mul(cumul[i], invR)
		if err != nil {
			return nil, fmt.Errorf("ratio %d mul failed: %w", i, err)
		}
		ratio, err = o.eval.Rescale(ratio)
		if err != nil {
			return nil, fmt.Errorf("ratio %d rescale failed: %w", i, err)
		}

		// ratio - k/100
		diff, err := o.eval.AddConst(ratio, complex(-kThreshold, 0))
		if err != nil {
			return nil, fmt.Errorf("diff %d failed: %w", i, err)
		}

		// Approximate sign
		sign, err := o.approxOp.APPROXSIGN(diff, signConfig)
		if err != nil {
			return nil, fmt.Errorf("sign %d failed: %w", i, err)
		}

		// Map sign to indicator using f(x) = -0.5(x-0.5)^2 + 1.125
		// This maps: sign=-1 (below threshold) -> 0
		//            sign=1 (at or above threshold) -> 1
		indicators[i], err = o.applyFlipMapping(sign)
		if err != nil {
			return nil, fmt.Errorf("flip %d failed: %w", i, err)
		}
	}

	// Step 5: Find the first bucket where indicator becomes 1
	// Percentile = first i where cumul[i]/R >= k/100
	// Use: Σ (1 - indicator[i]) to count how many are below
	// Then percentile index = count + 1

	var belowCount *rlwe.Ciphertext
	for i := 0; i < config.Categories; i++ {
		// 1 - indicator[i]
		notInd, err := o.eval.MulConst(indicators[i], complex(-1, 0))
		if err != nil {
			return nil, fmt.Errorf("neg indicator %d failed: %w", i, err)
		}
		notInd, err = o.eval.AddConst(notInd, complex(1, 0))
		if err != nil {
			return nil, fmt.Errorf("1-indicator %d failed: %w", i, err)
		}

		if belowCount == nil {
			belowCount = notInd
		} else {
			err = o.eval.AddInPlace(belowCount, notInd)
			if err != nil {
				return nil, fmt.Errorf("sum indicators %d failed: %w", i, err)
			}
		}
	}

	// Percentile bucket = belowCount + 1 (but clamped to Categories)
	result, err := o.eval.AddConst(belowCount, complex(1, 0))
	if err != nil {
		return nil, fmt.Errorf("final add 1 failed: %w", err)
	}

	return result, nil
}

// applyFlipMapping applies f(x) = -0.5(x-0.5)^2 + 1.125
// Maps sign output to clean 0/1 indicator
func (o *OrdinalOp) applyFlipMapping(x *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	// f(x) = -0.5(x-0.5)^2 + 1.125
	// = -0.5(x^2 - x + 0.25) + 1.125
	// = -0.5x^2 + 0.5x - 0.125 + 1.125
	// = -0.5x^2 + 0.5x + 1

	// x^2
	x2, err := o.eval.Mul(x, x)
	if err != nil {
		return nil, fmt.Errorf("x^2 failed: %w", err)
	}
	x2, err = o.eval.Rescale(x2)
	if err != nil {
		return nil, fmt.Errorf("x^2 rescale failed: %w", err)
	}

	// -0.5x^2
	term1, err := o.eval.MulConst(x2, complex(-0.5, 0))
	if err != nil {
		return nil, fmt.Errorf("-0.5x^2 failed: %w", err)
	}

	// 0.5x
	term2, err := o.eval.MulConst(x, complex(0.5, 0))
	if err != nil {
		return nil, fmt.Errorf("0.5x failed: %w", err)
	}

	// -0.5x^2 + 0.5x
	result, err := o.eval.Add(term1, term2)
	if err != nil {
		return nil, fmt.Errorf("term1+term2 failed: %w", err)
	}

	// + 1
	result, err = o.eval.AddConst(result, complex(1, 0))
	if err != nil {
		return nil, fmt.Errorf("+1 failed: %w", err)
	}

	return result, nil
}

// PlaintextPercentile computes k-percentile from plaintext (for validation)
func PlaintextPercentile(values []int, valid []bool, k float64) int {
	// Collect valid values
	var validValues []int
	for i, v := range values {
		if valid[i] {
			validValues = append(validValues, v)
		}
	}

	if len(validValues) == 0 {
		return 0
	}

	// Sort
	sort.Ints(validValues)

	// Find k-th percentile
	idx := int(float64(len(validValues)) * k / 100.0)
	if idx >= len(validValues) {
		idx = len(validValues) - 1
	}
	if idx < 0 {
		idx = 0
	}

	return validValues[idx]
}

// PlaintextCumulativeHistogram computes cumulative histogram (for validation)
func PlaintextCumulativeHistogram(values []int, valid []bool, categories int) []int {
	// Count frequencies
	freq := make([]int, categories)
	for i, v := range values {
		if valid[i] && v >= 1 && v <= categories {
			freq[v-1]++
		}
	}

	// Cumulative
	cumul := make([]int, categories)
	cumul[0] = freq[0]
	for i := 1; i < categories; i++ {
		cumul[i] = cumul[i-1] + freq[i]
	}

	return cumul
}
