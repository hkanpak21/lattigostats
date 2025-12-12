// Package numeric implements numerical statistical operations:
// mean, variance, stdev, correlation, and INVNTHSQRT.
package numeric

import (
	"fmt"
	"math"

	"github.com/hkanpak21/lattigostats/pkg/he"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// NumericOp computes numerical statistics on encrypted data
type NumericOp struct {
	eval *he.Evaluator
}

// NewNumericOp creates a new numeric operations handler
func NewNumericOp(eval *he.Evaluator) *NumericOp {
	return &NumericOp{eval: eval}
}

// MaskedSum computes sum(x * v) across blocks
// x: data blocks, v: validity/mask blocks
func (n *NumericOp) MaskedSum(xBlocks, vBlocks []*rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	if len(xBlocks) != len(vBlocks) {
		return nil, fmt.Errorf("block count mismatch: %d vs %d", len(xBlocks), len(vBlocks))
	}
	if len(xBlocks) == 0 {
		return nil, fmt.Errorf("no blocks provided")
	}

	var result *rlwe.Ciphertext
	for i := range xBlocks {
		// Multiply x * v
		masked, err := n.eval.Mul(xBlocks[i], vBlocks[i])
		if err != nil {
			return nil, fmt.Errorf("block %d mul failed: %w", i, err)
		}
		masked, err = n.eval.Rescale(masked)
		if err != nil {
			return nil, fmt.Errorf("block %d rescale failed: %w", i, err)
		}

		if result == nil {
			result = masked
		} else {
			err = n.eval.AddInPlace(result, masked)
			if err != nil {
				return nil, fmt.Errorf("block %d add failed: %w", i, err)
			}
		}
	}

	// Sum across slots
	return n.eval.SumSlots(result)
}

// Count computes sum(v) - the count of valid entries
func (n *NumericOp) Count(vBlocks []*rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	if len(vBlocks) == 0 {
		return nil, fmt.Errorf("no blocks provided")
	}

	var result *rlwe.Ciphertext
	for i, v := range vBlocks {
		if result == nil {
			result = v.CopyNew()
		} else {
			err := n.eval.AddInPlace(result, v)
			if err != nil {
				return nil, fmt.Errorf("block %d add failed: %w", i, err)
			}
		}
	}

	// Sum across slots
	return n.eval.SumSlots(result)
}

// MaskedSumOfSquares computes sum(x^2 * v)
func (n *NumericOp) MaskedSumOfSquares(xBlocks, vBlocks []*rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	if len(xBlocks) != len(vBlocks) {
		return nil, fmt.Errorf("block count mismatch")
	}
	if len(xBlocks) == 0 {
		return nil, fmt.Errorf("no blocks provided")
	}

	var result *rlwe.Ciphertext
	for i := range xBlocks {
		// Compute x^2
		xSquared, err := n.eval.Mul(xBlocks[i], xBlocks[i])
		if err != nil {
			return nil, fmt.Errorf("block %d square failed: %w", i, err)
		}
		xSquared, err = n.eval.Rescale(xSquared)
		if err != nil {
			return nil, fmt.Errorf("block %d rescale1 failed: %w", i, err)
		}

		// Multiply by validity
		masked, err := n.eval.Mul(xSquared, vBlocks[i])
		if err != nil {
			return nil, fmt.Errorf("block %d mask failed: %w", i, err)
		}
		masked, err = n.eval.Rescale(masked)
		if err != nil {
			return nil, fmt.Errorf("block %d rescale2 failed: %w", i, err)
		}

		if result == nil {
			result = masked
		} else {
			err = n.eval.AddInPlace(result, masked)
			if err != nil {
				return nil, fmt.Errorf("block %d add failed: %w", i, err)
			}
		}
	}

	return n.eval.SumSlots(result)
}

// INVNTHSQRTConfig configures the inverse n-th root computation
type INVNTHSQRTConfig struct {
	N                  int     // Root power (1 for inverse, 2 for inverse sqrt)
	Iterations         int     // Newton iterations
	BootstrapFrequency int     // Bootstrap every N iterations (0 = never)
	InitialGuess       float64 // Initial y0 value
}

// DefaultINVConfig returns default config for inverse (n=1)
func DefaultINVConfig() INVNTHSQRTConfig {
	return INVNTHSQRTConfig{
		N:                  1,
		Iterations:         25,
		BootstrapFrequency: 5,
		InitialGuess:       0.5,
	}
}

// DefaultINVSQRTConfig returns default config for inverse sqrt (n=2)
func DefaultINVSQRTConfig() INVNTHSQRTConfig {
	return INVNTHSQRTConfig{
		N:                  2,
		Iterations:         21,
		BootstrapFrequency: 5,
		InitialGuess:       0.5,
	}
}

// INVNTHSQRT computes x^(-1/n) using Newton iteration
// For n=1: computes 1/x
// For n=2: computes 1/sqrt(x)
// Iteration: y <- (y * ((n+1) - x * y^n)) / n
func (n *NumericOp) INVNTHSQRT(x *rlwe.Ciphertext, config INVNTHSQRTConfig) (*rlwe.Ciphertext, error) {
	if config.N < 1 {
		return nil, fmt.Errorf("n must be positive")
	}

	// Bootstrap x if needed at start
	var err error
	x, err = n.eval.MaybeBootstrap(x)
	if err != nil {
		return nil, fmt.Errorf("initial bootstrap failed: %w", err)
	}

	// Initialize y with constant
	nPlusOne := float64(config.N + 1)
	nFloat := float64(config.N)
	invN := 1.0 / nFloat

	// Initialize y as a ciphertext containing the initial guess in all slots
	// Method: Create a zero ciphertext from x, then add the constant
	yCt := n.eval.ZeroCiphertextLike(x)
	yCt, err = n.eval.AddConst(yCt, complex(config.InitialGuess, 0))
	if err != nil {
		return nil, fmt.Errorf("initial y setup failed: %w", err)
	}

	// Newton iteration
	for iter := 0; iter < config.Iterations; iter++ {
		// Maybe bootstrap
		if config.BootstrapFrequency > 0 && iter > 0 && iter%config.BootstrapFrequency == 0 {
			if n.eval.NeedsBootstrap(yCt) {
				yCt, err = n.eval.Bootstrap(yCt)
				if err != nil {
					return nil, fmt.Errorf("iteration %d bootstrap failed: %w", iter, err)
				}
			}
		}

		// Compute y^n
		var yN *rlwe.Ciphertext
		if config.N == 1 {
			yN = yCt.CopyNew()
		} else {
			yN, err = n.eval.Power(yCt, config.N)
			if err != nil {
				return nil, fmt.Errorf("iteration %d power failed: %w", iter, err)
			}
		}

		// Compute x * y^n
		xyN, err := n.eval.Mul(x, yN)
		if err != nil {
			return nil, fmt.Errorf("iteration %d mul x*yN failed: %w", iter, err)
		}
		xyN, err = n.eval.Rescale(xyN)
		if err != nil {
			return nil, fmt.Errorf("iteration %d rescale failed: %w", iter, err)
		}
		// Bootstrap after rescale if needed
		xyN, err = n.eval.MaybeBootstrap(xyN)
		if err != nil {
			return nil, fmt.Errorf("iteration %d bootstrap xyN failed: %w", iter, err)
		}

		// Compute (n+1) - x*y^n
		diff, err := n.eval.AddConst(xyN, complex(-nPlusOne, 0))
		if err != nil {
			return nil, fmt.Errorf("iteration %d sub failed: %w", iter, err)
		}
		// Negate: we want (n+1) - x*y^n = -((x*y^n) - (n+1))
		diff, err = n.eval.MulConst(diff, -1)
		if err != nil {
			return nil, fmt.Errorf("iteration %d negate failed: %w", iter, err)
		}

		// Compute y * ((n+1) - x*y^n)
		yNew, err := n.eval.Mul(yCt, diff)
		if err != nil {
			return nil, fmt.Errorf("iteration %d mul y*diff failed: %w", iter, err)
		}
		yNew, err = n.eval.Rescale(yNew)
		if err != nil {
			return nil, fmt.Errorf("iteration %d final rescale failed: %w", iter, err)
		}
		// Bootstrap after final rescale if needed
		yNew, err = n.eval.MaybeBootstrap(yNew)
		if err != nil {
			return nil, fmt.Errorf("iteration %d bootstrap yNew failed: %w", iter, err)
		}

		// Divide by n: y = y * ((n+1) - x*y^n) / n
		yCt, err = n.eval.MulConst(yNew, complex(invN, 0))
		if err != nil {
			return nil, fmt.Errorf("iteration %d div by n failed: %w", iter, err)
		}
	}

	return yCt, nil
}

// Mean computes the mean of x given validity mask v
// mean = sum(x * v) / sum(v)
func (n *NumericOp) Mean(xBlocks, vBlocks []*rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	// Compute sum(x * v)
	sumXV, err := n.MaskedSum(xBlocks, vBlocks)
	if err != nil {
		return nil, fmt.Errorf("masked sum failed: %w", err)
	}

	// Compute count = sum(v)
	count, err := n.Count(vBlocks)
	if err != nil {
		return nil, fmt.Errorf("count failed: %w", err)
	}

	// Compute 1/count using INVNTHSQRT
	invCount, err := n.INVNTHSQRT(count, DefaultINVConfig())
	if err != nil {
		return nil, fmt.Errorf("inverse count failed: %w", err)
	}

	// mean = sum * invCount
	mean, err := n.eval.Mul(sumXV, invCount)
	if err != nil {
		return nil, fmt.Errorf("mean mul failed: %w", err)
	}
	return n.eval.Rescale(mean)
}

// Variance computes the variance of x given validity mask v
// var = sum((x - mean)^2 * v) / sum(v)
//
//	= sum(x^2 * v) / sum(v) - mean^2
func (n *NumericOp) Variance(xBlocks, vBlocks []*rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	// Compute mean first
	mean, err := n.Mean(xBlocks, vBlocks)
	if err != nil {
		return nil, fmt.Errorf("mean failed: %w", err)
	}

	// Compute sum(x^2 * v)
	sumX2V, err := n.MaskedSumOfSquares(xBlocks, vBlocks)
	if err != nil {
		return nil, fmt.Errorf("sum of squares failed: %w", err)
	}

	// Compute count
	count, err := n.Count(vBlocks)
	if err != nil {
		return nil, fmt.Errorf("count failed: %w", err)
	}

	// Compute 1/count
	invCount, err := n.INVNTHSQRT(count, DefaultINVConfig())
	if err != nil {
		return nil, fmt.Errorf("inverse count failed: %w", err)
	}

	// E[X^2] = sum(x^2 * v) / count
	eX2, err := n.eval.Mul(sumX2V, invCount)
	if err != nil {
		return nil, fmt.Errorf("E[X^2] mul failed: %w", err)
	}
	eX2, err = n.eval.Rescale(eX2)
	if err != nil {
		return nil, fmt.Errorf("E[X^2] rescale failed: %w", err)
	}

	// mean^2
	meanSq, err := n.eval.Mul(mean, mean)
	if err != nil {
		return nil, fmt.Errorf("mean^2 failed: %w", err)
	}
	meanSq, err = n.eval.Rescale(meanSq)
	if err != nil {
		return nil, fmt.Errorf("mean^2 rescale failed: %w", err)
	}

	// var = E[X^2] - E[X]^2
	variance, err := n.eval.Sub(eX2, meanSq)
	if err != nil {
		return nil, fmt.Errorf("variance sub failed: %w", err)
	}

	return variance, nil
}

// Stdev computes the standard deviation (sqrt of variance)
func (n *NumericOp) Stdev(xBlocks, vBlocks []*rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	// Compute variance
	variance, err := n.Variance(xBlocks, vBlocks)
	if err != nil {
		return nil, fmt.Errorf("variance failed: %w", err)
	}

	// Compute 1/sqrt(var) then invert using multiplication
	// Actually, stdev = sqrt(var) = var * (1/sqrt(var)) is circular
	// We need: stdev = sqrt(var)
	// Use: 1/sqrt(var) via INVNTHSQRT with n=2, then compute var * (1/sqrt(var)) = sqrt(var)
	invSqrt, err := n.INVNTHSQRT(variance, DefaultINVSQRTConfig())
	if err != nil {
		return nil, fmt.Errorf("inv sqrt variance failed: %w", err)
	}

	// stdev = var * (1/sqrt(var)) = sqrt(var)
	stdev, err := n.eval.Mul(variance, invSqrt)
	if err != nil {
		return nil, fmt.Errorf("stdev mul failed: %w", err)
	}
	return n.eval.Rescale(stdev)
}

// MaskedCrossSum computes sum(x * y * v)
func (n *NumericOp) MaskedCrossSum(xBlocks, yBlocks, vBlocks []*rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	if len(xBlocks) != len(yBlocks) || len(xBlocks) != len(vBlocks) {
		return nil, fmt.Errorf("block count mismatch")
	}
	if len(xBlocks) == 0 {
		return nil, fmt.Errorf("no blocks provided")
	}

	var result *rlwe.Ciphertext
	for i := range xBlocks {
		// Compute x * y
		xy, err := n.eval.Mul(xBlocks[i], yBlocks[i])
		if err != nil {
			return nil, fmt.Errorf("block %d xy mul failed: %w", i, err)
		}
		xy, err = n.eval.Rescale(xy)
		if err != nil {
			return nil, fmt.Errorf("block %d xy rescale failed: %w", i, err)
		}

		// Multiply by validity
		masked, err := n.eval.Mul(xy, vBlocks[i])
		if err != nil {
			return nil, fmt.Errorf("block %d mask failed: %w", i, err)
		}
		masked, err = n.eval.Rescale(masked)
		if err != nil {
			return nil, fmt.Errorf("block %d masked rescale failed: %w", i, err)
		}

		if result == nil {
			result = masked
		} else {
			err = n.eval.AddInPlace(result, masked)
			if err != nil {
				return nil, fmt.Errorf("block %d add failed: %w", i, err)
			}
		}
	}

	return n.eval.SumSlots(result)
}

// Correlation computes Pearson correlation between x and y
// corr = cov(x,y) / (stdev(x) * stdev(y))
// cov(x,y) = E[XY] - E[X]*E[Y]
func (n *NumericOp) Correlation(xBlocks, yBlocks, vBlocks []*rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	// Compute means
	meanX, err := n.Mean(xBlocks, vBlocks)
	if err != nil {
		return nil, fmt.Errorf("mean x failed: %w", err)
	}
	meanY, err := n.Mean(yBlocks, vBlocks)
	if err != nil {
		return nil, fmt.Errorf("mean y failed: %w", err)
	}

	// Compute E[XY]
	sumXY, err := n.MaskedCrossSum(xBlocks, yBlocks, vBlocks)
	if err != nil {
		return nil, fmt.Errorf("sum xy failed: %w", err)
	}
	count, err := n.Count(vBlocks)
	if err != nil {
		return nil, fmt.Errorf("count failed: %w", err)
	}
	invCount, err := n.INVNTHSQRT(count, DefaultINVConfig())
	if err != nil {
		return nil, fmt.Errorf("inv count failed: %w", err)
	}
	eXY, err := n.eval.Mul(sumXY, invCount)
	if err != nil {
		return nil, fmt.Errorf("E[XY] mul failed: %w", err)
	}
	eXY, err = n.eval.Rescale(eXY)
	if err != nil {
		return nil, fmt.Errorf("E[XY] rescale failed: %w", err)
	}

	// Compute E[X]*E[Y]
	eXeY, err := n.eval.Mul(meanX, meanY)
	if err != nil {
		return nil, fmt.Errorf("E[X]*E[Y] failed: %w", err)
	}
	eXeY, err = n.eval.Rescale(eXeY)
	if err != nil {
		return nil, fmt.Errorf("E[X]*E[Y] rescale failed: %w", err)
	}

	// cov = E[XY] - E[X]*E[Y]
	cov, err := n.eval.Sub(eXY, eXeY)
	if err != nil {
		return nil, fmt.Errorf("cov sub failed: %w", err)
	}

	// Compute variances
	varX, err := n.Variance(xBlocks, vBlocks)
	if err != nil {
		return nil, fmt.Errorf("var x failed: %w", err)
	}
	varY, err := n.Variance(yBlocks, vBlocks)
	if err != nil {
		return nil, fmt.Errorf("var y failed: %w", err)
	}

	// Compute 1/sqrt(varX) and 1/sqrt(varY)
	invSqrtVarX, err := n.INVNTHSQRT(varX, DefaultINVSQRTConfig())
	if err != nil {
		return nil, fmt.Errorf("inv sqrt var x failed: %w", err)
	}
	invSqrtVarY, err := n.INVNTHSQRT(varY, DefaultINVSQRTConfig())
	if err != nil {
		return nil, fmt.Errorf("inv sqrt var y failed: %w", err)
	}

	// corr = cov * (1/stdevX) * (1/stdevY) = cov * invSqrtVarX * invSqrtVarY
	corr, err := n.eval.Mul(cov, invSqrtVarX)
	if err != nil {
		return nil, fmt.Errorf("corr mul1 failed: %w", err)
	}
	corr, err = n.eval.Rescale(corr)
	if err != nil {
		return nil, fmt.Errorf("corr rescale1 failed: %w", err)
	}
	corr, err = n.eval.Mul(corr, invSqrtVarY)
	if err != nil {
		return nil, fmt.Errorf("corr mul2 failed: %w", err)
	}
	corr, err = n.eval.Rescale(corr)
	if err != nil {
		return nil, fmt.Errorf("corr rescale2 failed: %w", err)
	}

	return corr, nil
}

// PlaintextMean computes mean from plaintext values (for validation)
func PlaintextMean(values []float64, valid []bool) float64 {
	var sum float64
	var count int
	for i, v := range values {
		if valid[i] {
			sum += v
			count++
		}
	}
	if count == 0 {
		return 0
	}
	return sum / float64(count)
}

// PlaintextVariance computes variance from plaintext values (for validation)
func PlaintextVariance(values []float64, valid []bool) float64 {
	mean := PlaintextMean(values, valid)
	var sumSq float64
	var count int
	for i, v := range values {
		if valid[i] {
			diff := v - mean
			sumSq += diff * diff
			count++
		}
	}
	if count == 0 {
		return 0
	}
	return sumSq / float64(count)
}

// PlaintextStdev computes standard deviation from plaintext values
func PlaintextStdev(values []float64, valid []bool) float64 {
	return math.Sqrt(PlaintextVariance(values, valid))
}

// PlaintextCorrelation computes Pearson correlation from plaintext values
func PlaintextCorrelation(x, y []float64, valid []bool) float64 {
	meanX := PlaintextMean(x, valid)
	meanY := PlaintextMean(y, valid)

	var sumXY, sumX2, sumY2 float64
	var count int
	for i := range x {
		if valid[i] {
			dx := x[i] - meanX
			dy := y[i] - meanY
			sumXY += dx * dy
			sumX2 += dx * dx
			sumY2 += dy * dy
			count++
		}
	}
	if count == 0 || sumX2 == 0 || sumY2 == 0 {
		return 0
	}
	return sumXY / (math.Sqrt(sumX2) * math.Sqrt(sumY2))
}
