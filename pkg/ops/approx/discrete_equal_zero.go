// Package approx implements approximation functions for HE:
// DISCRETEEQUALZERO (equality check), APPROXSIGN (sign function),
// and table lookup using polynomial approximations.
package approx

import (
	"fmt"
	"math"

	"github.com/hkanpak21/lattigostats/pkg/he"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// ApproxOp provides approximate HE operations
type ApproxOp struct {
	eval *he.Evaluator
}

// NewApproxOp creates a new approximation operations handler
func NewApproxOp(eval *he.Evaluator) *ApproxOp {
	return &ApproxOp{eval: eval}
}

// DEZConfig configures DISCRETEEQUALZERO
type DEZConfig struct {
	Sf      int     // Number of categories (determines normalization)
	K       int     // Precision parameter (number of sinc iterations)
	FilterP float64 // Filter polynomial exponent
}

// DefaultDEZConfig returns default DEZ configuration
func DefaultDEZConfig(Sf int) DEZConfig {
	d := int(math.Ceil(math.Log2(float64(Sf))))
	k := 2 * d // heuristic from paper
	return DEZConfig{
		Sf:      Sf,
		K:       k,
		FilterP: 4, // p(s) = 4s^3 - 3s^4
	}
}

// ChebyshevCoeffs stores precomputed Chebyshev coefficients
type ChebyshevCoeffs struct {
	Coeffs []float64
	Degree int
}

// ComputeCosCoeffs computes Chebyshev coefficients for cos(πx) on [-1,1]
func ComputeCosCoeffs(degree int) *ChebyshevCoeffs {
	coeffs := make([]float64, degree+1)

	// cos(πx) Chebyshev expansion
	// We'll use the truncated Taylor/Chebyshev series
	// cos(πx) ≈ Σ c_k T_k(x)
	n := degree + 1
	for k := 0; k <= degree; k++ {
		sum := 0.0
		for j := 0; j < n; j++ {
			x := math.Cos(math.Pi * (float64(j) + 0.5) / float64(n))
			fx := math.Cos(math.Pi * x)
			Tk := math.Cos(float64(k) * math.Acos(x))
			sum += fx * Tk
		}
		coeffs[k] = 2.0 * sum / float64(n)
		if k == 0 {
			coeffs[k] /= 2.0
		}
	}

	return &ChebyshevCoeffs{Coeffs: coeffs, Degree: degree}
}

// ComputeSincCoeffs computes Chebyshev coefficients for sinc(x) = sin(πx)/(πx)
func ComputeSincCoeffs(degree int) *ChebyshevCoeffs {
	coeffs := make([]float64, degree+1)

	n := degree + 1
	for k := 0; k <= degree; k++ {
		sum := 0.0
		for j := 0; j < n; j++ {
			x := math.Cos(math.Pi * (float64(j) + 0.5) / float64(n))
			var fx float64
			if math.Abs(x) < 1e-10 {
				fx = 1.0 // sinc(0) = 1
			} else {
				fx = math.Sin(math.Pi*x) / (math.Pi * x)
			}
			Tk := math.Cos(float64(k) * math.Acos(x))
			sum += fx * Tk
		}
		coeffs[k] = 2.0 * sum / float64(n)
		if k == 0 {
			coeffs[k] /= 2.0
		}
	}

	return &ChebyshevCoeffs{Coeffs: coeffs, Degree: degree}
}

// EvaluateChebyshev evaluates a Chebyshev polynomial on a ciphertext
// Uses standard polynomial form converted from Chebyshev coefficients
func (a *ApproxOp) EvaluateChebyshev(x *rlwe.Ciphertext, coeffs *ChebyshevCoeffs) (*rlwe.Ciphertext, error) {
	if coeffs.Degree == 0 {
		return a.eval.AddConst(x, complex(coeffs.Coeffs[0], 0))
	}

	// Build power cache: x^1, x^2, ..., x^degree using binary powering
	powers := make([]*rlwe.Ciphertext, coeffs.Degree+1)
	powers[1] = x.CopyNew()

	for i := 2; i <= coeffs.Degree; i++ {
		var err error
		if i%2 == 0 {
			// x^i = x^(i/2) * x^(i/2)
			half := i / 2
			powers[i], err = a.eval.Mul(powers[half], powers[half])
			if err != nil {
				return nil, fmt.Errorf("power %d mul failed: %w", i, err)
			}
		} else {
			// x^i = x^(i-1) * x
			powers[i], err = a.eval.Mul(powers[i-1], powers[1])
			if err != nil {
				return nil, fmt.Errorf("power %d mul failed: %w", i, err)
			}
		}
		powers[i], err = a.eval.Rescale(powers[i])
		if err != nil {
			return nil, fmt.Errorf("power %d rescale failed: %w", i, err)
		}

		// Bootstrap if needed
		powers[i], err = a.eval.MaybeBootstrap(powers[i])
		if err != nil {
			return nil, fmt.Errorf("power %d bootstrap failed: %w", i, err)
		}
	}

	// Convert Chebyshev to standard polynomial form
	stdCoeffs := chebyshevToStandard(coeffs.Coeffs)

	// Evaluate: c_0 + c_1*x + c_2*x^2 + ...
	// Start with c_1*x (first non-constant term)
	var result *rlwe.Ciphertext
	for k := 1; k < len(stdCoeffs); k++ {
		if math.Abs(stdCoeffs[k]) < 1e-15 {
			continue
		}
		term, err := a.eval.MulConst(powers[k], complex(stdCoeffs[k], 0))
		if err != nil {
			return nil, fmt.Errorf("term %d mul const failed: %w", k, err)
		}

		if result == nil {
			result = term
		} else {
			err = a.eval.AddInPlace(result, term)
			if err != nil {
				return nil, fmt.Errorf("term %d add failed: %w", k, err)
			}
		}
	}

	// Add constant term c_0
	if result == nil {
		// No non-constant terms, just return constant
		return a.eval.AddConst(x, complex(stdCoeffs[0]-1, 0))
	}
	return a.eval.AddConst(result, complex(stdCoeffs[0], 0))
}

// chebyshevToStandard converts Chebyshev coefficients to standard polynomial
func chebyshevToStandard(cheb []float64) []float64 {
	n := len(cheb)
	if n == 0 {
		return []float64{}
	}

	// T_0 = 1
	// T_1 = x
	// T_n = 2xT_{n-1} - T_{n-2}
	// Build matrix and solve

	std := make([]float64, n)

	// Simple approach: use recursion for T_k
	// T_k expressed in x^j coefficients
	T := make([][]float64, n)
	for k := range T {
		T[k] = make([]float64, n)
	}

	// T_0 = 1
	T[0][0] = 1
	if n > 1 {
		// T_1 = x
		T[1][1] = 1
	}

	// T_k = 2x*T_{k-1} - T_{k-2}
	for k := 2; k < n; k++ {
		for j := 0; j < n; j++ {
			if j > 0 {
				T[k][j] += 2 * T[k-1][j-1]
			}
			T[k][j] -= T[k-2][j]
		}
	}

	// std = Σ cheb[k] * T[k]
	for k := 0; k < n; k++ {
		for j := 0; j < n; j++ {
			std[j] += cheb[k] * T[k][j]
		}
	}

	return std
}

// DISCRETEEQUALZERO computes an indicator function: ~1 if x==0 (integer), ~0 otherwise
// Based on the paper's sinc-based approach with filtering
func (a *ApproxOp) DISCRETEEQUALZERO(x *rlwe.Ciphertext, config DEZConfig) (*rlwe.Ciphertext, error) {
	// Step 1: Normalize x -> x / 2^d where d = ceil(log2(Sf))
	d := int(math.Ceil(math.Log2(float64(config.Sf))))
	scale := 1.0 / math.Pow(2, float64(d))

	normalized, err := a.eval.MulConst(x, complex(scale, 0))
	if err != nil {
		return nil, fmt.Errorf("normalize failed: %w", err)
	}

	// Bootstrap before expensive computation
	normalized, err = a.eval.MaybeBootstrap(normalized)
	if err != nil {
		return nil, fmt.Errorf("normalize bootstrap failed: %w", err)
	}

	// Step 2: Compute sinc approximation using cos double-angle recursion
	// sinc(x) = sin(πx)/(πx) ≈ product of cos terms via double-angle
	// Or use Chebyshev approximation directly

	// For simplicity, use Chebyshev polynomial approximation of sinc
	sincCoeffs := ComputeSincCoeffs(16) // degree 16 approximation

	sinc, err := a.EvaluateChebyshev(normalized, sincCoeffs)
	if err != nil {
		return nil, fmt.Errorf("sinc eval failed: %w", err)
	}

	// Step 3: Apply sinc^K to sharpen the peak
	result := sinc
	for i := 1; i < config.K; i++ {
		result, err = a.eval.Mul(result, sinc)
		if err != nil {
			return nil, fmt.Errorf("sinc^%d mul failed: %w", i+1, err)
		}
		result, err = a.eval.Rescale(result)
		if err != nil {
			return nil, fmt.Errorf("sinc^%d rescale failed: %w", i+1, err)
		}
		result, err = a.eval.MaybeBootstrap(result)
		if err != nil {
			return nil, fmt.Errorf("sinc^%d bootstrap failed: %w", i+1, err)
		}
	}

	// Step 4: Apply filter polynomial p(s) = 4s^3 - 3s^4 to map to [0,1]
	// This sharpens the indicator
	result, err = a.ApplyFilterPolynomial(result)
	if err != nil {
		return nil, fmt.Errorf("filter failed: %w", err)
	}

	return result, nil
}

// ApplyFilterPolynomial applies p(s) = 4s^3 - 3s^4
func (a *ApproxOp) ApplyFilterPolynomial(s *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	// p(s) = 4s^3 - 3s^4 = s^3 * (4 - 3s)

	// Compute s^2
	s2, err := a.eval.Mul(s, s)
	if err != nil {
		return nil, fmt.Errorf("s^2 failed: %w", err)
	}
	s2, err = a.eval.Rescale(s2)
	if err != nil {
		return nil, fmt.Errorf("s^2 rescale failed: %w", err)
	}

	// Compute s^3 = s^2 * s
	s3, err := a.eval.Mul(s2, s)
	if err != nil {
		return nil, fmt.Errorf("s^3 failed: %w", err)
	}
	s3, err = a.eval.Rescale(s3)
	if err != nil {
		return nil, fmt.Errorf("s^3 rescale failed: %w", err)
	}

	// Compute 4 - 3s
	neg3s, err := a.eval.MulConst(s, complex(-3, 0))
	if err != nil {
		return nil, fmt.Errorf("-3s failed: %w", err)
	}
	fourMinus3s, err := a.eval.AddConst(neg3s, complex(4, 0))
	if err != nil {
		return nil, fmt.Errorf("4-3s failed: %w", err)
	}

	// Result = s^3 * (4 - 3s)
	result, err := a.eval.Mul(s3, fourMinus3s)
	if err != nil {
		return nil, fmt.Errorf("final mul failed: %w", err)
	}
	return a.eval.Rescale(result)
}

// ApproxSignConfig configures the approximate sign function
type ApproxSignConfig struct {
	Degree     int // Polynomial degree for approximation
	Iterations int // Refinement iterations
}

// DefaultApproxSignConfig returns default APPROXSIGN configuration
func DefaultApproxSignConfig() ApproxSignConfig {
	return ApproxSignConfig{
		Degree:     15,
		Iterations: 3,
	}
}

// APPROXSIGN computes an approximate sign function
// Returns ~-1 for x < 0, ~0 for x ≈ 0, ~+1 for x > 0
func (a *ApproxOp) APPROXSIGN(x *rlwe.Ciphertext, config ApproxSignConfig) (*rlwe.Ciphertext, error) {
	// Use polynomial approximation of sign function
	// A common approach: iterate s <- s * (3 - s^2) / 2 starting from x/||x||

	// For bounded input [-1, 1], we can use Chebyshev approximation of sign
	result := x.CopyNew()

	// Iterative refinement: s_{n+1} = s_n * (3 - s_n^2) / 2
	for i := 0; i < config.Iterations; i++ {
		// s^2
		s2, err := a.eval.Mul(result, result)
		if err != nil {
			return nil, fmt.Errorf("iter %d s^2 failed: %w", i, err)
		}
		s2, err = a.eval.Rescale(s2)
		if err != nil {
			return nil, fmt.Errorf("iter %d s^2 rescale failed: %w", i, err)
		}

		// 3 - s^2
		threeMinusS2, err := a.eval.MulConst(s2, complex(-1, 0))
		if err != nil {
			return nil, fmt.Errorf("iter %d -s^2 failed: %w", i, err)
		}
		threeMinusS2, err = a.eval.AddConst(threeMinusS2, complex(3, 0))
		if err != nil {
			return nil, fmt.Errorf("iter %d 3-s^2 failed: %w", i, err)
		}

		// s * (3 - s^2)
		result, err = a.eval.Mul(result, threeMinusS2)
		if err != nil {
			return nil, fmt.Errorf("iter %d mul failed: %w", i, err)
		}
		result, err = a.eval.Rescale(result)
		if err != nil {
			return nil, fmt.Errorf("iter %d rescale failed: %w", i, err)
		}

		// / 2
		result, err = a.eval.MulConst(result, complex(0.5, 0))
		if err != nil {
			return nil, fmt.Errorf("iter %d /2 failed: %w", i, err)
		}

		// Bootstrap if needed
		result, err = a.eval.MaybeBootstrap(result)
		if err != nil {
			return nil, fmt.Errorf("iter %d bootstrap failed: %w", i, err)
		}
	}

	return result, nil
}

// COMP computes approximate comparison: returns ~1 if x1 > x2, ~0.5 if equal, ~0 otherwise
func (a *ApproxOp) COMP(x1, x2 *rlwe.Ciphertext, config ApproxSignConfig) (*rlwe.Ciphertext, error) {
	// diff = x1 - x2
	diff, err := a.eval.Sub(x1, x2)
	if err != nil {
		return nil, fmt.Errorf("diff failed: %w", err)
	}

	// sign(diff): -1, 0, or 1
	sign, err := a.APPROXSIGN(diff, config)
	if err != nil {
		return nil, fmt.Errorf("approxsign failed: %w", err)
	}

	// Map to [0, 1]: (sign + 1) / 2
	result, err := a.eval.AddConst(sign, complex(1, 0))
	if err != nil {
		return nil, fmt.Errorf("shift failed: %w", err)
	}
	result, err = a.eval.MulConst(result, complex(0.5, 0))
	if err != nil {
		return nil, fmt.Errorf("scale failed: %w", err)
	}

	return result, nil
}

// TableLookup selects rows where categorical == value using DISCRETEEQUALZERO
func (a *ApproxOp) TableLookup(
	catBlocks []*rlwe.Ciphertext,
	value int,
	targetBlocks []*rlwe.Ciphertext,
	config DEZConfig,
) ([]*rlwe.Ciphertext, error) {
	results := make([]*rlwe.Ciphertext, len(catBlocks))

	for i := range catBlocks {
		// Compute cat - value
		shifted, err := a.eval.AddConst(catBlocks[i], complex(float64(-value), 0))
		if err != nil {
			return nil, fmt.Errorf("block %d shift failed: %w", i, err)
		}

		// Compute equality indicator
		eq, err := a.DISCRETEEQUALZERO(shifted, config)
		if err != nil {
			return nil, fmt.Errorf("block %d DEZ failed: %w", i, err)
		}

		// Multiply by target
		results[i], err = a.eval.Mul(eq, targetBlocks[i])
		if err != nil {
			return nil, fmt.Errorf("block %d mul failed: %w", i, err)
		}
		results[i], err = a.eval.Rescale(results[i])
		if err != nil {
			return nil, fmt.Errorf("block %d rescale failed: %w", i, err)
		}
	}

	return results, nil
}

// PlaintextDEZ computes discrete equality to zero (for validation)
func PlaintextDEZ(x float64, Sf int) float64 {
	// Returns 1 if x rounds to 0, 0 otherwise
	if math.Abs(x) < 0.5 {
		return 1.0
	}
	return 0.0
}

// PlaintextSign computes sign function (for validation)
func PlaintextSign(x float64) float64 {
	if x > 0 {
		return 1.0
	} else if x < 0 {
		return -1.0
	}
	return 0.0
}
