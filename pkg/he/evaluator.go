// Package he provides a thin wrapper around Lattigo's CKKS evaluator, encoder,
// and bootstrapper with level tracking and profiling support.
package he

import (
	"fmt"
	"sync"
	"time"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// Stats tracks HE operation statistics
type Stats struct {
	mu             sync.Mutex
	MulCount       int64
	AddCount       int64
	RotateCount    int64
	RescaleCount   int64
	BootstrapCount int64
	MulTime        time.Duration
	AddTime        time.Duration
	RotateTime     time.Duration
	RescaleTime    time.Duration
	BootstrapTime  time.Duration
}

// Reset resets all statistics
func (s *Stats) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.MulCount = 0
	s.AddCount = 0
	s.RotateCount = 0
	s.RescaleCount = 0
	s.BootstrapCount = 0
	s.MulTime = 0
	s.AddTime = 0
	s.RotateTime = 0
	s.RescaleTime = 0
	s.BootstrapTime = 0
}

// Evaluator wraps Lattigo's CKKS evaluator with level tracking and profiling
type Evaluator struct {
	params       ckks.Parameters
	encoder      *ckks.Encoder
	evaluator    *ckks.Evaluator
	bootstrapper *bootstrapping.Evaluator
	stats        *Stats
	minLevel     int // minimum level before bootstrap is needed
}

// NewEvaluator creates a new HE evaluator
func NewEvaluator(params ckks.Parameters, evk rlwe.EvaluationKeySet, btp *bootstrapping.Evaluator) (*Evaluator, error) {
	encoder := ckks.NewEncoder(params)
	evaluator := ckks.NewEvaluator(params, evk)

	minLevel := 2 // default minimum level
	if btp != nil {
		minLevel = btp.MinimumInputLevel()
	}

	return &Evaluator{
		params:       params,
		encoder:      encoder,
		evaluator:    evaluator,
		bootstrapper: btp,
		stats:        &Stats{},
		minLevel:     minLevel,
	}, nil
}

// Params returns the CKKS parameters
func (e *Evaluator) Params() ckks.Parameters {
	return e.params
}

// Encoder returns the CKKS encoder
func (e *Evaluator) Encoder() *ckks.Encoder {
	return e.encoder
}

// Stats returns the operation statistics
func (e *Evaluator) Stats() *Stats {
	return e.stats
}

// Slots returns the number of slots (N/2)
func (e *Evaluator) Slots() int {
	return e.params.MaxSlots()
}

// Level returns the current level of a ciphertext
func (e *Evaluator) Level(ct *rlwe.Ciphertext) int {
	return ct.Level()
}

// NeedsBootstrap returns true if the ciphertext needs bootstrapping
func (e *Evaluator) NeedsBootstrap(ct *rlwe.Ciphertext) bool {
	return ct.Level() <= e.minLevel
}

// CanBootstrap returns true if bootstrapping is available
func (e *Evaluator) CanBootstrap() bool {
	return e.bootstrapper != nil
}

// Bootstrap performs bootstrapping on a ciphertext
func (e *Evaluator) Bootstrap(ct *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	if e.bootstrapper == nil {
		return nil, fmt.Errorf("bootstrapping not available")
	}

	start := time.Now()
	result, err := e.bootstrapper.Bootstrap(ct)
	if err != nil {
		return nil, fmt.Errorf("bootstrap failed: %w", err)
	}

	e.stats.mu.Lock()
	e.stats.BootstrapCount++
	e.stats.BootstrapTime += time.Since(start)
	e.stats.mu.Unlock()

	return result, nil
}

// MaybeBootstrap bootstraps if needed, otherwise returns the original
func (e *Evaluator) MaybeBootstrap(ct *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	if e.NeedsBootstrap(ct) && e.CanBootstrap() {
		return e.Bootstrap(ct)
	}
	return ct, nil
}

// Add adds two ciphertexts
func (e *Evaluator) Add(op0, op1 *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	start := time.Now()
	result, err := e.evaluator.AddNew(op0, op1)
	if err != nil {
		return nil, fmt.Errorf("add failed: %w", err)
	}

	e.stats.mu.Lock()
	e.stats.AddCount++
	e.stats.AddTime += time.Since(start)
	e.stats.mu.Unlock()

	return result, nil
}

// AddInPlace adds op1 to op0 in place
func (e *Evaluator) AddInPlace(op0, op1 *rlwe.Ciphertext) error {
	start := time.Now()
	err := e.evaluator.Add(op0, op1, op0)
	if err != nil {
		return fmt.Errorf("add in place failed: %w", err)
	}

	e.stats.mu.Lock()
	e.stats.AddCount++
	e.stats.AddTime += time.Since(start)
	e.stats.mu.Unlock()

	return nil
}

// Sub subtracts op1 from op0
func (e *Evaluator) Sub(op0, op1 *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	start := time.Now()
	result, err := e.evaluator.SubNew(op0, op1)
	if err != nil {
		return nil, fmt.Errorf("sub failed: %w", err)
	}

	e.stats.mu.Lock()
	e.stats.AddCount++ // count as add operation
	e.stats.AddTime += time.Since(start)
	e.stats.mu.Unlock()

	return result, nil
}

// Mul multiplies two ciphertexts and relinearizes
func (e *Evaluator) Mul(op0, op1 *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	start := time.Now()
	result, err := e.evaluator.MulRelinNew(op0, op1)
	if err != nil {
		return nil, fmt.Errorf("mul failed: %w", err)
	}

	e.stats.mu.Lock()
	e.stats.MulCount++
	e.stats.MulTime += time.Since(start)
	e.stats.mu.Unlock()

	return result, nil
}

// MulPlaintext multiplies a ciphertext by a plaintext
func (e *Evaluator) MulPlaintext(ct *rlwe.Ciphertext, pt *rlwe.Plaintext) (*rlwe.Ciphertext, error) {
	start := time.Now()
	result, err := e.evaluator.MulNew(ct, pt)
	if err != nil {
		return nil, fmt.Errorf("mul plaintext failed: %w", err)
	}

	e.stats.mu.Lock()
	e.stats.MulCount++
	e.stats.MulTime += time.Since(start)
	e.stats.mu.Unlock()

	return result, nil
}

// MulConst multiplies a ciphertext by a constant
func (e *Evaluator) MulConst(ct *rlwe.Ciphertext, constant complex128) (*rlwe.Ciphertext, error) {
	start := time.Now()
	result := ct.CopyNew()
	err := e.evaluator.Mul(ct, constant, result)
	if err != nil {
		return nil, fmt.Errorf("mul const failed: %w", err)
	}

	e.stats.mu.Lock()
	e.stats.MulCount++
	e.stats.MulTime += time.Since(start)
	e.stats.mu.Unlock()

	return result, nil
}

// AddConst adds a constant to a ciphertext
func (e *Evaluator) AddConst(ct *rlwe.Ciphertext, constant complex128) (*rlwe.Ciphertext, error) {
	start := time.Now()
	result := ct.CopyNew()
	err := e.evaluator.Add(ct, constant, result)
	if err != nil {
		return nil, fmt.Errorf("add const failed: %w", err)
	}

	e.stats.mu.Lock()
	e.stats.AddCount++
	e.stats.AddTime += time.Since(start)
	e.stats.mu.Unlock()

	return result, nil
}

// Rescale rescales a ciphertext
func (e *Evaluator) Rescale(ct *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	start := time.Now()
	result := ct.CopyNew()
	err := e.evaluator.Rescale(ct, result)
	if err != nil {
		return nil, fmt.Errorf("rescale failed: %w", err)
	}

	e.stats.mu.Lock()
	e.stats.RescaleCount++
	e.stats.RescaleTime += time.Since(start)
	e.stats.mu.Unlock()

	return result, nil
}

// Rotate rotates a ciphertext by k positions
func (e *Evaluator) Rotate(ct *rlwe.Ciphertext, k int) (*rlwe.Ciphertext, error) {
	start := time.Now()
	result, err := e.evaluator.RotateNew(ct, k)
	if err != nil {
		return nil, fmt.Errorf("rotate by %d failed: %w", k, err)
	}

	e.stats.mu.Lock()
	e.stats.RotateCount++
	e.stats.RotateTime += time.Since(start)
	e.stats.mu.Unlock()

	return result, nil
}

// SumSlots sums all slots into slot 0 using rotations
func (e *Evaluator) SumSlots(ct *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	result := ct.CopyNew()
	slots := e.Slots()

	for rot := 1; rot < slots; rot *= 2 {
		rotated, err := e.Rotate(result, rot)
		if err != nil {
			return nil, fmt.Errorf("sum slots rotation failed: %w", err)
		}
		err = e.AddInPlace(result, rotated)
		if err != nil {
			return nil, fmt.Errorf("sum slots add failed: %w", err)
		}
	}

	return result, nil
}

// EncodePlaintext encodes a slice of complex values into a plaintext
func (e *Evaluator) EncodePlaintext(values []complex128, level int, scale rlwe.Scale) *rlwe.Plaintext {
	pt := ckks.NewPlaintext(e.params, level)
	pt.Scale = scale
	e.encoder.Encode(values, pt)
	return pt
}

// EncodeFloats encodes a slice of float64 values into a plaintext
func (e *Evaluator) EncodeFloats(values []float64, level int, scale rlwe.Scale) *rlwe.Plaintext {
	cvals := make([]complex128, len(values))
	for i, v := range values {
		cvals[i] = complex(v, 0)
	}
	return e.EncodePlaintext(cvals, level, scale)
}

// EncodeConstant encodes a constant value into all slots
func (e *Evaluator) EncodeConstant(value complex128, level int, scale rlwe.Scale) *rlwe.Plaintext {
	slots := e.Slots()
	values := make([]complex128, slots)
	for i := range values {
		values[i] = value
	}
	return e.EncodePlaintext(values, level, scale)
}

// DecodePlaintext decodes a plaintext to complex values
func (e *Evaluator) DecodePlaintext(pt *rlwe.Plaintext) []complex128 {
	values := make([]complex128, e.Slots())
	e.encoder.Decode(pt, values)
	return values
}

// DecodeFloats decodes a plaintext to float64 values (real parts only)
func (e *Evaluator) DecodeFloats(pt *rlwe.Plaintext) []float64 {
	complex := e.DecodePlaintext(pt)
	values := make([]float64, len(complex))
	for i, v := range complex {
		values[i] = real(v)
	}
	return values
}

// Power computes ct^n using binary exponentiation
func (e *Evaluator) Power(ct *rlwe.Ciphertext, n int) (*rlwe.Ciphertext, error) {
	if n < 1 {
		return nil, fmt.Errorf("power must be positive")
	}
	if n == 1 {
		return ct.CopyNew(), nil
	}

	result := ct.CopyNew()
	base := ct.CopyNew()
	power := n
	first := true

	for power > 0 {
		if power&1 == 1 {
			if first {
				result = base.CopyNew()
				first = false
			} else {
				var err error
				result, err = e.Mul(result, base)
				if err != nil {
					return nil, err
				}
				result, err = e.Rescale(result)
				if err != nil {
					return nil, err
				}
			}
		}
		power >>= 1
		if power > 0 {
			var err error
			base, err = e.Mul(base, base)
			if err != nil {
				return nil, err
			}
			base, err = e.Rescale(base)
			if err != nil {
				return nil, err
			}
		}
	}

	return result, nil
}

// EvaluatePolynomial evaluates a polynomial on a ciphertext
// coeffs[i] is the coefficient for x^i
func (e *Evaluator) EvaluatePolynomial(ct *rlwe.Ciphertext, coeffs []float64) (*rlwe.Ciphertext, error) {
	if len(coeffs) == 0 {
		return nil, fmt.Errorf("coefficients cannot be empty")
	}

	// Use Horner's method
	n := len(coeffs)
	result := e.EncodeConstant(complex(coeffs[n-1], 0), ct.Level(), ct.Scale)

	for i := n - 2; i >= 0; i-- {
		// result = result * ct + coeffs[i]
		resultCt := ckks.NewCiphertext(e.params, 1, ct.Level())
		err := e.evaluator.Mul(ct, result, resultCt)
		if err != nil {
			return nil, fmt.Errorf("polynomial mul failed: %w", err)
		}
		err = e.evaluator.Rescale(resultCt, resultCt)
		if err != nil {
			return nil, fmt.Errorf("polynomial rescale failed: %w", err)
		}
		err = e.evaluator.Add(resultCt, complex(coeffs[i], 0), resultCt)
		if err != nil {
			return nil, fmt.Errorf("polynomial add failed: %w", err)
		}
		// Store intermediate for next iteration if needed
		if i > 0 {
			result = e.EncodeConstant(0, resultCt.Level(), resultCt.Scale)
			// Copy the ciphertext values back appropriately
		}
		if i == 0 {
			return resultCt, nil
		}
	}

	return nil, fmt.Errorf("polynomial evaluation failed")
}

// Close releases resources
func (e *Evaluator) Close() {
	// Nothing to close for now
}
