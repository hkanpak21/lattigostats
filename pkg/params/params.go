// Package params provides CKKS parameter profiles for Lattigo-STAT.
// It defines two main profiles:
// - Profile A (no-bootstrap): for simpler ops with limited depth
// - Profile B (bootstrapped): for full functionality including INVNTHSQRT, DISCRETEEQUALZERO, k-percentile
package params

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// ProfileType identifies the parameter profile
type ProfileType string

const (
	ProfileA ProfileType = "A" // No bootstrapping, limited depth
	ProfileB ProfileType = "B" // With bootstrapping, full functionality
)

// Profile contains all CKKS parameters and derived values
type Profile struct {
	Type             ProfileType
	LogN             int   // Ring degree: N = 2^LogN
	Slots            int   // N/2 slots for CKKS
	LogScale         int   // Default scale: 2^LogScale
	LogQP            []int // Modulus chain bit-sizes
	BootstrapEnabled bool

	// Derived Lattigo parameters
	Params     ckks.Parameters
	ParamsHash string // SHA256 hash for reproducibility
}

// RotationSteps returns the standard rotation steps needed for slot reductions
// These are powers of 2: {1, 2, 4, ..., Slots/2}
func (p *Profile) RotationSteps() []int {
	steps := make([]int, 0)
	for i := 1; i < p.Slots; i *= 2 {
		steps = append(steps, i)
	}
	return steps
}

// NewProfileA creates a no-bootstrap profile suitable for mean/var/Bc/Ba/Bv
// with limited multiplicative depth
func NewProfileA() (*Profile, error) {
	// LogN=14 gives 8192 slots, suitable for medium-scale datasets
	logN := 14
	slots := 1 << (logN - 1) // N/2

	// Modulus chain for ~40 levels of multiplication
	// Prime sizes: 60 bits for Q0, 40 bits for subsequent levels
	logQ := []int{60}
	for i := 0; i < 40; i++ {
		logQ = append(logQ, 40)
	}
	logP := []int{60, 60} // Special modulus for key-switching

	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            logN,
		LogQ:            logQ,
		LogP:            logP,
		LogDefaultScale: 40,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create Profile A parameters: %w", err)
	}

	profile := &Profile{
		Type:             ProfileA,
		LogN:             logN,
		Slots:            slots,
		LogScale:         40,
		LogQP:            append(logQ, logP...),
		BootstrapEnabled: false,
		Params:           params,
	}
	profile.ParamsHash = profile.computeHash()

	return profile, nil
}

// NewProfileB creates a bootstrapping-enabled profile for full functionality
// Supports INVNTHSQRT, DISCRETEEQUALZERO, k-percentile, etc.
func NewProfileB() (*Profile, error) {
	// LogN=16 gives 32768 slots and room for bootstrapping
	logN := 16
	slots := 1 << (logN - 1)

	// Extended modulus chain to support bootstrapping
	// Q0 + enough levels for bootstrap circuit + computation
	logQ := make([]int, 0)
	logQ = append(logQ, 60) // Q0
	for i := 0; i < 16; i++ {
		logQ = append(logQ, 45)
	}

	logP := []int{61, 61, 61, 61} // Special modulus

	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            logN,
		LogQ:            logQ,
		LogP:            logP,
		LogDefaultScale: 45,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create Profile B parameters: %w", err)
	}

	profile := &Profile{
		Type:             ProfileB,
		LogN:             logN,
		Slots:            slots,
		LogScale:         45,
		LogQP:            append(logQ, logP...),
		BootstrapEnabled: true,
		Params:           params,
	}
	profile.ParamsHash = profile.computeHash()

	return profile, nil
}

// computeHash generates a deterministic hash of the parameter configuration
func (p *Profile) computeHash() string {
	data, _ := json.Marshal(struct {
		Type     ProfileType
		LogN     int
		LogQP    []int
		LogScale int
	}{
		Type:     p.Type,
		LogN:     p.LogN,
		LogQP:    p.LogQP,
		LogScale: p.LogScale,
	})
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// Validate checks that the parameters are consistent and usable
func (p *Profile) Validate() error {
	if p.LogN < 10 || p.LogN > 17 {
		return fmt.Errorf("LogN must be between 10 and 17, got %d", p.LogN)
	}
	if p.Slots != 1<<(p.LogN-1) {
		return fmt.Errorf("Slots mismatch: expected %d, got %d", 1<<(p.LogN-1), p.Slots)
	}
	if len(p.LogQP) < 2 {
		return fmt.Errorf("modulus chain too short")
	}
	return nil
}

// MaxLevel returns the maximum ciphertext level (number of Q primes - 1)
func (p *Profile) MaxLevel() int {
	return p.Params.MaxLevel()
}

// GetRLWEParams returns the underlying RLWE parameters
func (p *Profile) GetRLWEParams() rlwe.Parameters {
	return p.Params.Parameters
}

// String returns a human-readable description of the profile
func (p *Profile) String() string {
	return fmt.Sprintf("Profile %s: LogN=%d, Slots=%d, LogScale=%d, MaxLevel=%d, Bootstrap=%v, Hash=%s",
		p.Type, p.LogN, p.Slots, p.LogScale, p.MaxLevel(), p.BootstrapEnabled, p.ParamsHash[:16])
}
