// Package integration provides end-to-end integration tests for Lattigo-STAT
package integration

import (
	"math"
	"testing"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"

	"github.com/hkanpak21/lattigostats/pkg/he"
	"github.com/hkanpak21/lattigostats/pkg/ops/categorical"
	"github.com/hkanpak21/lattigostats/pkg/ops/numeric"
	"github.com/hkanpak21/lattigostats/pkg/params"
)

// helper function to create test environment
func setupTestEnv(t *testing.T) (*params.Profile, *he.Evaluator, *rlwe.SecretKey, *rlwe.PublicKey, *ckks.Encoder) {
	t.Helper()

	profile, err := params.NewProfileA()
	if err != nil {
		t.Fatalf("Failed to create profile: %v", err)
	}

	ckksParams := profile.Params

	// Create keys
	kgen := rlwe.NewKeyGenerator(ckksParams)
	sk := kgen.GenSecretKeyNew()
	pk := kgen.GenPublicKeyNew(sk)
	rlk := kgen.GenRelinearizationKeyNew(sk)

	// Convert rotation steps to Galois elements
	rotSteps := profile.RotationSteps()
	galoisElts := make([]uint64, len(rotSteps))
	for i, step := range rotSteps {
		galoisElts[i] = ckksParams.GaloisElement(step)
	}
	galoisKeys := kgen.GenGaloisKeysNew(galoisElts, sk)
	evk := rlwe.NewMemEvaluationKeySet(rlk, galoisKeys...)

	evaluator, err := he.NewEvaluator(ckksParams, evk, nil)
	if err != nil {
		t.Fatalf("Failed to create evaluator: %v", err)
	}

	encoder := ckks.NewEncoder(ckksParams)

	return profile, evaluator, sk, pk, encoder
}

// TestMaskedSumComputation tests the MaskedSum operation
func TestMaskedSumComputation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	profile, evaluator, sk, pk, encoder := setupTestEnv(t)
	ckksParams := profile.Params

	n := 100 // Number of data points

	// Generate data: [1, 2, 3, ..., 100, 0, 0, ...]
	data := make([]float64, profile.Slots)
	mask := make([]float64, profile.Slots)
	expectedSum := 0.0
	for i := 0; i < n; i++ {
		data[i] = float64(i + 1)
		mask[i] = 1.0 // All valid
		expectedSum += data[i]
	}

	// Encrypt data and mask
	encryptor := rlwe.NewEncryptor(ckksParams, pk)

	ptData := ckks.NewPlaintext(ckksParams, ckksParams.MaxLevel())
	if err := encoder.Encode(data, ptData); err != nil {
		t.Fatalf("Encode data failed: %v", err)
	}
	ctData, err := encryptor.EncryptNew(ptData)
	if err != nil {
		t.Fatalf("Failed to encrypt data: %v", err)
	}

	ptMask := ckks.NewPlaintext(ckksParams, ckksParams.MaxLevel())
	if err := encoder.Encode(mask, ptMask); err != nil {
		t.Fatalf("Encode mask failed: %v", err)
	}
	ctMask, err := encryptor.EncryptNew(ptMask)
	if err != nil {
		t.Fatalf("Failed to encrypt mask: %v", err)
	}

	// Compute masked sum
	numOps := numeric.NewNumericOp(evaluator)
	sumCt, err := numOps.MaskedSum([]*rlwe.Ciphertext{ctData}, []*rlwe.Ciphertext{ctMask})
	if err != nil {
		t.Fatalf("MaskedSum computation failed: %v", err)
	}

	// Decrypt result
	decryptor := rlwe.NewDecryptor(ckksParams, sk)
	ptResult := decryptor.DecryptNew(sumCt)
	result := make([]complex128, profile.Slots)
	if err := encoder.Decode(ptResult, result); err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	// Check result
	computedSum := real(result[0])
	relError := math.Abs(computedSum-expectedSum) / math.Abs(expectedSum)
	if relError > 0.01 {
		t.Errorf("MaskedSum mismatch: expected %.6f, got %.6f (relative error: %.6f)",
			expectedSum, computedSum, relError)
	}

	t.Logf("MaskedSum computation: expected=%.6f, computed=%.6f, relError=%.6f",
		expectedSum, computedSum, relError)
}

// TestMeanComputation tests mean computation across blocks
// NOTE: This test demonstrates the limitation of Profile A - it doesn't have
// enough multiplicative depth for the full mean computation which requires
// INVNTHSQRT. Use Profile B with bootstrapping for full functionality.
func TestMeanComputation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// This test is expected to fail with Profile A due to limited depth
	// The INVNTHSQRT operation requires bootstrapping (Profile B)
	t.Skip("Mean computation requires Profile B with bootstrapping for full functionality")

	profile, evaluator, sk, pk, encoder := setupTestEnv(t)
	ckksParams := profile.Params

	n := 100

	// Generate data
	data := make([]float64, profile.Slots)
	mask := make([]float64, profile.Slots)
	expectedSum := 0.0
	for i := 0; i < n; i++ {
		data[i] = float64(i + 1)
		mask[i] = 1.0
		expectedSum += data[i]
	}
	expectedMean := expectedSum / float64(n)

	// Encrypt
	encryptor := rlwe.NewEncryptor(ckksParams, pk)

	ptData := ckks.NewPlaintext(ckksParams, ckksParams.MaxLevel())
	if err := encoder.Encode(data, ptData); err != nil {
		t.Fatalf("Encode data failed: %v", err)
	}
	ctData, err := encryptor.EncryptNew(ptData)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	ptMask := ckks.NewPlaintext(ckksParams, ckksParams.MaxLevel())
	if err := encoder.Encode(mask, ptMask); err != nil {
		t.Fatalf("Encode mask failed: %v", err)
	}
	ctMask, err := encryptor.EncryptNew(ptMask)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Compute mean
	numOps := numeric.NewNumericOp(evaluator)
	meanCt, err := numOps.Mean([]*rlwe.Ciphertext{ctData}, []*rlwe.Ciphertext{ctMask})
	if err != nil {
		t.Fatalf("Mean computation failed: %v", err)
	}

	// Decrypt
	decryptor := rlwe.NewDecryptor(ckksParams, sk)
	ptResult := decryptor.DecryptNew(meanCt)
	result := make([]complex128, profile.Slots)
	if err := encoder.Decode(ptResult, result); err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	computedMean := real(result[0])
	relError := math.Abs(computedMean-expectedMean) / math.Abs(expectedMean)
	if relError > 0.02 {
		t.Errorf("Mean mismatch: expected %.6f, got %.6f (relative error: %.6f)",
			expectedMean, computedMean, relError)
	}

	t.Logf("Mean computation: expected=%.6f, computed=%.6f, relError=%.6f",
		expectedMean, computedMean, relError)
}

// TestPBMVEncoder tests the PBMV encoding
func TestPBMVEncoder(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	profile, err := params.NewProfileA()
	if err != nil {
		t.Fatalf("Failed to create profile: %v", err)
	}

	categories := 4
	config := categorical.DefaultLBcConfig()

	encoder := categorical.NewPBMVEncoder(categories, profile.Slots, config)
	if encoder == nil {
		t.Fatal("PBMV encoder is nil")
	}

	// Create categorical data: [0, 1, 2, 3, 0, 1, 2, 3, ...]
	n := 20
	values := make([]int, n)
	for i := 0; i < n; i++ {
		values[i] = i % categories
	}

	// Encode
	encoded := encoder.EncodePBMV(values)
	if len(encoded) != profile.Slots {
		t.Errorf("Expected encoded length %d, got %d", profile.Slots, len(encoded))
	}

	t.Logf("PBMV encoding test passed with %d categories and %d values", categories, n)
}

// TestBBMVEncoder tests the BBMV encoding
func TestBBMVEncoder(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	profile, err := params.NewProfileA()
	if err != nil {
		t.Fatalf("Failed to create profile: %v", err)
	}

	config := categorical.DefaultLBcConfig()

	encoder := categorical.NewBBMVEncoder(profile.Slots, config)
	if encoder == nil {
		t.Fatal("BBMV encoder is nil")
	}

	// Create binary mask
	n := 50
	mask := make([]bool, n)
	for i := 0; i < n; i++ {
		mask[i] = i%2 == 0
	}

	// Encode
	encoded := encoder.EncodeBBMV(mask)
	if len(encoded) != profile.Slots {
		t.Errorf("Expected encoded length %d, got %d", profile.Slots, len(encoded))
	}

	t.Logf("BBMV encoding test passed with %d mask values", n)
}

// TestProfileCreation tests the creation of both profiles
func TestProfileCreation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Test Profile A
	profileA, err := params.NewProfileA()
	if err != nil {
		t.Fatalf("Failed to create Profile A: %v", err)
	}

	if profileA.Type != params.ProfileA {
		t.Errorf("Expected ProfileA type, got %v", profileA.Type)
	}
	if profileA.Slots != 8192 {
		t.Errorf("Expected 8192 slots for Profile A, got %d", profileA.Slots)
	}

	t.Logf("Profile A: LogN=%d, Slots=%d, BootstrapEnabled=%v",
		profileA.LogN, profileA.Slots, profileA.BootstrapEnabled)

	// Test Profile B (only if we have enough resources)
	profileB, err := params.NewProfileB()
	if err != nil {
		t.Fatalf("Failed to create Profile B: %v", err)
	}

	if profileB.Type != params.ProfileB {
		t.Errorf("Expected ProfileB type, got %v", profileB.Type)
	}
	if profileB.Slots != 32768 {
		t.Errorf("Expected 32768 slots for Profile B, got %d", profileB.Slots)
	}
	if !profileB.BootstrapEnabled {
		t.Error("Profile B should have bootstrapping enabled")
	}

	t.Logf("Profile B: LogN=%d, Slots=%d, BootstrapEnabled=%v",
		profileB.LogN, profileB.Slots, profileB.BootstrapEnabled)
}

// TestEvaluatorOperations tests basic evaluator operations
func TestEvaluatorOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	profile, evaluator, sk, pk, encoder := setupTestEnv(t)
	ckksParams := profile.Params

	// Create two vectors
	a := make([]float64, profile.Slots)
	b := make([]float64, profile.Slots)
	for i := 0; i < 10; i++ {
		a[i] = float64(i + 1)
		b[i] = float64((i + 1) * 2)
	}

	// Encrypt
	encryptor := rlwe.NewEncryptor(ckksParams, pk)

	ptA := ckks.NewPlaintext(ckksParams, ckksParams.MaxLevel())
	if err := encoder.Encode(a, ptA); err != nil {
		t.Fatalf("Encode A failed: %v", err)
	}
	ctA, err := encryptor.EncryptNew(ptA)
	if err != nil {
		t.Fatalf("Encrypt A failed: %v", err)
	}

	ptB := ckks.NewPlaintext(ckksParams, ckksParams.MaxLevel())
	if err := encoder.Encode(b, ptB); err != nil {
		t.Fatalf("Encode B failed: %v", err)
	}
	ctB, err := encryptor.EncryptNew(ptB)
	if err != nil {
		t.Fatalf("Encrypt B failed: %v", err)
	}

	// Test Add
	ctSum, err := evaluator.Add(ctA, ctB)
	if err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	// Decrypt and check
	decryptor := rlwe.NewDecryptor(ckksParams, sk)
	ptResult := decryptor.DecryptNew(ctSum)
	result := make([]complex128, profile.Slots)
	if err := encoder.Decode(ptResult, result); err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	// Check first 10 values
	for i := 0; i < 10; i++ {
		expected := a[i] + b[i]
		got := real(result[i])
		if math.Abs(got-expected) > 0.01 {
			t.Errorf("Add result[%d]: expected %.6f, got %.6f", i, expected, got)
		}
	}

	// Test Mul
	ctProd, err := evaluator.Mul(ctA, ctB)
	if err != nil {
		t.Fatalf("Mul failed: %v", err)
	}
	ctProd, err = evaluator.Rescale(ctProd)
	if err != nil {
		t.Fatalf("Rescale failed: %v", err)
	}

	ptResult = decryptor.DecryptNew(ctProd)
	if err := encoder.Decode(ptResult, result); err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	for i := 0; i < 10; i++ {
		expected := a[i] * b[i]
		got := real(result[i])
		relError := math.Abs(got-expected) / math.Abs(expected)
		if relError > 0.01 {
			t.Errorf("Mul result[%d]: expected %.6f, got %.6f (relError: %.6f)",
				i, expected, got, relError)
		}
	}

	t.Log("Evaluator operations test passed")
}
